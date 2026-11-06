//! The settings page's certificate. The gateway keeps its own small
//! certificate authority (ca.pem, ca-key.pem 0600, never sent anywhere)
//! and issues the page's certificate (cert.pem, key.pem 0600) from it, for
//! every address the gateway has plus foilgateway.local and its host name.
//! A new one is issued when an address changes or 30 days before it runs
//! out, and the page switches to it without a restart.
//!
//! Upgrades: a gateway from before 0.5.4 has a self-signed cert.pem and no
//! CA. That one keeps being served, so browsers that accepted it still
//! do, until the owner makes a new certificate on the Certificates page.

use rcgen::{BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose, SanType};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};

const CA_NAME: &str = "FoilGateway local CA";
const CA_DAYS: i64 = 3650;
const CERT_DAYS: i64 = 397;
const RENEW_DAYS: i64 = 30;

/// What is being served right now; swapped in place on a new certificate.
static LIVE: RwLock<Option<Arc<CertifiedKey>>> = RwLock::new(None);
/// One issue at a time.
static ISSUING: Mutex<()> = Mutex::new(());

#[derive(Debug)]
pub struct Resolver;

impl ResolvesServerCert for Resolver {
    fn resolve(&self, _: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        LIVE.read().unwrap().clone()
    }
}

/// What the page shows about a certificate.
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct Info {
    pub subject: String,
    pub sha256: String,
    /// Unix time it runs out; 0 when unknown (an old self-signed one).
    pub not_after: i64,
    pub names: Vec<String>,
}

#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct State {
    pub ca: Option<Info>,
    pub server: Option<Info>,
    /// The served one came from an earlier version, not from our CA.
    pub legacy: bool,
}

fn p(dir: &str, f: &str) -> PathBuf {
    Path::new(dir).join(f)
}

fn now() -> i64 {
    crate::caplog::now()
}

fn write_private(path: &Path, text: &str) -> Result<(), String> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let tmp = path.with_extension("new");
    let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp).map_err(|e| e.to_string())?;
    f.write_all(text.as_bytes()).map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, path).map_err(|e| e.to_string())
}

fn write_public(path: &Path, text: &str) -> Result<(), String> {
    let tmp = path.with_extension("new");
    std::fs::write(&tmp, text).map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, path).map_err(|e| e.to_string())
}

pub fn fingerprint(der: &[u8]) -> String {
    ring::digest::digest(&ring::digest::SHA256, der).as_ref().iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(":")
}

/// What Windows calls the Thumbprint, shown in its certificate dialogs.
pub fn thumbprint(der: &[u8]) -> String {
    ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, der).as_ref().iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(" ")
}

fn pem_der(pem: &str) -> Option<Vec<u8>> {
    rustls_pemfile::certs(&mut pem.as_bytes()).next()?.ok().map(|c| c.to_vec())
}

fn when(days: i64) -> time::OffsetDateTime {
    time::OffsetDateTime::from_unix_timestamp(now() + days * 86400).unwrap_or(time::OffsetDateTime::UNIX_EPOCH)
}

fn ca_params() -> CertificateParams {
    let mut c = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, CA_NAME);
    dn.push(DnType::OrganizationName, "FoilGateway");
    c.distinguished_name = dn;
    c.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    c.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign, KeyUsagePurpose::DigitalSignature];
    c
}

/// The names the page's certificate should carry now.
pub fn wanted_names() -> Vec<String> {
    let mut names = vec!["foilgateway.local".to_string(), "foilgateway".to_string()];
    if let Ok(h) = std::fs::read_to_string("/etc/hostname") {
        let h = h.trim();
        if !h.is_empty() {
            names.push(h.to_string());
            names.push(format!("{h}.local"));
        }
    }
    names.push(crate::anyport::SETUP_ADDR.to_string());
    names.push(crate::anyport::FALLBACK.to_string());
    let mut ips: Vec<String> = crate::net::ports().iter().chain(crate::net::bridge_port().iter()).flat_map(|p| p.ips.iter().map(|i| i.split('/').next().unwrap_or("").to_string())).collect();
    ips.retain(|i| !i.is_empty() && !i.starts_with("fe80"));
    ips.sort();
    names.extend(ips);
    let mut seen = std::collections::HashSet::new();
    names.retain(|n| seen.insert(n.clone()));
    names
}

pub fn state(dir: &str) -> State {
    std::fs::read_to_string(p(dir, "certs.json")).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default()
}

fn save_state(dir: &str, s: &State) -> Result<(), String> {
    write_public(&p(dir, "certs.json"), &serde_json::to_string_pretty(s).unwrap())
}

/// Makes the CA when there is none. The key stays in ca-key.pem.
fn ensure_ca(dir: &str, st: &mut State) -> Result<KeyPair, String> {
    if let (Ok(k), Some(_)) = (std::fs::read_to_string(p(dir, "ca-key.pem")), &st.ca) {
        if std::fs::metadata(p(dir, "ca.pem")).is_ok() {
            return KeyPair::from_pem(&k).map_err(|e| e.to_string());
        }
    }
    let key = KeyPair::generate().map_err(|e| e.to_string())?;
    let mut c = ca_params();
    c.not_before = when(-1);
    c.not_after = when(CA_DAYS);
    let cert = c.self_signed(&key).map_err(|e| e.to_string())?;
    write_private(&p(dir, "ca-key.pem"), &key.serialize_pem())?;
    write_public(&p(dir, "ca.pem"), &cert.pem())?;
    st.ca = Some(Info { subject: CA_NAME.into(), sha256: fingerprint(cert.der()), not_after: now() + CA_DAYS * 86400, names: vec![] });
    Ok(key)
}

/// Issues the page's certificate from the CA for `names`, saves it and
/// serves it from the next connection on.
pub fn issue(dir: &str, names: Vec<String>) -> Result<State, String> {
    let _one = ISSUING.lock().unwrap();
    let mut st = state(dir);
    let ca_key = ensure_ca(dir, &mut st)?;
    // The issuer is rebuilt from the same name and key: the signature and
    // the key id it leaves on the new certificate match the saved CA.
    let issuer = ca_params().self_signed(&ca_key).map_err(|e| e.to_string())?;
    let key = KeyPair::generate().map_err(|e| e.to_string())?;
    let mut c = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "foilgateway.local");
    c.distinguished_name = dn;
    c.subject_alt_names = names
        .iter()
        .filter_map(|n| match n.parse::<std::net::IpAddr>() {
            Ok(ip) => Some(SanType::IpAddress(ip)),
            Err(_) => n.clone().try_into().ok().map(SanType::DnsName),
        })
        .collect();
    c.key_usages = vec![KeyUsagePurpose::DigitalSignature, KeyUsagePurpose::KeyEncipherment];
    c.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    c.not_before = when(-1);
    c.not_after = when(CERT_DAYS);
    let cert = c.signed_by(&key, &issuer, &ca_key).map_err(|e| e.to_string())?;
    let ca_pem = std::fs::read_to_string(p(dir, "ca.pem")).map_err(|e| e.to_string())?;
    // The chain goes out with it, so a client holding the CA can build it.
    write_private(&p(dir, "key.pem"), &key.serialize_pem())?;
    write_public(&p(dir, "cert.pem"), &(cert.pem() + &ca_pem))?;
    st.server = Some(Info { subject: "foilgateway.local".into(), sha256: fingerprint(cert.der()), not_after: now() + CERT_DAYS * 86400, names });
    st.legacy = false;
    save_state(dir, &st)?;
    load(dir)?;
    Ok(st)
}

/// Puts cert.pem / key.pem in service.
pub fn load(dir: &str) -> Result<(), String> {
    let certs = rustls_pemfile::certs(&mut std::io::BufReader::new(std::fs::File::open(p(dir, "cert.pem")).map_err(|e| e.to_string())?)).collect::<Result<Vec<_>, _>>().map_err(|e| e.to_string())?;
    let key = rustls_pemfile::private_key(&mut std::io::BufReader::new(std::fs::File::open(p(dir, "key.pem")).map_err(|e| e.to_string())?)).map_err(|e| e.to_string())?.ok_or("no key in key.pem")?;
    let signer = rustls::crypto::ring::sign::any_supported_type(&key).map_err(|e| e.to_string())?;
    *LIVE.write().unwrap() = Some(Arc::new(CertifiedKey::new(certs, signer)));
    Ok(())
}

/// At start: a CA always exists, and the page certificate is one it issued.
pub fn startup(dir: &str) -> Result<(), String> {
    let mut st = state(dir);
    let had_cert = std::fs::metadata(p(dir, "cert.pem")).is_ok() && std::fs::metadata(p(dir, "key.pem")).is_ok();
    // A certificate this gateway's CA didn't issue (an earlier version's
    // self-signed one, or one we have no record of) is replaced at once:
    // computers that installed the CA must see a page they trust.
    let ours = had_cert && !st.legacy && st.server.as_ref().is_some_and(|s| {
        let pem = std::fs::read_to_string(p(dir, "cert.pem")).unwrap_or_default();
        pem_der(&pem).is_some_and(|d| fingerprint(&d) == s.sha256)
    });
    ensure_ca(dir, &mut st)?;
    save_state(dir, &st)?;
    if ours {
        load(dir)
    } else {
        issue(dir, wanted_names()).map(|_| ())
    }
}

/// Run now and then: a new certificate when the addresses changed, the
/// end is near, or the one in use isn't from this gateway's CA.
pub fn check(dir: &str) -> Option<Result<State, String>> {
    let st = state(dir);
    if st.legacy || st.server.is_none() {
        return Some(issue(dir, wanted_names()));
    }
    let s = st.server.as_ref()?;
    let names = wanted_names();
    let missing = names.iter().any(|n| !s.names.contains(n));
    if !missing && s.not_after - now() > RENEW_DAYS * 86400 {
        return None;
    }
    Some(issue(dir, names))
}

pub fn ca_pem(dir: &str) -> Result<String, String> {
    std::fs::read_to_string(p(dir, "ca.pem")).map_err(|e| e.to_string())
}

pub fn ca_der(dir: &str) -> Result<Vec<u8>, String> {
    pem_der(&ca_pem(dir)?).ok_or("ca.pem unreadable".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp() -> String {
        let d = std::env::temp_dir().join(format!("fg-certs-{}", crate::auth::token()));
        std::fs::create_dir_all(&d).unwrap();
        d.display().to_string()
    }

    #[test]
    fn issues_from_own_ca_with_private_keys() {
        use std::os::unix::fs::PermissionsExt;
        let d = tmp();
        startup(&d).unwrap();
        let st = issue(&d, vec!["foilgateway.local".into(), "192.168.1.50".into()]).unwrap();
        for k in ["ca-key.pem", "key.pem"] {
            assert_eq!(std::fs::metadata(p(&d, k)).unwrap().permissions().mode() & 0o777, 0o600, "{k}");
        }
        assert!(!st.legacy && st.server.as_ref().unwrap().not_after > now() + 300 * 86400);
        // The same CA signs the next one.
        let ca1 = ca_pem(&d).unwrap();
        issue(&d, vec!["foilgateway.local".into()]).unwrap();
        assert_eq!(ca1, ca_pem(&d).unwrap());
        // An address the certificate lacks makes check() issue again.
        let mut s = state(&d);
        s.server.as_mut().unwrap().names = vec![];
        save_state(&d, &s).unwrap();
        assert!(check(&d).unwrap().is_ok());
        assert!(check(&d).is_none());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn old_self_signed_cert_is_replaced_at_start() {
        let d = tmp();
        let c = rcgen::generate_simple_self_signed(vec!["foilgateway".into()]).unwrap();
        std::fs::write(p(&d, "cert.pem"), c.cert.pem()).unwrap();
        std::fs::write(p(&d, "key.pem"), c.key_pair.serialize_pem()).unwrap();
        // 0.5.4-0.5.6 left this state behind: CA made, old cert marked legacy.
        let mut st = state(&d);
        ensure_ca(&d, &mut st).unwrap();
        st.legacy = true;
        save_state(&d, &st).unwrap();
        startup(&d).unwrap();
        let st = state(&d);
        let pem = std::fs::read_to_string(p(&d, "cert.pem")).unwrap();
        assert!(!st.legacy && st.ca.is_some() && pem != c.cert.pem());
        assert!(pem.ends_with(&ca_pem(&d).unwrap()), "chain carries the CA");
        // A cert.pem swapped behind our back is replaced too.
        std::fs::write(p(&d, "cert.pem"), c.cert.pem()).unwrap();
        std::fs::write(p(&d, "key.pem"), c.key_pair.serialize_pem()).unwrap();
        startup(&d).unwrap();
        assert_ne!(std::fs::read_to_string(p(&d, "cert.pem")).unwrap(), c.cert.pem());
        let _ = std::fs::remove_dir_all(&d);
    }
}
