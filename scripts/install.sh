#!/bin/sh
# FoilGateway Network installer (POSIX sh).
#
#   curl -fsSL https://github.com/iBgeek/FoilGateway-Network/releases/latest/download/install.sh | sudo sh
#
# Testing only: set FOILGW_RELEASE_BASE to a directory URL (no trailing slash)
# that serves the same asset names as a GitHub Release. Example:
#   FOILGW_RELEASE_BASE=http://127.0.0.1:8765 sudo -E sh install.sh
#
# Re-runs upgrade in place via `foilgw update` and never write or replace
# /etc/foilgateway or /var/lib/foilgateway.

set -eu

REPO_SLUG="iBgeek/FoilGateway-Network"
DEFAULT_BASE="https://github.com/${REPO_SLUG}/releases/latest/download"
BASE="${FOILGW_RELEASE_BASE:-$DEFAULT_BASE}"

BIN_DST="/usr/local/bin/foilgw"
WEB_DST="/usr/share/foilgateway/web"
LIB_DST="/usr/local/lib/foilgateway"
UNIT_DST="/etc/systemd/system/foilgw.service"
CONF_DIR="/etc/foilgateway"
STATE_DIR="/var/lib/foilgateway"

err() { printf '%s\n' "$*" >&2; exit 1; }
info() { printf '%s\n' "$*"; }

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || err "Need $1 on PATH."
}

detect_arch() {
  m=$(uname -m)
  case "$m" in
    x86_64|amd64) echo x86_64 ;;
    riscv64) echo riscv64 ;;
    *) err "Unsupported architecture: $m (need x86_64 or riscv64)." ;;
  esac
}

require_root() {
  [ "$(id -u)" -eq 0 ] || err "Run as root (sudo)."
}

require_systemd() {
  [ -d /run/systemd/system ] || err "systemd is required (no /run/systemd/system)."
  need_cmd systemctl
}

download() {
  url=$1
  out=$2
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL --connect-timeout 30 --retry 3 -o "$out" "$url" \
      || err "Download failed: $url"
  elif command -v wget >/dev/null 2>&1; then
    wget -q -O "$out" "$url" || err "Download failed: $url"
  else
    err "Need curl or wget."
  fi
}

verify_sums() {
  dir=$1
  arch=$2
  need_cmd sha256sum
  (
    cd "$dir" || exit 1
    grep -E " (foilgw-${arch}|foilgw-web\\.tar\\.gz)\$" SHA256SUMS > SUMS.check \
      || err "SHA256SUMS has no entries for this architecture."
    sha256sum -c SUMS.check || err "Checksum mismatch. Aborting."
  )
}

write_unit_if_missing() {
  if [ -f "$UNIT_DST" ]; then
    info "Keeping existing unit $UNIT_DST"
    return 0
  fi
  mkdir -p "$(dirname "$UNIT_DST")"
  cat > "$UNIT_DST" <<'UNIT'
[Unit]
Description=FoilGateway network edition
After=network-online.target systemd-networkd.service NetworkManager.service
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/foilgw serve
Restart=always
RestartSec=2
User=root
StateDirectory=foilgateway
ConfigurationDirectory=foilgateway

[Install]
WantedBy=multi-user.target
UNIT
  info "Wrote $UNIT_DST"
}

guess_url() {
  port=8443
  if [ -f "$CONF_DIR/gateway.conf" ]; then
    p=$(grep -E '^admin_port[[:space:]]*=' "$CONF_DIR/gateway.conf" 2>/dev/null | head -1 | sed 's/.*=[[:space:]]*//;s/[[:space:]]*$//')
    case "$p" in
      ''|*[!0-9]*) ;;
      *) port=$p ;;
    esac
  fi
  ip=""
  if command -v ip >/dev/null 2>&1; then
    ip=$(ip -4 -o route get 1.1.1.1 2>/dev/null | sed -n 's/.*src \([0-9.]*\).*/\1/p' | head -1)
  fi
  if [ -z "$ip" ] && command -v hostname >/dev/null 2>&1; then
    ip=$(hostname -I 2>/dev/null | awk '{print $1}')
  fi
  if [ -n "$ip" ]; then
    printf 'https://%s:%s/\n' "$ip" "$port"
  else
    printf 'https://<this-box>:%s/\n' "$port"
  fi
}

preserve_notice() {
  if [ -d "$CONF_DIR" ] || [ -d "$STATE_DIR" ]; then
    info "Existing settings left untouched ($CONF_DIR, $STATE_DIR)."
  fi
}

main() {
  require_root
  require_systemd
  need_cmd tar
  arch=$(detect_arch)
  info "Architecture: $arch"
  info "Release base: $BASE"

  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' EXIT INT TERM

  bin_name="foilgw-${arch}"
  info "Downloading $bin_name, foilgw-web.tar.gz, SHA256SUMS…"
  download "$BASE/SHA256SUMS" "$tmp/SHA256SUMS"
  download "$BASE/$bin_name" "$tmp/$bin_name"
  download "$BASE/foilgw-web.tar.gz" "$tmp/foilgw-web.tar.gz"
  chmod +x "$tmp/$bin_name"
  verify_sums "$tmp" "$arch"

  # Confirm the binary runs here before touching the install.
  ver=$("$tmp/$bin_name" version 2>/dev/null || true)
  case "$ver" in
    foilgw\ *) info "Package: $ver" ;;
    *) err "Downloaded binary does not run as foilgw on this machine." ;;
  esac

  mkdir -p "$(dirname "$BIN_DST")" "$LIB_DST" "$(dirname "$WEB_DST")"

  if [ -x "$BIN_DST" ]; then
    info "Existing install found; upgrading with foilgw update (config kept)."
    "$BIN_DST" update "$tmp/$bin_name" "$tmp/foilgw-web.tar.gz" \
      || err "foilgw update failed."
  else
    info "First install."
    # Use the downloaded binary's own update path so slots/web land the same way.
    FOILGW_BIN="$BIN_DST" FOILGW_LIB="$LIB_DST" FOILGW_WEB="$WEB_DST" \
      "$tmp/$bin_name" update "$tmp/$bin_name" "$tmp/foilgw-web.tar.gz" \
      || err "foilgw update (first install) failed."
  fi

  # Never create or overwrite gateway.conf / users / policy — wizard owns first run.
  preserve_notice

  write_unit_if_missing
  systemctl daemon-reload
  systemctl enable foilgw >/dev/null 2>&1 || true
  if systemctl restart foilgw; then
    info "Service foilgw restarted."
  else
    # First install: restart may fail if never started; try start.
    systemctl start foilgw || err "Could not start foilgw.service"
    info "Service foilgw started."
  fi

  # Wait until the service is active (and preferably answering on the settings port).
  i=0
  while [ "$i" -lt 60 ]; do
    if systemctl is-active --quiet foilgw; then
      break
    fi
    i=$((i + 1))
    sleep 0.5
  done
  systemctl is-active --quiet foilgw || err "foilgw.service is not active after install."
  # Soft wait for the settings page; do not fail the install if curl is missing.
  if command -v curl >/dev/null 2>&1; then
    port=8443
    if [ -f "$CONF_DIR/gateway.conf" ]; then
      p=$(grep -E '^admin_port[[:space:]]*=' "$CONF_DIR/gateway.conf" 2>/dev/null | head -1 | sed 's/.*=[[:space:]]*//;s/[[:space:]]*$//')
      case "$p" in ''|*[!0-9]*) ;; *) port=$p ;; esac
    fi
    j=0
    while [ "$j" -lt 30 ]; do
      code=$(curl -sk -o /dev/null -w '%{http_code}' "https://127.0.0.1:${port}/" 2>/dev/null || true)
      case "$code" in
        200|301|302|303|401|403) break ;;
      esac
      j=$((j + 1))
      sleep 1
    done
  fi

  url=$(guess_url)
  info ""
  info "FoilGateway Network is installed."
  info "Open $url"
  if [ ! -f "$CONF_DIR/gateway.conf" ]; then
    info "Finish setup in the browser (first-run wizard)."
  fi
  info "Manual: ${BASE}/FoilGateway-Manual.html"
}

main "$@"
