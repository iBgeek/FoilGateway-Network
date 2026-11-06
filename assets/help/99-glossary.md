# Glossary

Copyright (C) 2026 iBGeek

- **WAN** - the port toward your router or modem.
- **LAN** - the side toward your switch, Wi-Fi, and devices.
- **SSH** - a way to log in to the gateway from a terminal.
- **MAC** - a device's hardware address on the network. Phones may randomize it.
- **CIDR** - a way to write a range of addresses, like 10.0.0.0/8.
- **HTTPS** - the encrypted web address for this settings page.
- **Bridge** - FoilGateway passes traffic through; your router still hands out addresses.
- **Audit** - lets traffic through and logs what would have been blocked. Safety rules still apply.
- **Normal** - Protection Mode that applies the Normal protection level; also the name of that level (Threat Lists On, Block All Telemetry Off); also a device policy that follows network Hardening, lists, geo, and Ports.
- **FortNox** - Protection Level with Block All Telemetry On, Strict Outbound On, and Remote Desktop blocked on the LAN.
- **Custom** - Protection Level when a Hardening setting differs from Normal and FortNox.
- **Local Network Only** - blocks traffic between the LAN and the internet.
- **Block Everything** - blocks all traffic to and through the gateway. Safety computers can open the settings pages and connect over SSH. Both require signing in.
- **Trusted** - device policy that skips Blacklist, threat lists, and countries.
- **Block All** - device policy that cuts that device from traffic to and through the gateway.
- **Safety** - computers that can open the settings pages and connect over SSH. Both require signing in.
- **Telemetry** - usage and diagnostic data devices send to makers or third parties.
- **Threat Lists** - downloaded bad-network and botnet lists (Spamhaus DROP / DROPv6, Feodo, and related feeds).
- **Geo-Blocking** - stop traffic to and from ticked countries.
- **Whitelist** - always allow listed hosts or nets.
- **Blacklist** - always stop listed hosts or nets.
- **Strict Outbound** - allow only new outbound that matches your rules.
- **Block IPv6** - when On, no IPv6 passes the gateway onto the LAN; when Off, IPv6 is allowed with IPv4-matching hardening. Default Off.
- **DoT / DoH** - DNS over TLS (853) / DNS over HTTPS (often 443).
- **Stronger Identity** - remembers hostname and DHCP fingerprint hints when a phone rotates its MAC. Default Off.
- **Deeper Detection** - quieter pattern checks beyond volume spikes. Default Off.
- **Likely Attack** - Blocked Today subtitle when alarm volume is far above usual (`Likely attack · far above usual`).
- **Needs a Look** - Capture Log filter for rows worth a glance.
- **Undo / Rollback Timer** - if the browser loses the gateway after a risky change, the change undoes itself within the timer.
- **FoilGateway Network** - this product.
- **iBGeek** - copyright holder, Copyright (C) 2026.
