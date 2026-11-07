# Protection

Copyright (C) 2026 iBGeek

## Firewall Home

**Firewall → Status** shows:

- **Protection** - Protection Mode and Protection Level.
- **Hardening settings** - Threat Lists, Telemetry Block, Encrypted DNS (DoT 853), Strict Outbound, Block VPN Ports, Block IPv6, Whitelist Expiry, Stronger Identity, Deeper Detection, Remote Desktop Outside, Remote Desktop On LAN.
- **Network Health**
  - **In Path** - Yes when traffic is crossing the gateway; Not Yet when it is not.
  - **Filtering** - On when filtering rules are loaded; Off when they are not.
  - **Bridge** - Up when the bridge is up; None when there is no bridge.
  - **Settings Reachable From** - Local Network Only, or Home Network Or Router Side.
  - **Pending Undo** - the change waiting to be kept and seconds left, or None.
  - **Device uptime** and **FoilGateway uptime**.

When Threat Lists or Block Encrypted DNS (Port 853) are On, a notice about encrypted DNS on port 443 appears. Some apps still use encrypted DNS on port 443. FoilGateway often misses those names. Names already on your lists still become address blocks. When Block Encrypted DNS is On, the notice also states that encrypted DNS on port 853 is blocked.

## Protection Mode

**Protection Mode** - sets how much traffic is allowed to and through the gateway.

- **Normal** - applies the Normal protection level. Settings can be changed afterward.
- **Audit** - lets all traffic through and logs what would have been blocked. Safety rules still apply. Fresh installs start here.
- **Local Network Only** - blocks traffic between the LAN and the internet. Devices can still reach FoilGateway. Trusted devices are included.
- **Block Everything** - blocks all traffic to and through the gateway. Safety computers can open the settings pages and connect over SSH. Both require signing in.

**Changing the mode:** Firewall → Protection Mode, choose a mode. A list of the settings that will change is shown with OK or Cancel. Block Everything also asks you to type BLOCK.

**Leave Audit · Apply Normal** applies the Normal protection level. A list of the settings that will change is shown with OK or Cancel.

## Protection Levels

**Protection Level** - a named set of Hardening settings. Applying a level also sets Protection Mode to Normal.

- **Normal** - Threat Lists On, Block All Telemetry Off, Block Encrypted DNS (Port 853) Off, Whitelist Expiry On, Strict Outbound Off, Block VPN Ports Off, Block IPv6 Off. Remote Desktop from outside is blocked. Remote Desktop on the LAN is allowed.
- **FortNox** - the Normal settings, plus Block Encrypted DNS (Port 853) On, Block All Telemetry On, Strict Outbound On, and Remote Desktop on the LAN blocked.
- **Custom** - at least one Hardening setting differs from Normal and from FortNox.

**Applying a level:** Firewall → Protection Levels, Review And Apply. A list of the settings that will change is shown with OK or Cancel. Reset To Normal applies the Normal level the same way. Settings can be changed afterward under Hardening.

## Hardening

**Hardening** - the individual settings that Normal and FortNox set. Changing one moves the Protection Level to Custom.

**Opening it:** Firewall → Hardening.

**Block All Telemetry** - stops known tracking and telemetry addresses for every device, both ways.

- **On** - those addresses are blocked.
- **Off** - telemetry addresses pass unless a device has its own telemetry block.

**Threat Lists** - stops known bad networks (Spamhaus DROP and DROPv6) and botnet servers (abuse.ch Feodo), both ways. Lists download about once a day.

- **On** - threat list addresses are blocked.
- **Off** - connections to threat-list addresses pass unless another rule stops them.

**Block Encrypted DNS (Port 853)** - stops DNS over TLS on port 853. Off by default and in the Normal protection level. On in FortNox.

- **On** - port 853 is blocked through the gateway. Devices set to require DNS over TLS (for example Android Private DNS set to a provider name) cannot look up names.
- **Off** - port 853 passes through the gateway.

**Strict Outbound** - allows only new outbound traffic that matches your rules.

- **On** - new outbound that matches no rule is blocked. Blocked apps can be allowed from Devices → Troubleshooter.
- **Off** - new outbound follows Whitelist, Blacklist, threat lists, geo, Ports, and the other Hardening settings only.

**Block VPN Ports** - stops common VPN / WireGuard ports (51820, 1194, 500, 4500).

- **On** - those ports are blocked through the gateway.
- **Off** - those ports pass through the gateway.

**Block IPv6** - controls IPv6 through the gateway onto the LAN. Default Off.

- **On** - no IPv6 traffic is forwarded across the gateway, including neighbour discovery and DHCPv6. Neighbour discovery to the gateway itself still works for local management.
- **Off** - IPv6 is allowed through the gateway with the same hardening that applies to IPv4.

**Whitelist Expiry For Auto Allows** - time limit for Allows created from Audit or the Troubleshooter. Default Off.

- **On** - those Allows expire after 30 days.
- **Off** - those Allows stay until you remove them.

**Allow · Permanent** - creates an Allow that stays until you remove it, whether Whitelist Expiry is On or Off.

**Stronger Device Identity** - remembers hostname and DHCP fingerprint hints when a phone rotates its private MAC. Default Off.

- **On** - those hints are used for returning devices.

**Deeper Detection** - looks for port sweeps and repeated TCP connection failures in traffic passing through the gateway. Default Off.

- **On** - checks forwarded TCP connections for port sweeps and repeated connection failures.
- **Off** - stops new checks and clears pending attempts. Capture Log history stays.

A port sweep is twelve different ports tried on one remote address within sixty seconds. Repeated connection failures are eight refused or unanswered attempts to one service within sixty seconds. An unanswered attempt has had no observed connection reply for ten seconds while observation is healthy. Retransmissions count as the same attempt.

Already blocked traffic and traffic covered by an Allow, Trusted, Whitelist, infrastructure or open-port rule are excluded. Traffic allowed by Audit is still checked.

**Observation** - the current state, shown below the switch. Watching means observation is active. A degraded or unavailable state includes a message about the problem. Interrupted observation clears pending checks.

New warnings for the same subject have a five-minute cooldown. A later successful reply resolves the matching failed attempt. Alerts show the attempts still needing attention; Capture Log keeps the original record.

**Using it:** Firewall → Hardening, Deeper Detection. Default Off.

**New Devices** - what a device gets the first time its MAC shows up. The device is flagged as new either way.

- **Normal** - the device starts with the Normal device policy.
- **Local Network Only** - the device starts with the Local Network Only device policy.

## Best Practices

**Best Practices** - Firewall → Best Practices. You will be presented with several questions. After which you will be given a list of best practices that match your answers and an opportunity to instate those changes or ignore the recommendations.

## Geo-Blocking

**Geo-Blocking** - stops traffic to and from ticked countries, both ways. Trusted devices skip geo-blocking.

**Using it:** Firewall → Geo-Blocking. Tick a country to block it. Changes apply as you tick. Country blocking needs the location database. If the database is Off, the page links to Settings → Time and Location.

## Whitelist and Blacklist

**Whitelist** - always lets the listed hosts, URLs, or addresses through. Whitelist beats telemetry blocks, Blacklist, threat lists, and countries. Local Network Only and Block Everything still apply when a Whitelist entry is present. Names are looked up again every few minutes. Every address a name ever had stays in. When Whitelist Expiry is On, Allows created from Audit or the Troubleshooter expire after 30 days unless you used Allow · Permanent.

**Blacklist** - always stops the listed hosts, URLs, or addresses, both ways. Trusted devices skip the Blacklist.

**Editing lists:** Firewall → Whitelist or Firewall → Blacklist.

## Audit

**Audit** - while Audit is on for the whole network or for one device, the list shows traffic that would have been blocked but was let through.

**Buttons on each row:**

- **Allow · Permanent** - keeps that destination allowed. The Allow stays until you remove it.
- **Keep Blocking** - the destination stays blocked once Audit is off.

**Leave Audit · Apply Normal** applies the Normal protection level. A list of the settings that will change is shown with OK or Cancel.

**Opening it:** Firewall → Audit.

## Rules as Loaded

**Rules as Loaded** - shows the live rules FoilGateway has loaded.

**Opening it:** Firewall → Rules as Loaded.

## Device Policies

**Device Policy** - per-device setting on the device page.

- **Trusted** - skips Blacklist, threat lists, and countries. Telemetry blocking can still apply. Local Network Only and Block Everything still apply at the network level.
- **Normal** - follows the network Protection Mode, Hardening settings, Whitelist, Blacklist, threat lists, geo-blocking, and Ports.
- **Local Network Only** - that device cannot reach the internet through the gateway.
- **Block All** - that device is cut from traffic to and through the gateway.

## DNS Proxy (Addon)

A DNS Proxy addon for FoilGateway Network is in development and will be available in the future.

**Fits when**

- You have no DNS filter such as Pi-hole and want FoilGateway to own DNS filtering and learn which names devices look up.
- Clients resolve over HTTPS on port 443, so ordinary DNS on port 53 never shows those names to FoilGateway.

**Already covered when**

- You already run a DNS filter such as Pi-hole.
- LAN↔WAN blocking alone is enough (threat lists, telemetry addresses, ports, geo, Strict Outbound).
