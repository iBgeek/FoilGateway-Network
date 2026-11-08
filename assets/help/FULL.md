# Getting Started

Copyright (C) 2026 iBGeek

## What FoilGateway Does

**FoilGateway Network** - a bridge between the WAN port and the LAN port. Traffic that crosses that path can be watched, logged, and blocked. Your router still hands out addresses. The gateway gets its own address from the router.

Everything downstream of the LAN port (switches, Wi-Fi, and all devices behind FoilGateway) is protected. Anything upstream of the WAN port is not.

## First Setup

Open the gateway in a browser over HTTPS. The certificate is made on the box, so the browser warns once for each address. Trust it for this device, or install the gateway certificate authority from Settings → Certificates later.

Setup steps, in order:

1. **Welcome** - shows the product name and short product description.
2. **Admin** (first install) - creates the first sign-in name and a password of at least 10 characters.
3. **Mode** - sets placement to Between Internet And Switch or Between Router And Switch. The gateway runs as a bridge.
4. **Ports** - sets WAN (toward the router or modem) and one or more LAN ports. Blink flashes a socket's link light so you can identify it.
5. **Settings Port** - sets the HTTPS port for these pages (8443 unless you choose another).
6. **Safety** - turns Safety on and lists always-allowed IPv4 addresses. Add at least the computer you are using now. Sets what New Devices get: Normal or Local Network Only.
7. **Review** - shows WAN, LAN, Safety, and new-device policy for confirmation.
8. **Apply** - joins the ports into one bridge. The page must reach the gateway again. If it cannot within the rollback timer (usually about 3 minutes), the bridge comes apart and ports go back.

After Apply you land on Done. Sign in and open the Dashboard.

## Safety

**Safety** - Safety computers can open the settings pages and connect over SSH. Both require signing in.

**During setup:** Keep Management Safety On (Recommended), list always-allowed computers by IPv4 address (comma separated; the wizard fills in the computer you are on), and pick what New Devices get (Normal or Local Network Only).

**Later:** Settings → Network & Access.

## Undo Timer

Many changes that could lock you out arm a rollback timer (often about 3 minutes). If this browser cannot reach the gateway afterwards, the change undoes itself. Those confirms link to If You Can't Reach This Page.

## After Setup

1. Sign in. Open the Dashboard.
2. Leave Protection Mode on Audit while you watch traffic (fresh installs start in Audit).
3. Open Devices. Name anything that shows only a maker string (Give It a Name).
4. When you are ready to block for real, use Leave Audit · Apply Normal. A list of the settings that will change is shown with OK or Cancel. That applies the Normal protection level.
5. Open Firewall → Best Practices if you want guided suggestions.
6. When setup from the router side is finished, switch Who Can Open This Page to only devices behind the gateway (Settings → Network & Access).


# Daily Use

Copyright (C) 2026 iBGeek

## Dashboard

**Dashboard** - home screen after sign-in. Status cards across the top (on or off under Settings → View):

- **Mode** - current Protection Mode, and whether telemetry is blocked network-wide.
- **Traffic Path** - In path or Not in path, and whether filtering is on.
- **WAN Speed** / **LAN Speed** - in and out rates, two lines each.
- **Countries Now** - countries with fresh forwarded traffic. Click for the country names.
- **Devices Online** - count of devices seen recently.
- **CPU Load**, **CPU Temperature** (caption only when hot), **Disk**, **Memory**
- **Blocked Today** - block count for today. Click to open the log.

Below the cards are the map and the connections table. Connections are observed tracking entries; a listed connection alone does not prove that packets are still passing.

### Map

**Map** - shows traffic and stopped connection attempts by location.

- **Traffic Only** - shows traffic currently passing through the gateway. Selected when you open the Dashboard.
- **Blocked Connection Attempts** - shows recently logged stopped attempts. Counts cover roughly the last minute.

Only one mode is On. Hover over a location for devices, destinations and direction. Traffic counts show active device/address paths.

**Buttons:**

- **Pause Motion** - stops the map animation.
- **Play Motion** - starts the map animation.
- **Full Screen** - expands the map. Press Escape to leave full screen.

**Using it:** Open Dashboard and choose a map mode. Traffic updates every few seconds. Quiet paths disappear as samples refresh. Public addresses with a known location appear on the map. Device uptime and FoilGateway uptime stay in the sidebar.

### Alerts

Alerts show things that still need attention, such as a new device, an allowed threat-list match in Audit, or a filtering failure. Already stopped traffic does not create a suspicious, new-port or volume-spike warning. Resolved warnings leave Alerts and Needs a Look. Raw history remains under Capture Log → All, and stopped attempts remain under Blocked. Old port observations without an outcome stay unclassified unless matching inbound drop evidence or a handled decision is available; they are not assumed stopped.

### Blocked Today

The number is today's full logged block count. It does not turn high block volume into an attack warning. Click it to open today's blocked rows in the Capture Log.

## Devices

**Devices → All Devices** - everything FoilGateway has seen. Search, filter (Online, New, Blocked or Local Network Only, Trusted), and sort. Scroll loads more in batches of 100.

Each row shows a label, address, maker when known, policy label, and optional new / telemetry blocked labels. Unnamed devices get Give It a Name.

Open a device for:

- **Policy** - Trusted, Normal, Local Network Only, or Block All.
- **Audit** - lets that device's traffic through while writing down what would have been blocked.
- **Telemetry** - stops known telemetry for this device only.
- **Websites and Addresses** - Block It (default) or Allow It per entry.
- **Connections Now** - live connections for that device.
- **More** - Forget, Block All, and related actions.

## Troubleshooter

**Devices → Troubleshooter** - shows why a device's traffic is being blocked and lets you allow it.

Pick a device, then choose a filter beside the device picker:

- **All attempts** - shows stopped attempts and traffic allowed during Audit.
- **Stopped only** - shows traffic FoilGateway blocked.
- **Audit allowed only** - shows traffic that Audit let through and would otherwise have blocked.

The page shows status notes, a likely-cause strip when one is known, and Allow actions beside that line. Stopped and Audit-allowed attempts stay on separate lines, even for the same address. Blocked apps can be allowed from here.

## Capture Log

**Capture Log** - searchable history of blocks, device events, alerts, audit rows, DHCP, settings changes, and list downloads.

Filters: Needs a Look; kind (All, Blocked, Devices, Alerts, Audit, DHCP, Settings, Downloads); search; Today; date range; sort; Download.

Retention and download controls also sit under Settings → Capture Log.


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


# Ports

Copyright (C) 2026 iBGeek

## What Ports Control

**Ports** - whether the router side (WAN) may start connections into your devices on a TCP or UDP port, and whether your devices may start those ports toward the router side. Global settings win over a device's own port overrides.

In Normal and Audit, these choices apply. In Local Network Only or Block Everything, those modes block traffic to and through the gateway; the Ports page shows a notice.

## Global and Per Device

- **Global** - one setting for every device on that port.
- **Per Device** - every device listed; open a row for overrides. Filter All / With Own / Same as Global. Same as Global clears an override.

Per-device choices: Same as Global, Allow, Block from WAN, Block from LAN, Block Both.

## Choices

- **Allow** - the router side may start connections to your devices on that port.
- **Block from WAN** - stop new attempts from the router side.
- **Block from LAN** - stop your devices starting that port toward the router side.
- **Block Both** - both directions for new connections on that port.

Unset ports are treated as blocked from WAN until you set them.

**Adding a port:** Add a Port by Hand (protocol + number + choice). Custom ports can be removed.

## WAN and LAN

**WAN** - the port toward your router or modem. **LAN** - toward your switch, Wi-Fi, and devices. From the router side means something on the WAN side of FoilGateway trying to reach in.

## Remote Desktop (TCP 3389)

Remote Desktop from outside starts blocked. Devices behind the LAN port can still use it. FortNox also blocks Remote Desktop on the LAN.

**Opening it for one device:** Ports, that device, set the port as needed.

## Risky Ports and Alerts

Other ports show risk notes when known. When a new port shows up in traffic, the Dashboard can alert. Open Ports or the Troubleshooter from the alert.

## Placement

Everything downstream of the LAN port (switches, Wi-Fi, and all devices behind FoilGateway) is protected. Anything upstream of the WAN port is not.


# Settings

Copyright (C) 2026 iBGeek

**Settings** - gateway configuration. Sub-topics, in order: Network & Access, Certificates, Time and Location, Capture Log, Account, View, Setup, Updates, Help, About (always last).

## Network & Access

**Ports (WAN / LAN)** - which interfaces are WAN and LAN. WAN is locked until you Unlock WAN (confirm; undo timer). SSH answers from both sides. Whether this settings page answers from the router side depends on Who Can Open This Page.

**Gateway Address** - DHCP from the router, or a fixed address with gateway and DNS. After a fixed-address change, open the new URL within the countdown and sign in to keep it.

**Internet speed test** - measures the gateway's internet download speed, upload speed and HTTP response latency using Cloudflare.

The panel shows:

- **Download** and **Upload** - measured speed in Mbps.
- **HTTP response latency** - the median time from sending a request to the first byte of the reply, in milliseconds. Name lookup, connection and encryption setup are not counted. This is not an ICMP ping.
- **Progress** and **elapsed time** - the current test stage and time spent running.
- **Last result** - the most recent completed test and its time. Kept until FoilGateway restarts.

**Buttons:**

- **Run speed test** - starts a test. Admin access is required.
- **Cancel** - stops the test. Wait for cleanup to finish before starting another.

A test can transfer up to 64 MiB down and 16 MiB up, plus protocol overhead, and may slow other traffic. Download is measured for up to 8 seconds from its first byte, or until 64 MiB arrives. Connection setup is not counted in either speed. It has a forty-second overall limit. If a test fails or is cancelled, the earlier completed result stays.

The gateway uses HTTPS certificate checks. Cloudflare receives its public address and measurement requests. Results estimate the gateway's connection to Cloudflare.

**Using it:** Settings → Network & Access, below Gateway Address.

**Who Can Open This Page**

- **Anyone on the Home Network or the Router Side** - default after the wizard.
- **Only Devices Behind the Gateway** - the router side cannot see the sign-in page. SSH still answers both sides. Safety computers can open the settings pages and connect over SSH. Both require signing in.

**Settings Port** - HTTPS port for these pages. Kept open for Safety computers.

**Safety** - toggle Safety and edit always-allowed IPv4 hosts. Safety computers can open the settings pages and connect over SSH. Both require signing in.

## Certificates

Download the gateway certificate authority and install it so browsers stop warning. Windows, macOS, iPhone/iPad, and Android steps are on the page. The certificate is generated on the gateway.

## Time and Location

Clock display (12/24h, date formats) and the location database used for Geo-Blocking. Progress, retries, errors, and Try Now show if a download stalls.

Also shows Device uptime and FoilGateway uptime.

## Capture Log (settings)

Retention, a link into the full log, and download controls.

## Account

Admins who may sign in. Sign out is top-right on every page.

## View

Which Dashboard cards are on. The server stores choices by card id. Turning a card off stops measuring work only that card needs.

## Setup

- **Run Setup Again** - type YES. Devices keep working until the last step; that step undoes itself if the browser loses the gateway. Admin accounts stay as they are.
- Restart FoilGateway.
- Download Backup, restore (summary, Cancel, Download Backup First).
- Roll Back to the previous release when one is kept.

## Updates

**Updates** - checks GitHub Releases for a newer FoilGateway Network build and installs it when you ask.

- **Current Version** - the build running now.
- **Latest Version** - the newest release on GitHub, with its date and release notes.
- **Last Checked** - when FoilGateway last asked GitHub.

**Buttons:**

- **Check Now** - asks GitHub for the latest release right away. A daily check also runs in the background.
- **Install Update** - downloads the matching binary and web package, checks SHA256SUMS, installs into the version slots, and restarts. Shown only when a newer release is available. A confirm lists the version change and that the gateway restarts.
- **Roll Back To Previous Version** - puts back the version kept from the last update and restarts. Shown when a previous slot exists.

If this page does not come back after Install Update, FoilGateway restores the previous version within the undo timer. Updates never install by themselves.

**Opening it:** Settings → Updates.

## Help

Settings → Help. Tabbed categories matching this manual, search, Download Manual.

## About

Settings → About (always last). Product name, version, OS, architecture, board when known, Software License text, Download Manual. [Support](https://github.com/iBgeek/FoilGateway-Network/discussions/1).


# If Something Breaks

Copyright (C) 2026 iBGeek

## If You Can't Reach This Page

1. **Use a safety computer.** The computer you added during setup can open this page (sign in as usual).
2. **Wait about 3 minutes.** A change that cuts you off undoes itself within the rollback timer if this browser cannot reach the gateway.
3. **Log in over SSH, then run** `foilgw rollback` for the last good settings, or `foilgw rollback-version` for the previous release.
4. **Pulling the power is safe.** Unplug the gateway, wait a few seconds, plug it back in. Settings stay; the running state restarts.

## Something Stopped Working After a Block

1. Open Devices → Troubleshooter (or follow the alert).
2. Read the likely-cause line. Use Allow for that site, address, or port if the device needs it.
3. Check Firewall → Audit if you are still in Audit. Use Allow · Permanent for what should keep working.
4. If you ticked a country, untick it or whitelist the site.
5. Check Protection Mode. Local Network Only and Block Everything block traffic to and through the gateway.
6. If you just applied FortNox, Strict Outbound or LAN Remote Desktop may be blocking the app. Use Devices → Troubleshooter, or Reset To Normal under Protection Levels.

## Geo or List Download Stuck

On Settings → Time and Location (geo) or Firewall list panels: wait for the retry schedule, read the error, use Try Now. Lists download when you enable a feature that needs them.

## Wrong Port Roles (WAN / LAN)

Unlock WAN only when you mean to move it. Confirm and watch the undo timer. If you lose the page, wait for rollback or use a Safety computer / SSH.

## After a Restore or Roll Back

Download a backup before restore or version rollback when the dialog offers it. Restore shows a summary. Version rollback lists what you lose.

## SSH Commands

- `foilgw rollback` - last good settings
- `foilgw rollback-version` - previous release binary and web
- `foilgw show` - current config summary
- `foilgw apply` - apply rules / config
- `foilgw version` - print version

Exact flags follow `foilgw` usage on the box.

## Still Stuck

[Support](https://github.com/iBgeek/FoilGateway-Network/discussions/1)


# Limits

Copyright (C) 2026 iBGeek

## Placement

Everything downstream of the LAN port (switches, Wi-Fi, and all devices behind FoilGateway) is protected by FoilGateway. Anything upstream of the WAN port is not.

## Encrypted DNS on Port 443

When Block Encrypted DNS (Port 853) is On, FoilGateway blocks DNS over TLS on port 853. Devices set to require DNS over TLS (for example Android Private DNS set to a provider name) cannot look up names while it is On. Some apps still use encrypted DNS on port 443. FoilGateway often misses new names from those apps. Names already on your lists still become address blocks. IP, port, geo, and threat hardening still apply.

See Protection → DNS Proxy (Addon).

## Stopped Traffic and Alerts

Blocks remain in the Capture Log and the explicit blocked-attempts view. They do not create attack-volume warnings or alerts about traffic the gateway already stopped. Audit is different: it allows the traffic, so an unhandled warning can still appear.

## Country Blocks

Country matches use the installed address database, for both IPv4 and IPv6, in both directions. An unknown or missing country range cannot be matched. A location describes the public endpoint address, not necessarily the service or person's physical location.

DHCP and, when IPv6 is enabled, neighbour-discovery bootstrap exceptions precede country checks. Audit, Trusted devices, device Allow entries and Whitelist entries keep their existing precedence. Explicit router-side open ports also accept new incoming traffic before country checks; an incoming UDP packet can therefore pass from a selected country on an opened port. Selecting a country is therefore not an unconditional deny on an explicitly opened port. These exceptions are unchanged. Non-exempt tracked sessions are rechecked after a country policy or list generation changes.

Use the forwarded map to see recent accepted activity and the stopped-attempts mode or raw log to see drops. A stale connection-tracking entry alone is not evidence that a country rule failed.

## IPv6

Block IPv6 (Hardening) defaults to Off. Off allows IPv6 through the gateway with the same hardening that applies to IPv4. On blocks all IPv6 forwarding across the gateway, including neighbour discovery and DHCPv6. Neighbour discovery to the gateway itself still works for local management. Threat feeds include DROPv6. Safety hosts in this build are IPv4.

## VPN Tunnels

Traffic inside a VPN tunnel cannot be read. Geo and threat lists apply to the tunnel endpoints you can see. Block VPN Ports (default Off) can stop common WireGuard / VPN ports.

## Trusted Devices

Trusted skips Blacklist, threat lists, and countries. Telemetry blocking can still apply. Local Network Only and Block Everything still apply at the network level.


# About

Copyright (C) 2026 iBGeek

## Product

**FoilGateway Network** by **iBGeek**. Version, OS, architecture, and board (when the box reports one) show on Settings → About.

## Software License

```
FoilGateway Network
Copyright (C) 2026 iBGeek

Permission is granted to anyone to use, copy, modify, and share this
software and its source, free of charge, for personal, educational, or
other non-commercial purposes, subject to the conditions below.

You may not sell this software, offer it as a paid product or paid
hosted service, or use it as part of a commercial product or service,
without a separate commercial license from iBGeek.

You must keep this copyright notice and this permission notice in all
copies and substantial portions of the software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
LIABLE FOR ANY CLAIM, DAMAGES, OR OTHER LIABILITY, WHETHER IN AN ACTION
OF CONTRACT, TORT, OR OTHERWISE, ARISING FROM, OUT OF, OR IN CONNECTION
WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

For commercial licensing, contact iBGeek.
```

## Support

[Support](https://github.com/iBgeek/FoilGateway-Network/discussions/1)

## Download Manual

Use Download Manual on Help or About for a standalone copy of this manual.


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
- **Normal** - Protection Mode that applies the Normal protection level; also the name of that level (Threat Lists On, Block All Telemetry Off, Block Encrypted DNS Off); also a device policy that follows network Hardening, lists, geo, and Ports.
- **FortNox** - Protection Level with Block Encrypted DNS On, Block All Telemetry On, Strict Outbound On, and Remote Desktop blocked on the LAN.
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
- **Block Encrypted DNS** - Hardening setting that stops DNS over TLS on port 853. Off by default and in Normal; On in FortNox. While On, devices set to require DNS over TLS cannot look up names.
- **DoT / DoH** - DNS over TLS (853) / DNS over HTTPS (often 443).
- **Stronger Identity** - remembers hostname and DHCP fingerprint hints when a phone rotates its MAC. Default Off.
- **Needs a Look** - Capture Log filter for rows worth a glance.
- **Undo / Rollback Timer** - if the browser loses the gateway after a risky change, the change undoes itself within the timer.
- **FoilGateway Network** - this product.
- **iBGeek** - copyright holder, Copyright (C) 2026.

