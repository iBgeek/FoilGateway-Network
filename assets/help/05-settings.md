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

- **Check Now** - asks GitHub for the latest release right away. FoilGateway also checks shortly after it starts and every hour. If a check fails, it tries again sooner.
- **Install Update** - downloads the matching binary and web package, checks SHA256SUMS, installs into the version slots, and restarts. Shown only when a newer release is available. A confirm lists the version change and that the gateway restarts.
- **Roll Back To Previous Version** - puts back the version kept from the last update and restarts. Shown when a previous slot exists.

When a newer version is available, a notice shows at the top of every page. Open Updates on the notice goes to this page; it does not install anything.

If this page does not come back after Install Update, FoilGateway restores the previous version within the undo timer. Updates never install by themselves.

**Opening it:** Settings → Updates.

## Help

Settings → Help. Tabbed categories matching this manual, search, Download Manual.

## About

Settings → About (always last). Product name, version, OS, architecture, board when known, Software License text, Download Manual. [Support](https://github.com/iBgeek/FoilGateway-Network/discussions/1).
