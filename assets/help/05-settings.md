# Settings

Copyright (C) 2026 iBGeek

**Settings** - gateway configuration. Sub-topics, in order: Network & Access, Certificates, Time and Location, Capture Log, Users, Notifications, View, Setup, Updates, Help, About (always last). The API Reference opens from Users.

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

## Users

Who can sign in to these pages or use the API. Sign out is top-right on every page.

- **Users** lists every user with their role, whether they can sign in on the web, and whether they can use an API key. **Add User** and **Edit** open the same dialog.
- **Admin** users can do everything. **Custom** users get only the permissions ticked for them.
- Monitoring permissions: status and dashboard, devices, alerts and audit, Capture Log, firewall rules and ports (view only), speed test results, updates (see if one is out).
- Action permissions: block or allow a device, the Black list, the White list, mark alerts handled, run a speed test, check for updates.
- A Custom user sees only the pages and buttons their permissions cover. The server refuses anything else anyway.
- **Sign in on the web** needs a password of 10 or more characters. **Use the API with a key** gives the user an API key.
- The gateway always keeps one admin who can sign in. You can't make the last one Custom, turn off their web sign-in, or remove the user you are signed in as.
- **Your Password** changes the password of the user you are signed in as.
- **Signed In** lists open sessions. **Sign out** ends one.

### API keys

- A key starts with `fgk_`. It is shown once, when it is made, with a **Copy** button. The gateway keeps only a fingerprint of it, so a lost key can't be shown again. Make a new one instead.
- In a user's Edit dialog, **New Key** replaces the old key at once and **Revoke** stops it at once.
- **API Keys** lists each user's key by its first characters, when it was last used, and from which address.
- Wrong keys count toward the same lockout as wrong passwords: after 5 wrong tries from one address, that address has to wait.
- Turning off a user's API access stops their key. Turning off web sign-in ends their open sessions.

### Lists and permissions

The Black list and the White list have separate permissions. Adding an address to one list takes it off the other, so that needs both permissions. A user with only one of them is told the address is on the other list, and nothing changes. Taking an entry off a device's deny list from the Troubleshooter also needs both.

### Refused calls

When a user tries something they aren't allowed to do, the call is refused and written to the Capture Log (under Alerts and All). The dashboard gets one alert per user per 10 minutes, such as "3 refused calls from jarvis", and its count goes up while more come in.

### API Reference

**Open the API Reference** (on Users) lists every call a key can make, the permission it needs, and what it does. It also shows the permission ids and the notification format. Calls not listed are for admins only. A call the user isn't allowed to make gets 403.

A change made through the API waits to be kept, like a change made on the page. Send `POST /api/confirm` after it. Only the user who made the change, or an admin, can keep it. If nobody keeps it, it is undone when the undo time runs out.

## Notifications

Sends events to other systems, such as a home assistant, as signed JSON messages.

- **Add Destination** takes a name and a web address (http or https). You can have up to 10.
- When you add one, the gateway shows its **signing secret** once, with a **Copy** button. Each message carries a signature made with that secret, so the receiver can check it came from this gateway. **New Secret** makes a new one, and later messages use only the new secret.
- **Send these** picks which events go to that destination: new device, needs a look, blocked connections, audit, settings changed, update available, gateway started.
- **Send Test** sends a test message. **Edit** changes the name, address or events and keeps the secret. **Remove** deletes the destination.
- New device, needs-a-look and blocked messages go once per device every 5 minutes. The first goes at once. The rest in those 5 minutes arrive as one message that starts with the count, such as "4 more like this in 5 minutes".
- Sign-ins are written to the Capture Log but not sent.
- **Recent Sends** shows the last 50 messages: when, to whom, what, and the result. If an address can't be reached, the gateway tries again for 10 minutes and shows **Retrying**. After that the message shows **Not delivered**. A message that got through on a later try shows **Retried, delivered**.

## View

Which Dashboard cards are on. The server stores choices by card id. Turning a card off stops measuring work only that card needs.

## Setup

- **Run Setup Again** - type YES. Devices keep working until the last step; that step undoes itself if the browser loses the gateway. Users and their keys stay as they are. While setup runs, only admins can open it. Other users see a message to try again later.
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

FoilGateway installs its own updates. If an update ever has a problem, sign in to the gateway over SSH and run this command. It updates FoilGateway and keeps your settings:

```
curl -fsSL https://github.com/iBgeek/FoilGateway-Network/releases/latest/download/install.sh | sudo sh
```

If you are signed in as root, leave out sudo.

**Opening it:** Settings → Updates.

## Help

Settings → Help. Tabbed categories matching this manual, search, Download Manual.

## About

Settings → About (always last). Product name, version, OS, architecture, board when known, Software License text, Download Manual. [Support](https://github.com/iBgeek/FoilGateway-Network/discussions/1).
