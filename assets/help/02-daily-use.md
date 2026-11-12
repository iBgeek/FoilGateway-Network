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

Alerts show things that still need attention, such as a new device, an allowed threat-list match in Audit, or a filtering failure. Already stopped traffic does not create a suspicious, new-port or volume-spike warning. Resolved warnings leave Alerts and Needs a Look. Raw history remains under Capture Log → All, and stopped attempts remain under Blocked.

**Clear** on an alert row takes it off the dashboard. **Clear All Shown** clears every alert the list shows right now, so search or filter first to clear only those; it asks before it clears. Cleared alerts stay in the Capture Log, marked handled. Only alerts can be cleared, and only by users allowed to mark alerts handled.

Refused calls show as one alert per user per 10 minutes, with the count. Each refused call is in the Capture Log. Old port observations without an outcome stay unclassified unless matching inbound drop evidence or a handled decision is available; they are not assumed stopped.

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
