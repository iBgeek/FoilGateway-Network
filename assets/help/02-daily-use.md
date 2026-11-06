# Daily Use

Copyright (C) 2026 iBGeek

## Dashboard

**Dashboard** - home screen after sign-in. Status cards across the top (on or off under Settings → View):

- **Mode** - current Protection Mode, and whether telemetry is blocked network-wide.
- **Traffic Path** - In path or Not in path, and whether filtering is on.
- **WAN Speed** / **LAN Speed** - in and out rates, two lines each.
- **Countries Now** - countries with live connections. Click for the country names.
- **Devices Online** - count of devices seen recently.
- **CPU Load**, **CPU Temperature** (caption only when hot), **Disk**, **Memory**
- **Blocked Today** - block count for today, with a subtitle that compares volume to what is usual for this hour.

Below the cards: the live map (arcs, home ring, Pause Motion / Play Motion) and the open connections table. Alerts cover new devices, new ports, and suspicious activity.

### Blocked Today

The number is today's full block count. The subtitle compares a quieter alarm count to what is usual for this hour. Blocks from Block All Telemetry, Local Network Only, and Block All are left out of that comparison.

Subtitles:

- **Likely attack · far above usual**
- **Higher than usual**
- **Usual for this hour**
- **Open the log**
- **Learning usual · first week** (first roughly six days after a fresh install)

**Opening today's blocks:** click Blocked Today. The Capture Log opens filtered to today's blocks.

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

Pick a device (or arrive from an alert). The page shows status notes, a likely-cause strip when one is known (reason, remote, protocol, port), Allow actions beside that line, and recent blocked / audit context for that device. Blocked apps can be allowed from here.

## Capture Log

**Capture Log** - searchable history of blocks, device events, alerts, audit rows, DHCP, settings changes, and list downloads.

Filters: Needs a Look; kind (All, Blocked, Devices, Alerts, Audit, DHCP, Settings, Downloads); search; Today; date range; sort; Download.

Retention and download controls also sit under Settings → Capture Log.
