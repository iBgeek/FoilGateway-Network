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
