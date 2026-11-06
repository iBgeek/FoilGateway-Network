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
