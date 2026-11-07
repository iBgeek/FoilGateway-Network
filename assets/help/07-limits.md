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
