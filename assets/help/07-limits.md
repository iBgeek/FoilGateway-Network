# Limits

Copyright (C) 2026 iBGeek

## Placement

Everything downstream of the LAN port (switches, Wi-Fi, and all devices behind FoilGateway) is protected by FoilGateway. Anything upstream of the WAN port is not.

## Encrypted DNS on Port 443

When Block Encrypted DNS (Port 853) is On, FoilGateway blocks DNS over TLS on port 853. Devices set to require DNS over TLS (for example Android Private DNS set to a provider name) cannot look up names while it is On. Some apps still use encrypted DNS on port 443. FoilGateway often misses new names from those apps. Names already on your lists still become address blocks. IP, port, geo, and threat hardening still apply.

See Protection → DNS Proxy (Addon).

## Volume Detection

Blocked Today and Likely Attack compare block volume to what is usual for this hour. Deeper Detection (default Off) adds quieter pattern checks beyond volume spikes.

## IPv6

Block IPv6 (Hardening) defaults to Off. Off allows IPv6 through the gateway with the same hardening that applies to IPv4. On blocks IPv6 through the gateway onto the LAN; neighbour discovery and DHCPv6 still work. Threat feeds include DROPv6. Safety hosts in this build are IPv4.

## VPN Tunnels

Traffic inside a VPN tunnel cannot be read. Geo and threat lists apply to the tunnel endpoints you can see. Block VPN Ports (default Off) can stop common WireGuard / VPN ports.

## Trusted Devices

Trusted skips Blacklist, threat lists, and countries. Telemetry blocking can still apply. Local Network Only and Block Everything still apply at the network level.
