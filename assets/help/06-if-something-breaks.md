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
