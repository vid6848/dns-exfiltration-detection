# CyberTrace DNS Alerts (Chrome extension)

Desktop notifications for suspicious DNS activity flagged by a CyberTrace server, so
an analyst does not need to keep the dashboard open.

## What it does

- Every 30 seconds (configurable) it calls `GET /alerts` on the configured server.
- Each new suspicious event raises a desktop notification with the domain, host,
  attack score and the reasons (high entropy, query burst, many unique subdomains…).
  Several at once are grouped into one notification.
- The toolbar badge shows the unread count; the popup lists recent alerts and live
  counts. Clicking a notification opens the dashboard.
- Optional, off by default: **check the sites this browser contacts**. Each hostname
  (never the full URL or page content), at most once a minute, is sent to `POST /ingest`
  under a per-browser `capture_id`.

## Install (unpacked)

1. Open `chrome://extensions` and switch on **Developer mode**.
2. **Load unpacked** and pick this `extension/` folder.
3. The settings page opens: enter the server URL (for example the Render URL), press
   **Save**, and allow Chrome to contact that site.
4. Make sure Chrome notifications are allowed by the operating system
   (macOS: System Settings › Notifications › Google Chrome).

To share it, zip this folder (or use **Pack extension** on `chrome://extensions`).

## Limits

- Alerts come from whatever feeds the server: the dashboard, `scripts/dns_sensor.py`
  (live capture or replay), or the browser option above.
- A browser cannot see raw DNS packets; the browser option approximates lookups from the
  hostnames of web requests.
- The server keeps alerts in memory. If the free host restarts or sleeps, earlier alerts
  are gone, and the first check after waking can take ~30–60 seconds.
