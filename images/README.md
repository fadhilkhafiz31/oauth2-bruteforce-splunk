# Screenshots

Place your screenshots here and they will be automatically displayed in the main README.

| Filename | Description |
|----------|-------------|
| `burpsuite-intruder-setup.png` | Burp Suite Intruder tab showing the payload position set on the `password` field |
| `burpsuite-intruder-results.png` | Burp Suite Intruder results table — payload 27 (`admin123`) returns HTTP 200 |
| `security-log-output.png` | Terminal view of `logs/security.log` showing `LOGIN_FAILED` and `LOGIN_SUCCESS` JSON events |
| `splunk-detection-query.png` | Splunk search results for the brute-force threshold detection SPL query |
| `splunk-dashboard-overview.png` | Full Splunk dashboard showing all five panels |
| `splunk-attack-timeline.png` | Splunk line chart showing the spike of `LOGIN_FAILED` events over time |

## How to add your own screenshots

1. Take a screenshot using your preferred tool (e.g., Snipping Tool, `scrot`, or the Burp Suite / Splunk built-in export).
2. Save it to this `images/` directory using the exact filename listed above.
3. Commit and push — the image will appear automatically in the README.

> **Tip:** PNG format is recommended for crisp UI screenshots. Keep files under 1 MB for fast page loads.
