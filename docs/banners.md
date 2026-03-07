# Banner Grabbing

Banner grabbing sends multiple payloads to open ports in order to identify services.

## Notes
- TCP and UDP banners are processed by separate threads.
- Results are stored in the `banners` table.
- Responses are saved both as raw bytes and as decoded text.
- Probe payload lists are deduplicated before scanning to avoid repeated requests.
- Probe selection is port-aware (HTTP, SMTP, DNS, SNMP, Redis, MQTT, RDP, SQL, etc.) and then falls back to generic probes.
- TCP uses connect/read timeouts and UDP uses read timeout per probe.
- TCP performs a passive read first to capture greeting banners (for example SSH/FTP/SMTP) before active probes.
- Probe flow stops early when enough unique banner responses are captured, repeated empty probes are detected, or duplicate responses repeat too many times.
