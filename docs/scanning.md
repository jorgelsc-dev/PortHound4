# Scanning

## Scan types
- common: ports 1-1023
- not_common: ports 1024-65534
- full: ports 1-65534

## Protocol workers
- TCP worker scans only targets with `proto=tcp`.
- UDP worker scans only targets with `proto=udp`.
- ICMP worker scans only targets with `proto=icmp` and performs host discovery via echo requests.
- SCTP worker scans only targets with `proto=sctp` when the host OS/runtime supports SCTP sockets.
- This avoids duplicate scan threads on mixed target lists.

## Supported protocols
- `tcp`: port scan + timing tags.
- `udp`: port scan + timing tags.
- `icmp`: host reachability scan (stored as `port=0`, `proto=icmp`).
- `sctp`: port scan + timing tags (and `socket_type`) when `IPPROTO_SCTP` is available.

Check active protocols at runtime with `GET /protocols/`.

## ICMP notes
- ICMP uses raw sockets when available.
- If raw sockets are not permitted, ICMP falls back to `ping` subprocess and then TCP reachability probe.
- ICMP results are saved in `ports` and `tags` tables.

## Progress
Each target stores a progress percentage in the targets table. If a scan restarts, it will continue from the stored progress.

## Timing
Use `timesleep` to slow down scans when needed.
