# server-status-python
One script server status monitor over web written in python

<img src="https://raw.githubusercontent.com/somik123/server-status-python/main/screenshot.png">

Uses only the Python 3 standard library (3.6+): no venv, no `pip install`, and the page works
without internet access. It runs on Debian, Ubuntu, Raspberry Pi OS and other Debian variants,
on anything from a Raspberry Pi to a large server. You do **not** need to run it as root.

### What it shows

- Uptime, hostname, IP, OS, kernel, device model and CPU model
- CPU usage (overall and per core), load average, temperatures, Raspberry Pi under-voltage / throttling
- Memory, cache and swap
- Disk space for every real filesystem (snap loops, tmpfs and Docker layers are skipped; hung network mounts are flagged instead of freezing the page)
- Network and disk I/O rates, with 15-minute history graphs
- Top processes by CPU and memory
- Service status in the sidebar (TCP ports or systemd units)
- When available: md RAID and ZFS pool health, Docker containers, NVIDIA GPUs, pending apt updates and "reboot required"

Cards for features the machine doesn't have are hidden automatically.

### Installation

Download to your server:
```
wget https://raw.githubusercontent.com/somik123/server-status-python/main/server.py
```

Start it up on port 9888:
```
python3 server.py 9888
```
> **Note:** If no port is provided, server will start up on port 9808

### Options

```
python3 server.py [PORT] [options]

  --bind, -b ADDRESS     address to listen on, e.g. 127.0.0.1 or :: (default: all IPv4 interfaces)
  --service, -s NAME:PORT|NAME:UNIT
                         service to show in the sidebar; repeatable, replaces the defaults
                         (HTTP:80, SSH:22, Samba:139). A non-numeric target is a systemd unit.
  --auth USER:PASSWORD   require HTTP Basic auth (or set SERVER_STATUS_AUTH instead)
  --interval SECONDS     sample / refresh interval (default: 2)
  --no-updates           don't count pending apt updates
  --verbose, -v          log every HTTP request
  --print-systemd-unit   print a systemd unit for the current options and exit
```

Example:
```
python3 server.py 9888 -s SSH:22 -s Plex:32400 -s Docker:docker.service
```

Optional extras need group membership for the user running the script: `docker` for the Docker
card, and `video` for Raspberry Pi throttling (`vcgencmd`).

### Start on boot (systemd, recommended)

```
python3 server.py 9888 --print-systemd-unit | sudo tee /etc/systemd/system/server-status.service
sudo systemctl daemon-reload
sudo systemctl enable --now server-status
```

To require a password, put `SERVER_STATUS_AUTH=user:password` in `/etc/server-status.env`
(`sudo chmod 600` it) and uncomment the `EnvironmentFile=` line in the unit.

### Start on boot (cron)

```
crontab -e
```

If the full path of the file is `/home/somik/status/server.py`, add to the bottom of the file:
```
@reboot python3 /home/somik/status/server.py 9888 > /home/somik/status/logs.txt 2>&1 &
```

### Endpoints

| Path | Description |
|---|---|
| `/` | Dashboard |
| `/api` | All current data as JSON (for Home Assistant, Homepage, scripts, ...) |
| `/api/history` | Last 15 minutes of CPU, memory and network samples |
| `/health` | `{"status": "ok" \| "warning", "warnings": [...]}`; add `?strict` to get HTTP 503 on warnings (for Uptime Kuma etc.) |
| `/metrics` | Prometheus text format |

`/health` warns about filesystems over 90% full or not responding, less than 10% memory
available, degraded RAID / ZFS, services that are down, and active Raspberry Pi throttling.
