#!/usr/bin/env python3
"""
setup_netwatch.py – richtet die DHCP-/Netzwerk-Überwachung auf dem Raspberry Pi ein.

Installiert und konfiguriert:
  - tcpdump + dhcpdump (Paketinstallation)
  - systemd-Dienst "dhcp-capture" (DHCP-Mitschnitt UDP 67/68, Ringpuffer)
  - /usr/local/sbin/net-snapshot.sh (minütlicher Zustands-Snapshot)
  - Root-Cronjob für den Snapshot
  - Logrotate-Regel für /var/log/netwatch/

Aufruf auf dem Raspi:
    sudo python3 setup_netwatch.py [interface]

Ohne Argument wird das Interface aus der Default-Route ermittelt.
Das Skript ist idempotent und kann beliebig oft ausgeführt werden.
"""

import os
import subprocess
import sys
from pathlib import Path

UNIT_PATH = Path("/etc/systemd/system/dhcp-capture.service")
SNAPSHOT_PATH = Path("/usr/local/sbin/net-snapshot.sh")
LOGROTATE_PATH = Path("/etc/logrotate.d/netwatch")
DHCP_LOG_DIR = Path("/var/log/dhcp")
CRON_LINE = "* * * * * /usr/local/sbin/net-snapshot.sh"

UNIT_TEMPLATE = """\
[Unit]
Description=DHCP traffic capture (ring buffer)
After=network-online.target

[Service]
ExecStart=/usr/bin/tcpdump -i @IFACE@ -n -s0 'udp port 67 or udp port 68' -w /var/log/dhcp/dhcp.pcap -C 20 -W 5
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
"""

SNAPSHOT_TEMPLATE = """\
#!/bin/bash
LOG=/var/log/netwatch/state.log
mkdir -p /var/log/netwatch
{
  echo "===== $(date '+%F %T') ====="
  ip addr show
  ip route show
  ip neigh show
  nmcli -f DHCP4 connection show "$(nmcli -t -f NAME,DEVICE connection show --active | grep @IFACE@ | cut -d: -f1)" 2>/dev/null
  ping -c2 -W1 "$(ip route | awk '/default/ {print $3; exit}')" >/dev/null && echo "GW OK" || echo "GW FAIL"
} >> "$LOG" 2>&1
"""

LOGROTATE_CONF = """\
/var/log/netwatch/*.log {
    weekly
    rotate 8
    compress
    missingok
    notifempty
}
"""


def run(cmd: list[str], check: bool = True) -> subprocess.CompletedProcess:
    print(f"$ {' '.join(cmd)}")
    return subprocess.run(cmd, check=check)


def require_root() -> None:
    if os.geteuid() != 0:
        sys.exit("Fehler: Bitte mit sudo ausführen (sudo python3 setup_netwatch.py).")


def detect_interface() -> str:
    out = subprocess.run(
        ["ip", "route", "show", "default"], capture_output=True, text=True, check=True
    ).stdout
    parts = out.split()
    if "dev" in parts:
        return parts[parts.index("dev") + 1]
    sys.exit("Fehler: Kein Default-Interface gefunden. Bitte Interface als Argument übergeben.")


def install_packages() -> None:
    run(["apt-get", "update"])
    run(["apt-get", "install", "-y", "tcpdump", "dhcpdump"])


def write_file(path: Path, content: str, mode: int | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    if mode is not None:
        path.chmod(mode)
    print(f"geschrieben: {path}")


def install_cron() -> None:
    existing = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
    current = existing.stdout if existing.returncode == 0 else ""
    if CRON_LINE in current:
        print("Cronjob bereits vorhanden.")
        return
    new_crontab = current.rstrip("\n") + ("\n" if current.strip() else "") + CRON_LINE + "\n"
    subprocess.run(["crontab", "-"], input=new_crontab, text=True, check=True)
    print(f"Cronjob installiert: {CRON_LINE}")


def main() -> None:
    require_root()
    iface = sys.argv[1] if len(sys.argv) > 1 else detect_interface()
    print(f"Verwende Interface: {iface}")

    install_packages()

    DHCP_LOG_DIR.mkdir(parents=True, exist_ok=True)

    write_file(UNIT_PATH, UNIT_TEMPLATE.replace("@IFACE@", iface))
    write_file(SNAPSHOT_PATH, SNAPSHOT_TEMPLATE.replace("@IFACE@", iface), mode=0o755)
    write_file(LOGROTATE_PATH, LOGROTATE_CONF)

    install_cron()

    run(["systemctl", "daemon-reload"])
    run(["systemctl", "enable", "--now", "dhcp-capture"])

    print("\n--- Testlauf Snapshot ---")
    run([str(SNAPSHOT_PATH)])
    run(["tail", "-20", "/var/log/netwatch/state.log"], check=False)

    print("\n--- Status dhcp-capture ---")
    run(["systemctl", "status", "dhcp-capture", "--no-pager"], check=False)

    print(
        "\nFertig. Mitschnitt liegt unter /var/log/dhcp/ (Ringpuffer 5 x 20 MB),"
        "\nSnapshots unter /var/log/netwatch/state.log."
        "\n\nBeim nächsten Vorfall vom Windows-Rechner aus holen:"
        f"\n  scp <user>@<raspi-ip>:/var/log/dhcp/dhcp.pcap* C:\\Logs\\"
        "\nund in Wireshark mit Filter 'bootp' auswerten."
    )


if __name__ == "__main__":
    main()
