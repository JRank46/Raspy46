#!/usr/bin/env python3
"""
setup_netwatch.py – richtet die DHCP-/Netzwerk-Überwachung auf dem Raspberry Pi ein.

Installiert und konfiguriert:
  - tcpdump + dhcpdump (Paketinstallation, zur Auswertung)
  - /usr/local/sbin/netwatch.py (Python-Mitschnitt, kopiert aus netwatch.py neben diesem Skript)
  - systemd-Dienst "dhcp-capture" (startet netwatch.py beim Booten, PCAP-Ringpuffer)
  - /usr/local/sbin/net-snapshot.sh (minütlicher Zustands-Snapshot)
  - Root-Cronjob für den Snapshot
  - Logrotate-Regel für /var/log/netwatch/

Aufruf auf dem Raspi (netwatch.py muss im selben Verzeichnis liegen):
    sudo python3 setup_netwatch.py [interface] [--dhcp-server IP] [--mqtt-host <ha-ip> --mqtt-user <user>]

Mit --mqtt-host meldet der Dienst den Vorfallsstatus per MQTT (Auto-Discovery) an Home
Assistant. Das MQTT-Passwort wird einmalig abgefragt (oder aus $NETWATCH_MQTT_PASSWORD
gelesen) und in /etc/netwatch/mqtt_password (Modus 600) gespeichert.

Ohne Argumente werden Interface und erlaubter DHCP-Server (Gateway) aus der Default-Route
ermittelt. Antwortet ein anderer Server, sichert netwatch.py den Ringpuffer unter
/var/log/dhcp/incidents/.
Das Skript ist idempotent und kann beliebig oft ausgeführt werden.
"""

import argparse
import getpass
import os
import subprocess
import sys
from pathlib import Path

UNIT_PATH = Path("/etc/systemd/system/dhcp-capture.service")
SNAPSHOT_PATH = Path("/usr/local/sbin/net-snapshot.sh")
WATCHER_SRC = Path(__file__).resolve().parent / "netwatch.py"
WATCHER_PATH = Path("/usr/local/sbin/netwatch.py")
LOGROTATE_PATH = Path("/etc/logrotate.d/netwatch")
DHCP_LOG_DIR = Path("/var/log/dhcp")
MQTT_PASSWORD_PATH = Path("/etc/netwatch/mqtt_password")
CRON_LINE = "* * * * * /usr/local/sbin/net-snapshot.sh"

UNIT_TEMPLATE = """\
[Unit]
Description=DHCP traffic capture (ring buffer)
After=network-online.target

[Service]
ExecStart=/usr/bin/python3 /usr/local/sbin/netwatch.py @IFACE@ --dir /var/log/dhcp --size-mb 20 --files 5 --allowed-server @DHCP_SERVER@@HA_ARGS@
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


def detect_gateway() -> str | None:
    out = subprocess.run(
        ["ip", "route", "show", "default"], capture_output=True, text=True, check=True
    ).stdout
    parts = out.split()
    return parts[parts.index("via") + 1] if "via" in parts else None


def setup_mqtt_password(reset: bool) -> None:
    if MQTT_PASSWORD_PATH.exists() and not reset:
        print(f"MQTT-Passwort vorhanden ({MQTT_PASSWORD_PATH}), wird weiterverwendet.")
        return
    password = os.environ.get("NETWATCH_MQTT_PASSWORD") or getpass.getpass(
        "MQTT-Passwort (Eingabe unsichtbar): "
    )
    if not password:
        sys.exit("Fehler: Kein Passwort angegeben.")
    MQTT_PASSWORD_PATH.parent.mkdir(parents=True, exist_ok=True)
    # Datei erst mit restriktiven Rechten anlegen, dann beschreiben
    fd = os.open(MQTT_PASSWORD_PATH, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(password + "\n")
    MQTT_PASSWORD_PATH.chmod(0o600)
    print(f"MQTT-Passwort gespeichert: {MQTT_PASSWORD_PATH} (Modus 600)")


def main() -> None:
    parser = argparse.ArgumentParser(description="DHCP-Überwachung auf dem Raspi einrichten.")
    parser.add_argument("interface", nargs="?", help="Interface (Standard: aus der Default-Route)")
    parser.add_argument("--dhcp-server", help="Erlaubte DHCP-Server-IP (Standard: Gateway aus der Default-Route)")
    parser.add_argument("--mqtt-host", help="MQTT-Broker (Mosquitto auf Home Assistant); aktiviert die Meldung an HA")
    parser.add_argument("--mqtt-port", type=int, default=1883, help="MQTT-Port (Standard: 1883)")
    parser.add_argument("--mqtt-user", help="MQTT-Benutzer (das Passwort wird abgefragt)")
    parser.add_argument("--reset-mqtt-password", action="store_true", help="Gespeichertes MQTT-Passwort neu abfragen")
    args = parser.parse_args()

    require_root()
    iface = args.interface or detect_interface()
    dhcp_server = args.dhcp_server or detect_gateway()
    if not dhcp_server:
        sys.exit("Fehler: Gateway nicht ermittelbar. Bitte --dhcp-server <IP> angeben.")
    print(f"Verwende Interface: {iface}, erlaubter DHCP-Server: {dhcp_server}")

    ha_args = ""
    if args.mqtt_host:
        ha_args = f" --mqtt-host {args.mqtt_host} --mqtt-port {args.mqtt_port}"
        if args.mqtt_user:
            setup_mqtt_password(args.reset_mqtt_password)
            ha_args += f" --mqtt-user {args.mqtt_user} --mqtt-password-file {MQTT_PASSWORD_PATH}"

    install_packages()

    DHCP_LOG_DIR.mkdir(parents=True, exist_ok=True)

    if not WATCHER_SRC.is_file():
        sys.exit(f"Fehler: {WATCHER_SRC} nicht gefunden (netwatch.py muss neben diesem Skript liegen).")
    write_file(WATCHER_PATH, WATCHER_SRC.read_text(encoding="utf-8"), mode=0o755)
    write_file(
        UNIT_PATH,
        UNIT_TEMPLATE.replace("@IFACE@", iface).replace("@DHCP_SERVER@", dhcp_server).replace("@HA_ARGS@", ha_args),
    )
    write_file(SNAPSHOT_PATH, SNAPSHOT_TEMPLATE.replace("@IFACE@", iface), mode=0o755)
    write_file(LOGROTATE_PATH, LOGROTATE_CONF)

    install_cron()

    run(["systemctl", "daemon-reload"])
    run(["systemctl", "enable", "dhcp-capture"])
    run(["systemctl", "restart", "dhcp-capture"])

    print("\n--- Testlauf Snapshot ---")
    run([str(SNAPSHOT_PATH)])
    run(["tail", "-20", "/var/log/netwatch/state.log"], check=False)

    print("\n--- Status dhcp-capture ---")
    run(["systemctl", "status", "dhcp-capture", "--no-pager"], check=False)

    print(
        "\nFertig. Mitschnitt liegt unter /var/log/dhcp/ (Ringpuffer 5 x 20 MB),"
        "\ngesicherte Vorfälle unter /var/log/dhcp/incidents/,"
        "\nSnapshots unter /var/log/netwatch/state.log."
        "\n\nBeim nächsten Vorfall vom Windows-Rechner aus holen:"
        f"\n  scp <user>@<raspi-ip>:/var/log/dhcp/dhcp.pcap* C:\\Logs\\"
        "\nund in Wireshark mit Filter 'bootp' auswerten."
    )


if __name__ == "__main__":
    main()
