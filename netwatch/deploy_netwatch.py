#!/usr/bin/env python3
"""
deploy_netwatch.py – kopiert setup_netwatch.py und netwatch.py per scp auf den Raspi und führt es optional aus.

Voraussetzung: OpenSSH-Client (ssh/scp) auf dem Windows-Rechner (in Windows 10/11 enthalten).
Nur Standardbibliothek.

Beispiele:
    python deploy_netwatch.py 192.168.2.50            # nur kopieren
    python deploy_netwatch.py 192.168.2.50 --run      # kopieren und mit sudo ausführen
    python deploy_netwatch.py 192.168.2.50 --run --iface eth0
    python deploy_netwatch.py 192.168.2.50 -u jr46 --dest /home/jr46
"""

import argparse
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

SCRIPT_NAME = "setup_netwatch.py"
WATCHER_NAME = "netwatch.py"
LOCAL_SCRIPT = Path(__file__).resolve().parent / SCRIPT_NAME


def run(cmd: list[str]) -> None:
    print(f"$ {' '.join(cmd)}")
    result = subprocess.run(cmd)
    if result.returncode != 0:
        sys.exit(f"Fehler: Befehl endete mit Exit-Code {result.returncode}.")


def main() -> None:
    parser = argparse.ArgumentParser(description=f"{SCRIPT_NAME} auf den Raspi übertragen.")
    parser.add_argument("host", help="IP oder Hostname des Raspi (z. B. 192.168.2.50)")
    parser.add_argument("-u", "--user", default="jr46", help="SSH-Benutzer (Standard: jr46)")
    parser.add_argument("--dest", default="~", help="Zielverzeichnis auf dem Raspi (Standard: ~)")
    parser.add_argument("--run", action="store_true", help="Skript nach dem Kopieren mit sudo ausführen")
    parser.add_argument("--iface", help="Interface für setup_netwatch.py (Standard: automatisch)")
    parser.add_argument("--dhcp-server", help="Erlaubte DHCP-Server-IP (Standard: Gateway)")
    parser.add_argument("--mqtt-host", help="MQTT-Broker (Mosquitto auf Home Assistant), z. B. 192.168.2.10")
    parser.add_argument("--mqtt-port", type=int, default=1883, help="MQTT-Port (Standard: 1883)")
    parser.add_argument("--mqtt-user", help="MQTT-Benutzer (das Passwort wird auf dem Raspi abgefragt)")
    parser.add_argument("--reset-mqtt-password", action="store_true", help="MQTT-Passwort auf dem Raspi neu abfragen")
    args = parser.parse_args()

    for script in (LOCAL_SCRIPT, LOCAL_SCRIPT.with_name(WATCHER_NAME)):
        if not script.is_file():
            sys.exit(f"Fehler: {script} nicht gefunden.")
    for tool in ("ssh", "scp"):
        if shutil.which(tool) is None:
            sys.exit(f"Fehler: '{tool}' nicht gefunden. OpenSSH-Client installieren.")

    target = f"{args.user}@{args.host}"
    sources = [str(LOCAL_SCRIPT), str(LOCAL_SCRIPT.with_name(WATCHER_NAME))]
    run(["scp", *sources, f"{target}:{args.dest}/"])
    print(f"Kopiert nach {target}:{args.dest}/ ({SCRIPT_NAME}, {WATCHER_NAME})")

    if not args.run:
        print(f"\nAusführen mit:\n  ssh -t {target} 'sudo python3 {args.dest}/{SCRIPT_NAME}'")
        return

    remote_cmd = f"sudo python3 {args.dest}/{SCRIPT_NAME}"
    if args.iface:
        remote_cmd += f" {shlex.quote(args.iface)}"
    if args.dhcp_server:
        remote_cmd += f" --dhcp-server {shlex.quote(args.dhcp_server)}"
    if args.mqtt_host:
        remote_cmd += f" --mqtt-host {shlex.quote(args.mqtt_host)} --mqtt-port {args.mqtt_port}"
    if args.mqtt_user:
        remote_cmd += f" --mqtt-user {shlex.quote(args.mqtt_user)}"
    if args.reset_mqtt_password:
        remote_cmd += " --reset-mqtt-password"
    # -t: TTY für die sudo-Passwortabfrage
    run(["ssh", "-t", target, remote_cmd])


if __name__ == "__main__":
    main()
