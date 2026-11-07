#!/usr/bin/env python3
"""
netwatch.py – DHCP-Mitschnitt als reines Python-Skript (nur Standardbibliothek, Linux).

Liest per AF_PACKET-Socket alle DHCP-Pakete (UDP 67/68, IPv4) von einem Interface und
schreibt sie als PCAP-Dateien in einen Ringpuffer (dhcp.pcap0 ... dhcp.pcap<N-1>),
kompatibel zu Wireshark/tcpdump.

Bei auffälligem Verhalten (z. B. DHCP-Antwort von einem unerlaubten Server) wird der
Ringpuffer als Vorfall nach /var/log/dhcp/incidents/ kopiert und so vor dem Überschreiben
geschützt (siehe AnomalyMonitor). Optional meldet es den Status per MQTT an Home Assistant
(--mqtt-host, siehe HomeAssistantPublisher).

Aufruf (root nötig, wird normalerweise vom systemd-Dienst dhcp-capture gestartet):
    sudo python3 netwatch.py eth0 --allowed-server 192.168.2.1 [--dir /var/log/dhcp] [--size-mb 20] [--files 5]
"""

import argparse
import json
import shutil
import signal
import socket
import struct
import sys
import threading
import time
from datetime import datetime
from pathlib import Path

ETH_P_ALL = 0x0003
ETH_P_IP = 0x0800
VLAN_TYPES = (0x8100, 0x88A8)
DHCP_PORTS = (67, 68)
SNAPLEN = 65535
LINKTYPE_ETHERNET = 1
PCAP_GLOBAL_HEADER = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, SNAPLEN, LINKTYPE_ETHERNET)

_stop = False


def parse_udp(frame: bytes):
    """Liefert (src_mac, src_ip, sport, dport, payload) für IPv4/UDP-Frames, sonst None."""
    if len(frame) < 14:
        return None
    offset = 14
    ethertype = struct.unpack("!H", frame[12:14])[0]
    while ethertype in VLAN_TYPES:
        if len(frame) < offset + 4:
            return None
        ethertype = struct.unpack("!H", frame[offset + 2 : offset + 4])[0]
        offset += 4
    if ethertype != ETH_P_IP or len(frame) < offset + 20:
        return None
    ihl = (frame[offset] & 0x0F) * 4
    if frame[offset + 9] != 17:  # kein UDP
        return None
    if struct.unpack("!H", frame[offset + 6 : offset + 8])[0] & 0x1FFF:  # Folgefragment
        return None
    udp = offset + ihl
    if ihl < 20 or len(frame) < udp + 8:
        return None
    sport, dport = struct.unpack("!HH", frame[udp : udp + 4])
    src_ip = socket.inet_ntoa(frame[offset + 12 : offset + 16])
    return format_mac(frame[6:12]), src_ip, sport, dport, frame[udp + 8 :]


def is_dhcp(frame: bytes) -> bool:
    parsed = parse_udp(frame)
    return parsed is not None and (parsed[2] in DHCP_PORTS or parsed[3] in DHCP_PORTS)


def format_mac(raw: bytes) -> str:
    return ":".join(f"{b:02x}" for b in raw)


def parse_dhcp(frame: bytes):
    """Liefert ein dict mit den relevanten BOOTP/DHCP-Feldern oder None."""
    parsed = parse_udp(frame)
    if parsed is None or not (parsed[2] in DHCP_PORTS or parsed[3] in DHCP_PORTS):
        return None
    src_mac, src_ip, _, _, p = parsed
    if len(p) < 240 or p[236:240] != b"\x63\x82\x53\x63":
        return None
    info = {
        "src_mac": src_mac,
        "src_ip": src_ip,
        "op": p[0],
        "xid": struct.unpack("!I", p[4:8])[0],
        "client_mac": format_mac(p[28 : 28 + min(p[2], 16)]),
        "msg_type": None,
        "server_id": None,
    }
    i = 240
    while i < len(p):
        code = p[i]
        if code == 255:
            break
        if code == 0:
            i += 1
            continue
        if i + 1 >= len(p):
            break
        length = p[i + 1]
        data = p[i + 2 : i + 2 + length]
        if code == 53 and length == 1:
            info["msg_type"] = data[0]
        elif code == 54 and length == 4:
            info["server_id"] = socket.inet_ntoa(data)
        i += 2 + length
    return info


class RingPcapWriter:
    """Schreibt PCAP-Dateien <prefix>0..<prefix>N-1 reihum, jede höchstens max_bytes groß."""

    def __init__(self, directory: Path, prefix: str, max_bytes: int, files: int) -> None:
        self.directory = directory
        self.prefix = prefix
        self.max_bytes = max_bytes
        self.files = files
        self.fh = None
        self.size = 0
        self.index = self._next_index()
        self._open()

    def _path(self, index: int) -> Path:
        return self.directory / f"{self.prefix}{index}"

    def _next_index(self) -> int:
        # Nach einem Neustart hinter der zuletzt beschriebenen Datei weitermachen.
        existing = [(self._path(i).stat().st_mtime, i) for i in range(self.files) if self._path(i).exists()]
        return (max(existing)[1] + 1) % self.files if existing else 0

    def _open(self) -> None:
        self.fh = open(self._path(self.index), "wb")
        self.fh.write(PCAP_GLOBAL_HEADER)
        self.fh.flush()
        self.size = len(PCAP_GLOBAL_HEADER)

    def write(self, frame: bytes, timestamp: float) -> None:
        data = frame[:SNAPLEN]
        record = struct.pack(
            "<IIII", int(timestamp), int((timestamp % 1) * 1_000_000), len(data), len(frame)
        )
        if self.size + len(record) + len(data) > self.max_bytes and self.size > len(PCAP_GLOBAL_HEADER):
            self.fh.close()
            self.index = (self.index + 1) % self.files
            self._open()
        self.fh.write(record + data)
        self.fh.flush()  # DHCP-Verkehr ist gering; so bleibt der Mitschnitt auch bei Absturz lesbar
        self.size += len(record) + len(data)

    def close(self) -> None:
        if self.fh:
            self.fh.close()


class AnomalyMonitor:
    """Erkennt auffälliges DHCP-Verhalten und sichert den Ringpuffer als Vorfall.

    Erkannt werden:
      rogue-server     DHCP-Antwort (Offer/ACK/NAK) von einer nicht erlaubten Absender-IP
      multiple-servers verschiedene Absender-IPs antworten auf dieselbe Transaktion (xid)
      no-offer         Discover ohne Offer innerhalb des Timeouts (optional)

    Bei einem Vorfall wird der Ringpuffer sofort nach <incident_dir>/<zeit>_<grund>/at-trigger
    kopiert und nach Ablauf der Haltezeit erneut nach .../after-hold, damit auch der
    weitere Verlauf gesichert ist. Während der Haltezeit und der Sperrzeit (cooldown) werden
    weitere Auffälligkeiten nur protokolliert.
    """

    def __init__(self, writer, incident_dir, allowed_servers, hold=120, cooldown=600,
                 max_incidents=20, no_offer_timeout=0):
        self.writer = writer
        self.incident_dir = incident_dir
        self.allowed = set(allowed_servers)
        self.hold = hold
        self.cooldown = cooldown
        self.max_incidents = max_incidents
        self.no_offer_timeout = no_offer_timeout
        self.replies = {}  # xid -> (zeitpunkt, {absender-ips})
        self.discovers = {}  # xid -> (zeitpunkt, client_mac)
        self.active = None  # (verzeichnis, endzeit)
        self.last_incident = float("-inf")
        self.on_incident = None  # Callback nach einem neu gesicherten Vorfall

    def inspect(self, frame: bytes, now: float) -> None:
        pkt = parse_dhcp(frame)
        if pkt is None or pkt["msg_type"] is None:
            return
        if pkt["op"] == 1 and pkt["msg_type"] == 1 and self.no_offer_timeout:
            self.discovers[pkt["xid"]] = (now, pkt["client_mac"])
        if pkt["op"] != 2 or pkt["msg_type"] not in (2, 5, 6):  # Offer, ACK, NAK
            return
        if pkt["msg_type"] == 2:
            self.discovers.pop(pkt["xid"], None)
        who = f"Server {pkt['src_ip']} ({pkt['src_mac']}) -> Client {pkt['client_mac']}, xid {pkt['xid']:#x}"
        if self.allowed and pkt["src_ip"] not in self.allowed:
            self.trigger("rogue-server", f"DHCP-Antwort von nicht erlaubtem {who}", now)
        seen_at, servers = self.replies.setdefault(pkt["xid"], (now, set()))
        servers.add(pkt["src_ip"])
        if len(servers) > 1:
            self.trigger("multiple-servers", f"Mehrere Server antworten ({', '.join(sorted(servers))}): {who}", now)

    def tick(self, now: float) -> None:
        for xid, (t, mac) in list(self.discovers.items()):
            if now - t >= self.no_offer_timeout:
                del self.discovers[xid]
                self.trigger("no-offer", f"Discover von {mac} (xid {xid:#x}) ohne Offer", now)
        for xid, (t, _) in list(self.replies.items()):
            if now - t > 60:
                del self.replies[xid]
        if self.active and now >= self.active[1]:
            self._copy_ring(self.active[0] / "after-hold")
            print(f"Vorfall abgeschlossen: {self.active[0]}", flush=True)
            self.active = None

    def trigger(self, reason: str, detail: str, now: float) -> None:
        line = f"{time.strftime('%F %T', time.localtime(now))} [{reason}] {detail}"
        print(f"AUFFÄLLIG: {line}", flush=True)
        self.incident_dir.mkdir(parents=True, exist_ok=True)
        with open(self.incident_dir / "incidents.log", "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
        if self.active:
            with open(self.active[0] / "events.txt", "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
            return
        if now - self.last_incident < self.cooldown:
            return
        self.last_incident = now
        target = self.incident_dir / f"{time.strftime('%Y%m%d-%H%M%S', time.localtime(now))}_{reason}"
        target.mkdir(parents=True, exist_ok=True)
        (target / "events.txt").write_text(line + "\n", encoding="utf-8")
        self._copy_ring(target / "at-trigger")
        self.active = (target, now + self.hold)
        self._prune()
        if self.on_incident:
            self.on_incident()

    def _copy_ring(self, dest: Path) -> None:
        dest.mkdir(parents=True, exist_ok=True)
        for i in range(self.writer.files):
            src = self.writer.directory / f"{self.writer.prefix}{i}"
            if src.exists():
                shutil.copy2(src, dest / src.name)

    def _prune(self) -> None:
        incidents = sorted(p for p in self.incident_dir.iterdir() if p.is_dir())
        for old in incidents[: max(0, len(incidents) - self.max_incidents)]:
            shutil.rmtree(old, ignore_errors=True)


class MiniMqtt:
    """Minimaler MQTT-3.1.1-Client (nur CONNECT und PUBLISH mit QoS 0, retained) ohne Fremdbibliothek."""

    def __init__(self, host, port, client_id, user=None, password=None, will_topic=None,
                 will_payload="", keepalive=120):
        self.host, self.port = host, port
        self.client_id, self.user, self.password = client_id, user, password
        self.will_topic, self.will_payload = will_topic, will_payload
        self.keepalive = keepalive
        self.sock = None

    @staticmethod
    def _str(value: str) -> bytes:
        raw = value.encode("utf-8")
        return struct.pack("!H", len(raw)) + raw

    @staticmethod
    def _packet(first_byte: int, body: bytes) -> bytes:
        length, encoded = len(body), bytearray()
        while True:
            digit, length = length % 128, length // 128
            encoded.append(digit | (0x80 if length else 0))
            if not length:
                break
        return bytes([first_byte]) + bytes(encoded) + body

    def connect(self) -> None:
        self.sock = socket.create_connection((self.host, self.port), timeout=10)
        flags = 0x02  # clean session
        payload = self._str(self.client_id)
        if self.will_topic:
            flags |= 0x04 | 0x20  # Last Will, retained
            payload += self._str(self.will_topic) + self._str(self.will_payload)
        if self.user:
            flags |= 0x80
            payload += self._str(self.user)
            if self.password:
                flags |= 0x40
                payload += self._str(self.password)
        body = self._str("MQTT") + bytes([4, flags]) + struct.pack("!H", self.keepalive) + payload
        self.sock.sendall(self._packet(0x10, body))
        reply = b""
        while len(reply) < 4:
            chunk = self.sock.recv(4 - len(reply))
            if not chunk:
                raise ConnectionError("Verbindung vom Broker geschlossen")
            reply += chunk
        if reply[0] != 0x20 or reply[3] != 0:
            raise ConnectionError(f"MQTT-Anmeldung abgelehnt (Code {reply[3]}); Benutzer/Passwort prüfen")

    def publish(self, topic: str, payload: str, retain: bool = True) -> None:
        self.sock.sendall(self._packet(0x30 | int(retain), self._str(topic) + payload.encode("utf-8")))

    def close(self) -> None:
        if self.sock:
            try:
                self.sock.sendall(b"\xe0\x00")  # DISCONNECT (löst den Last Will bewusst nicht aus)
            except OSError:
                pass
            self.sock.close()
            self.sock = None


class HomeAssistantPublisher:
    """Meldet den Vorfallsstatus per MQTT (Auto-Discovery) an Home Assistant.

    Der Zustand wird aus dem Vorfallsordner auf der Platte berechnet und periodisch (Heartbeat)
    sowie sofort nach einem neuen Vorfall gesendet. Ist der Broker oder das Netz gerade nicht
    erreichbar, wird neu verbunden und der Zustand nachgeliefert. Läuft in einem eigenen Thread,
    damit der Mitschnitt nie blockiert. Fällt der Raspi aus, setzt der Broker per Last Will
    alle Entitäten auf "nicht verfügbar".

    Entitäten (per Discovery angelegt, Gerät "Netwatch"):
      binary_sensor.netwatch_incident        an, wenn der letzte Vorfall jünger als alert_hours ist
      sensor.netwatch_incident_count         Anzahl der gesicherten Vorfälle
      sensor.netwatch_last_incident          Zeitpunkt des letzten Vorfalls (timestamp)
    """

    def __init__(self, host, port, user, password, incident_dir, alert_hours=24.0, interval=60):
        self.host_name = host
        self.port = port
        self.user = user
        self.password = password
        self.incident_dir = incident_dir
        self.alert_seconds = alert_hours * 3600
        self.interval = interval
        self.wake = threading.Event()
        self.host = socket.gethostname().lower()
        self.base = f"netwatch/{self.host}"
        self.avail_topic = f"{self.base}/availability"
        self.thread = threading.Thread(target=self._run, name="mqtt-publisher", daemon=True)
        self.failed = False

    def start(self) -> None:
        self.thread.start()

    def kick(self) -> None:
        self.wake.set()

    def _latest_incident(self):
        dirs = sorted(p for p in self.incident_dir.iterdir() if p.is_dir()) if self.incident_dir.is_dir() else []
        if not dirs:
            return None, 0
        latest = dirs[-1]
        stamp, _, reason = latest.name.partition("_")
        try:
            when = datetime.strptime(stamp, "%Y%m%d-%H%M%S").astimezone()
        except ValueError:
            when = datetime.fromtimestamp(latest.stat().st_mtime).astimezone()
        try:
            detail = (latest / "events.txt").read_text(encoding="utf-8").splitlines()[0]
        except (OSError, IndexError):
            detail = ""
        return {"time": when, "reason": reason, "folder": latest.name, "detail": detail}, len(dirs)

    def _discovery(self) -> list:
        """Liefert (Topic, Config) für MQTT-Discovery; HA legt Gerät und Entitäten selbst an."""
        device = {
            "identifiers": [f"netwatch_{self.host}"],
            "name": "Netwatch",
            "manufacturer": "Raspy46",
            "model": "DHCP-Überwachung",
        }
        common = {"availability_topic": self.avail_topic, "device": device}
        node = f"netwatch_{self.host}"
        return [
            (f"homeassistant/binary_sensor/{node}/incident/config", {
                **common, "name": "Incident", "unique_id": f"{node}_incident",
                "state_topic": f"{self.base}/incident", "payload_on": "ON", "payload_off": "OFF",
                "device_class": "problem", "json_attributes_topic": f"{self.base}/incident/attributes",
            }),
            (f"homeassistant/sensor/{node}/incident_count/config", {
                **common, "name": "Incident count", "unique_id": f"{node}_incident_count",
                "state_topic": f"{self.base}/incident_count", "icon": "mdi:alert-network",
                "state_class": "measurement",
            }),
            (f"homeassistant/sensor/{node}/last_incident/config", {
                **common, "name": "Last incident", "unique_id": f"{node}_last_incident",
                "state_topic": f"{self.base}/last_incident", "device_class": "timestamp",
            }),
        ]

    def publish(self, mqtt: "MiniMqtt") -> None:
        latest, count = self._latest_incident()
        recent = bool(latest) and (time.time() - latest["time"].timestamp()) < self.alert_seconds
        attrs = {"host": self.host, "path": str(self.incident_dir)}
        if latest:
            attrs.update(reason=latest["reason"], detail=latest["detail"],
                         incident_folder=latest["folder"], incident_time=latest["time"].isoformat())
        mqtt.publish(f"{self.base}/incident", "ON" if recent else "OFF")
        mqtt.publish(f"{self.base}/incident/attributes", json.dumps(attrs, ensure_ascii=False))
        mqtt.publish(f"{self.base}/incident_count", str(count))
        mqtt.publish(f"{self.base}/last_incident", latest["time"].isoformat() if latest else "None")

    def _run(self) -> None:
        while True:
            mqtt = MiniMqtt(self.host_name, self.port, f"netwatch-{self.host}", self.user, self.password,
                            will_topic=self.avail_topic, will_payload="offline")
            try:
                mqtt.connect()
                for topic, config in self._discovery():
                    mqtt.publish(topic, json.dumps(config, ensure_ascii=False))
                mqtt.publish(self.avail_topic, "online")
                if self.failed:
                    print("MQTT-Broker wieder erreichbar.", flush=True)
                self.failed = False
                while True:
                    self.publish(mqtt)
                    self.wake.wait(self.interval)
                    self.wake.clear()
            except Exception as exc:  # Broker/Netz nicht erreichbar: nach kurzer Pause neu verbinden
                if not self.failed:
                    print(f"MQTT-Broker nicht erreichbar: {exc}", flush=True)
                self.failed = True
            finally:
                mqtt.close()
            time.sleep(self.interval)


def _handle_signal(signum, frame) -> None:
    global _stop
    _stop = True


def capture(iface: str, writer: RingPcapWriter, monitor: AnomalyMonitor) -> None:
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    sock.bind((iface, 0))
    sock.settimeout(1.0)
    print(f"Mitschnitt auf {iface} gestartet, Ziel: {writer.directory}", flush=True)
    count = 0
    try:
        while not _stop:
            try:
                frame, _ = sock.recvfrom(SNAPLEN)
            except socket.timeout:
                frame = None
            now = time.time()
            if frame is not None and is_dhcp(frame):
                writer.write(frame, now)
                count += 1
                print(f"DHCP-Paket #{count} ({len(frame)} Bytes) gespeichert", flush=True)
                monitor.inspect(frame, now)
            monitor.tick(now)
    finally:
        sock.close()
        writer.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="DHCP-Mitschnitt in PCAP-Ringpuffer.")
    parser.add_argument("interface", help="Netzwerk-Interface, z. B. eth0")
    parser.add_argument("--dir", default="/var/log/dhcp", help="Zielverzeichnis (Standard: /var/log/dhcp)")
    parser.add_argument("--prefix", default="dhcp.pcap", help="Dateiname-Präfix (Standard: dhcp.pcap)")
    parser.add_argument("--size-mb", type=int, default=20, help="Max. Größe je Datei in MB (Standard: 20)")
    parser.add_argument("--files", type=int, default=5, help="Anzahl Dateien im Ring (Standard: 5)")
    parser.add_argument("--allowed-server", action="append", default=[], metavar="IP",
                        help="Erlaubte DHCP-Server-IP (mehrfach möglich); andere Absender lösen einen Vorfall aus")
    parser.add_argument("--incident-dir", help="Ablage für Vorfälle (Standard: <dir>/incidents)")
    parser.add_argument("--hold", type=int, default=120,
                        help="Sekunden, die nach einem Vorfall weiter mitgeschnitten und erneut gesichert wird (Standard: 120)")
    parser.add_argument("--cooldown", type=int, default=600,
                        help="Mindestabstand in Sekunden zwischen zwei gesicherten Vorfällen (Standard: 600)")
    parser.add_argument("--max-incidents", type=int, default=20,
                        help="Maximal aufbewahrte Vorfälle, ältere werden gelöscht (Standard: 20)")
    parser.add_argument("--no-offer-timeout", type=int, default=0,
                        help="Sekunden bis ein Discover ohne Offer als Vorfall gilt (Standard: 0 = aus)")
    parser.add_argument("--mqtt-host", help="MQTT-Broker (Mosquitto auf Home Assistant), z. B. 192.168.2.10 (aktiviert die Meldung an HA)")
    parser.add_argument("--mqtt-port", type=int, default=1883, help="MQTT-Port (Standard: 1883)")
    parser.add_argument("--mqtt-user", help="MQTT-Benutzer")
    parser.add_argument("--mqtt-password-file", default="/etc/netwatch/mqtt_password",
                        help="Datei mit dem MQTT-Passwort (Standard: /etc/netwatch/mqtt_password)")
    parser.add_argument("--alert-hours", type=float, default=24.0,
                        help="Stunden, die der Vorfalls-Sensor nach einem Vorfall 'an' bleibt (Standard: 24)")
    args = parser.parse_args()

    if not hasattr(socket, "AF_PACKET"):
        sys.exit("Fehler: AF_PACKET wird nur unter Linux unterstützt.")

    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    directory = Path(args.dir)
    directory.mkdir(parents=True, exist_ok=True)
    writer = RingPcapWriter(directory, args.prefix, args.size_mb * 1024 * 1024, args.files)
    monitor = AnomalyMonitor(
        writer,
        Path(args.incident_dir) if args.incident_dir else directory / "incidents",
        args.allowed_server,
        hold=args.hold,
        cooldown=args.cooldown,
        max_incidents=args.max_incidents,
        no_offer_timeout=args.no_offer_timeout,
    )
    if args.mqtt_host:
        password = None
        if args.mqtt_user:
            try:
                password = Path(args.mqtt_password_file).read_text(encoding="utf-8").strip()
            except OSError as exc:
                sys.exit(f"Fehler: Passwortdatei {args.mqtt_password_file} nicht lesbar: {exc}")
        publisher = HomeAssistantPublisher(args.mqtt_host, args.mqtt_port, args.mqtt_user, password,
                                           monitor.incident_dir, args.alert_hours)
        monitor.on_incident = publisher.kick
        publisher.start()
        print(f"Meldung per MQTT aktiv: {args.mqtt_host}:{args.mqtt_port}", flush=True)
    try:
        capture(args.interface, writer, monitor)
    except PermissionError:
        sys.exit("Fehler: Raw-Sockets benötigen root (sudo).")
    except OSError as exc:  # z. B. Interface verschwunden; systemd startet den Dienst neu
        sys.exit(f"Fehler beim Mitschnitt auf {args.interface}: {exc}")


if __name__ == "__main__":
    main()
