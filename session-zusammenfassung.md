# Session-Zusammenfassung: DHCP-Netzwerkdiagnose (Stand 2026-11-07)

## Ausgangslage / Problem

Im Heimnetzwerk erhalten DHCP-Clients wiederholt unsinnige IP-Adressen.
Zwei mögliche Ursachen, die es zu unterscheiden gilt:

1. **Rogue DHCP-Server**: Ein zweites Gerät verteilt Adressen (Repeater, VM-Host,
   Windows-ICS, IoT-Gerät im AP-Modus). Symptom: IPs aus falschem Subnetz.
2. **Haupt-DHCP nicht erreichbar**: Clients fallen auf APIPA 169.254.x.x zurück.

Ziel: Daten kontinuierlich erfassen, damit beim nächsten Auftreten eine Analyse
möglich ist.

## Entscheidungen

- **Logger-Gerät**: Der Linux-Raspi (`Raspi46`, Benutzer `jr46`) – nicht der
  Home-Assistant-Raspi (HA OS ist eine Appliance, kein dauerhafter tcpdump möglich).
- Der HA-Raspi kann später optional als Alarmgeber dienen (Ping-Sensor + Automation).
- Der Logger-Raspi hat jetzt eine **feste statische IP außerhalb des DHCP-Bereichs**
  (per NetworkManager/nmcli gesetzt) → immun gegen DHCP-Störungen, während eines
  Vorfalls weiter per SSH erreichbar.
- **WLAN am Raspi deaktiviert** (`nmcli connection down "<WLAN-Name>"` +
  `connection.autoconnect no`), damit nur noch ein Interface/eine IP aktiv ist.
  Grund: eth0 + wlan0 hatten je eigene MAC und eigene IP → zwei Einträge im Router,
  uneindeutiges Routing.

## Netzwerk-Fakten

- Subnetz: **192.168.2.0/24** (NICHT Fritz!Box-Standard 192.168.178.x!)
- Gateway/Router: vermutlich 192.168.2.1 (auf dem Raspi prüfbar via `ip route`)
- Router ist eine Fritz!Box (Option „IPv4-Adresse dauerhaft zuweisen" = DHCP-Reservierung,
  gilt nur gegenüber der Fritz!Box, nicht gegen Rogue-Server)
- SSH-Zugang: `ssh jr46@<feste-ip>` (Hostname `Raspi46` löste unter Windows nicht auf,
  `.local`/IP verwenden)
- Raspberry Pi OS mit **NetworkManager** (Bookworm oder neuer); WLAN-Interface `wlan0`,
  LAN `eth0`

## Erfassungskonzept (umgesetzt)

Alle Dateien liegen in `c:\GitRepos\Raspy46\netwatch\` (nur Python-Standardbibliothek):

| Datei | Zweck |
|---|---|
| `netwatch.py` | DHCP-Mitschnitt, Anomalieerkennung, MQTT-Meldung (läuft als Dienst auf dem Raspi) |
| `setup_netwatch.py` | Einrichtung auf dem Raspi (idempotent, `sudo`), schreibt Dienst, Cron, Logrotate |
| `deploy_netwatch.py` | Windows-Seite: kopiert beide Skripte per `scp` und startet das Setup per `ssh -t` |

1. **DHCP-Mitschnitt** (`netwatch.py`, ersetzt tcpdump): `AF_PACKET`-Raw-Socket,
   filtert IPv4/UDP 67/68 (auch VLAN), schreibt PCAP-Ringpuffer
   `/var/log/dhcp/dhcp.pcap0..4` (5 × 20 MB, Wireshark-kompatibel), jedes Paket wird
   sofort geschrieben. Nach Neustart wird hinter der zuletzt beschriebenen Datei
   weitergemacht. Dienst `dhcp-capture` (systemd, `Restart=always`, `enable` = Autostart).
2. **Anomalieerkennung** (`AnomalyMonitor`): Auslöser sind
   - `rogue-server`: DHCP-Antwort (Offer/ACK/NAK) von nicht erlaubter Absender-IP
     (erlaubt = Gateway aus der Default-Route, oder `--dhcp-server`)
   - `rogue-server-selected`: Client-Request (Broadcast) nennt per Option 54 einen nicht
     erlaubten Server; erkennt Rogue-Server auch dann, wenn deren Unicast-Antwort den
     Raspi nie erreicht
   - `multiple-servers`: mehrere Absender-IPs auf dieselbe Transaktion (xid)
   - `no-offer`: Discover ohne Offer (standardmäßig aus, `--no-offer-timeout`)
3. **Vorfall sichern**: Ringpuffer wird nach `/var/log/dhcp/incidents/<Zeit>_<Grund>/at-trigger/`
   kopiert, nach 120 s (`--hold`) erneut nach `after-hold/`. Dazu `events.txt`
   (Server-IP/-MAC, Client-MAC, xid) und `incidents/incidents.log`. Sperrzeit 600 s
   (`--cooldown`), max. 20 Vorfälle (`--max-incidents`), ältere werden gelöscht.
4. **Minütlicher Zustands-Snapshot** (`/usr/local/sbin/net-snapshot.sh`, Root-Cron):
   `ip addr/route/neigh`, DHCP4-Lease-Info via nmcli, Gateway-Ping (GW OK/FAIL)
   → `/var/log/netwatch/state.log`. Logrotate wöchentlich, 8 Rotationen.
5. **Home Assistant per MQTT** (siehe unten).

Grenze: Der Raspi sieht nur Broadcast-Verkehr. Unicast-Offers an andere Clients sieht er
nicht, `no-offer` ist deshalb standardmäßig aus.

## Home-Assistant-Anbindung (MQTT, Auto-Discovery)

- **HA**: `192.168.2.18` (feste IP, außerhalb des DHCP-Bereichs, in HA unter
  Einstellungen → System → Netzwerk gesetzt). Mosquitto-Add-on läuft.
- **Raspi**: `192.168.2.19`, Benutzer `jr46`.
- `netwatch.py` enthält einen eigenen minimalen MQTT-3.1.1-Client (`MiniMqtt`, nur
  CONNECT/PUBLISH QoS 0, retained). Zustand wird jede Minute und sofort nach neuem
  Vorfall gesendet (eigener Thread, blockiert den Mitschnitt nie), berechnet aus dem
  Vorfallsordner auf der Platte.
- Last Will auf `netwatch/<hostname>/availability` (`offline`): Fällt der Raspi aus,
  werden die Entitäten `unavailable`.
- Entitäten (Gerät „Netwatch“): `binary_sensor.netwatch_incident` (an, wenn letzter
  Vorfall < 24 h; Attribute `reason`, `detail`, `incident_folder`, `incident_time`,
  `host`, `path`), `sensor.netwatch_incident_count`, `sensor.netwatch_last_incident`.
- Passwort liegt in `/etc/netwatch/mqtt_password` (Modus 600), nicht in der
  Kommandozeile/Unit. Abfrage einmalig beim Setup (`--reset-mqtt-password` zum Ändern).
- HA-Dateien im Repo `c:\GitRepos\hajr`: `dashboards/netwatch_dashboard.yaml`,
  `automations/netwatch_notifications.yaml` (Push bei Vorfall und bei 5 min Ausfall),
  `docs/netwatch.md`; Übertragung mit `syncPvCharge.py` (Samba).
- Nach HA-Neustart/Stromausfall: Retained-Nachrichten sorgen für sofortige Anzeige,
  der Raspi verbindet sich spätestens nach 1–2 Minuten neu. Nach Raspi-Stromausfall
  startet der Dienst automatisch, `offline` kommt nach ca. 3 min (Keepalive 120 s).

## Inbetriebnahme

1. MQTT-Benutzer `netwatch` in HA anlegen (Einstellungen → Personen → Benutzer, kein
   Admin, nur lokales Netz).
2. Vom Windows-PC aus:
   ```powershell
   cd C:\GitRepos\Raspy46\netwatch
   python deploy_netwatch.py 192.168.2.19 --run --mqtt-host 192.168.2.18 --mqtt-user netwatch
   ```
   Optionen: `--dhcp-server <IP>`, `--iface eth0`, `--reset-mqtt-password`.
3. HA-Dateien synchronisieren (PowerShell, Samba-Modus):
   `python syncPvCharge.py --mode samba --share "\\192.168.2.18\config" [--dry-run]`
   (in Git-Bash Backslashes verdoppeln). Danach Automationen neu laden, Dashboard in
   `configuration.yaml` eintragen, HA neu starten.
4. Verifikation: `systemctl status dhcp-capture`, `journalctl -u dhcp-capture -n 20`
   (muss `Meldung per MQTT aktiv: 192.168.2.18:1883` enthalten),
   `ls -lh /var/log/dhcp/`, in HA Gerät „Netwatch“ unter MQTT.

## Gelernte Fehlerbilder

- **`NameError: subprocess`** beim Setup: Import war beim Umbau verloren gegangen
  (behoben); alle Skripte mit `python -m pyflakes` prüfen.
- **MQTT „Anmeldung abgelehnt (Code 5)“**: Mosquitto lehnt Benutzer/Passwort ab. Prüfen:
  Benutzername (nicht Anzeigename) exakt `netwatch`, Passwort neu setzen, Mosquitto-Log
  lesen, notfalls `logins` direkt in der Add-on-Konfiguration anlegen.
- **Samba „path not found“** nach HA-IP-Änderung: Samba-Add-on musste neu gestartet
  werden (Port 445 vorher geschlossen).
- **Dashboard-Konfigurationsfehler** „Url path needs to contain a hyphen“: Schlüssel unter
  `lovelace: dashboards:` braucht einen Bindestrich (`netwatch-dashboard`), der Dateiname
  darf Unterstriche haben.
- **„Auf ein Thema lauschen“** (HA → MQTT → Konfigurieren) mit `netwatch/#` zeigt, ob
  Daten vom Raspi ankommen; mit `homeassistant/#` die Discovery-Konfigurationen.
- Birth/Will in den HA-MQTT-Optionen betreffen nur HA selbst, am Raspi nichts ändern.
- `sudo`/`ssh -t` ist nötig, damit Passwortabfragen (sudo, MQTT) funktionieren.
- **InfluxDB-Sensoren „Nicht verfügbar“** nach HA-IP-Wechsel (`.125` → `.18`): Die REST-
  Sensoren im Repo `hajr` hatten die alte IP fest eingetragen (angepasst). Nach einer
  IP-Änderung im Repo nach der alten Adresse suchen, synchronisieren, REST neu laden.
- **iPhone bekam 192.168.68.53/22 (Router 192.168.68.1)**, der Raspi bemerkte nichts:
  Ursache ist der **TP-Link Deco im Router-Modus** (eigener DHCP, eigenes Subnetz hinter
  der Fritz!Box, doppelte NAT). Dessen DHCP läuft nur im WLAN und erreicht `eth0` des
  Raspi nicht. Lösung: Deco auf **Access-Point-Modus** stellen, die Fritz!Box bleibt
  einziger Router/DHCP. Danach sieht der Raspi die DHCP-Anfragen aller WLAN-Geräte.
  Ein Mesh braucht keinen eigenen DHCP-Server, der ist nur beim Deco als einzigem Router
  sinnvoll.

## Offene Schritte

1. **Deco auf Access-Point-Modus umstellen** (Deco-App → Mehr → Erweitert → Betriebsmodus),
   danach prüfen, dass WLAN-Geräte `192.168.2.x` bekommen.
2. Neue Version (`rogue-server-selected`) auf dem Raspi einspielen:
   `python deploy_netwatch.py 192.168.2.19 --run --mqtt-host 192.168.2.18 --mqtt-user netwatch`
3. Erkennung mit künstlichem Vorfall testen (zweite Instanz mit falschem
   `--allowed-server`, dann `ipconfig /release` + `/renew` am PC; Dienst vorher
   stoppen, wenn auch die Dashboard-Anzeige getestet werden soll).
4. Optional: Fritz!Box-Ereignislog aktivieren (System → Ereignisse, alle Kategorien).

## Analyse beim nächsten Vorfall

1. Home Assistant meldet den Vorfall (Dashboard „Netwatch“, Push aufs Handy). Dort stehen
   Grund, Details und der Ordnername. Gesicherte Dateien holen:
   `scp -r jr46@192.168.2.19:/var/log/dhcp/incidents/<ordner> C:\Logs\`
   (ohne HA-Meldung: `scp jr46@192.168.2.19:/var/log/dhcp/dhcp.pcap* C:\Logs\`)
2. In Wireshark öffnen, Filter: `bootp`
   - **Mehrere DHCP Offer** von verschiedenen MACs auf ein Discover → Rogue-Server
     bestätigt. MAC notieren, OUI-Lookup (Hersteller), Gerät physisch suchen.
   - **Kein Offer** → Haupt-DHCP/Router war nicht erreichbar.
3. Schnellcheck auf dem Raspi:
   `tcpdump -r /var/log/dhcp/dhcp.pcap0 -n 'udp port 67'`
   Jeder Offer-Absender ist ein DHCP-Server – erlaubt ist genau einer (192.168.2.1).
4. `/var/log/netwatch/state.log` zum Vorfallszeitpunkt prüfen: Gateway-Ping
   (GW OK/FAIL), eigene IP, ARP-Tabelle.
5. Auf betroffenem Windows-Client: `ipconfig /all` → stimmt die DHCP-Server-Adresse
   mit 192.168.2.1 überein? IP 169.254.x.x → gar keine Antwort erhalten.

## Nützliche Befehle (Raspi)

```
ssh jr46@<feste-ip>                 # verbinden
exit                                # SSH-Sitzung beenden (Notaus: Enter ~ .)
nmcli device status                 # Interface-Übersicht
ip addr / ip route / ip neigh       # Netzwerkzustand
systemctl status dhcp-capture       # Mitschnitt-Dienst
journalctl -u dhcp-capture          # Dienst-Log
```
