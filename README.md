# Traffic-Gen

Proxmox LXC met een web-GUI die realistisch gebruikersverkeer genereert (Netflix, YouTube, Facebook, Teams, Office 365, Zoom, Salesforce, updates, SD-WAN probes, ...) vanaf **meerdere bron-IP's en VLANs**, om een FortiGate (SD-WAN, Application Control, Web Filter) te monitoren.

## Uitrollen (op de Proxmox host, als root)

```bash
git clone http://10.10.100.3:8010/sander/Traffic-Gen.git
cd Traffic-Gen && bash install.sh
```

De wizard maakt een Debian 12 LXC met **twee NIC's**:

| NIC  | Doel | Instelling |
|------|------|------------|
| eth0 | Management (web-GUI) | bridge, VLAN, IP/gateway/DNS via de wizard |
| eth1 | Testverkeer | bridge (optioneel tag); **geen IP**, de rest regel je in de GUI |

Aan het eind krijg je de GUI-URL (`https://<mgmt-ip>:8443`, zelfondertekend certificaat) en het admin-wachtwoord (zelf kiezen of laten genereren).

## In de GUI

- **Dashboard**: looptijd (5 min tot 2 uur, tot stop, of eigen waarde), intensiteit, sessies per IP, start/stop, live doorvoer, requests, geblokkeerd/fouten, per applicatie en per bron-IP, laatste requests.
- **Verkeersmix**: gewicht per groep (Microsoft 365, Samenwerken, Streaming, Social, SaaS, Web, Updates, Downloads, SD-WAN probes, Webfilter-test, EICAR) en per app aan/uit.
- **Netwerk**: per bronnetwerk de interface (eth1), optioneel VLAN, eerste IP, prefix, aantal IP's, gateway en DNS. *Toepassen* maakt de VLAN-subinterface, voegt de IP's toe en zet source-based routing op, zodat testverkeer via de eigen gateway (de FortiGate) gaat en management gescheiden blijft. *Verbinding testen* pingt de gateway en test DNS vanaf het bronnetwerk.
- **Instellingen**: wachtwoord wijzigen en TLS-certificaten van doelsites controleren (standaard uit, voor SSL deep inspection).

## Proxmox-notities

- Gebruik je VLANs in de GUI, laat dan de eth1-tag in de wizard leeg en zorg dat de bridge VLAN-aware is en de gewenste VLANs doorlaat. Voor één vlak netwerk kun je een tag op eth1 zetten.
- Netwerkwijzigingen worden toegepast bij *Toepassen* en bij het opstarten van de service. Tijdens een lopende test is toepassen geblokkeerd.

## Logs en CLI

- `/var/log/trafficgen/requests.log`: JSON per request, om met FortiGate-logs te vergelijken.
- `trafficgen run -d 5` voert een test in de voorgrond uit met de ingestelde netwerken; `trafficgen apps` toont de profielen; `trafficgen passwd` reset het GUI-wachtwoord.
- Eigen app-lijst: kopieer `/opt/trafficgen/profiles.yaml` naar `/etc/trafficgen/profiles.yaml`.
- Service: `systemctl status trafficgen-web`, logs met `journalctl -u trafficgen-web`.

## Let op

- Zorg dat de FortiGate-policy de bronnetwerken doorlaat naar internet.
- Webfilter-testsites en EICAR staan standaard op gewicht 0.
- Gebruik alleen op netwerken waar je dit mag doen.
