# Traffic-Gen

Proxmox LXC die realistisch gebruikersverkeer genereert (Netflix, YouTube, Facebook, Teams, Office 365, Zoom, Salesforce, updates, SD-WAN probes, ...) vanaf **meerdere bron-IP's**, om een FortiGate (SD-WAN, Application Control, Web Filter) te monitoren.

## Uitrollen (op de Proxmox host, als root)

```bash
git clone http://10.10.100.3:8010/sander/Traffic-Gen.git
cd Traffic-Gen && bash install.sh
```

De wizard vraagt CTID, hostname, bridge/VLAN, IP + gateway + DNS, aantal extra bron-IP's, standaard looptijd, intensiteit, storage en resources. Daarna maakt hij een Debian 12 LXC en installeert de generator.

## Gebruik (in de LXC: `pct enter <CTID>`)

```bash
trafficgen start                 # op de achtergrond, standaard looptijd uit config
trafficgen start -d 30           # 30 minuten (0 = tot 'stop')
trafficgen start -g streaming,collab -i high -t 4
trafficgen status                # toestand + laatste logregels
trafficgen stop
trafficgen run -d 5              # voorgrond, toont samenvatting per app
trafficgen apps                  # groepen, gewichten en apps
trafficgen wizard                # configuratie interactief aanpassen
```

## Hoe het werkt

- Extra bron-IP's (`source.first` + `source.count`) worden als alias op `eth0` gezet tijdens een run en daarna weer verwijderd (`keep_ips: true` om te houden). Elk IP draait `threads_per_ip` "gebruikers" met eigen User-Agent; DNS, TCP/TLS en UDP gebruiken dat bron-IP.
- Verkeer gebruikt echte hostnamen over TLS (SNI), waarop Application Control herkent. Teams en Meet sturen ook STUN/UDP-media (3478 / 19302).
- Groepen en gewichten staan in `/etc/trafficgen/config.yaml`; apps in `/opt/trafficgen/profiles.yaml` (kopieer naar `/etc/trafficgen/profiles.yaml` om eigen lijst te gebruiken).
- `webfilter` (gokken, proxy, p2p, games) en `security` (EICAR) staan standaard uit: zet het gewicht > 0. Geblokkeerde requests (FortiGate blokpagina/403) tellen als `blocked`.
- Logs: `/var/log/trafficgen/requests.log` (JSON per request, handig om met FortiGate-logs te vergelijken) en `last-run.json`.

## Let op

- Zet de FortiGate-policy zo dat alle bron-IP's (of het hele subnet) door de gewenste policy lopen; bij SSL deep inspection staat `tls_verify: false` correct.
- Gebruik alleen op netwerken waar je dit mag doen. De lijst met webfilter-testsites is aanpasbaar.
