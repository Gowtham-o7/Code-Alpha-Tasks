# Network Intrusion Detection System (NIDS)

A network-based Intrusion Detection System built with **Suricata** (primary) and **Snort** (alternative), including custom detection rules, an automated response script, and a lightweight alert dashboard.

## 📁 Project Structure
```
nids-project/
├── README.md
├── suricata/
│   ├── suricata.yaml          # Key config snippet (interface, rule paths, logging)
│   └── rules/
│       └── custom.rules       # Custom detection rules
├── snort/
│   ├── snort.conf             # Key config snippet
│   └── rules/
│       └── local.rules        # Custom detection rules (Snort syntax)
├── scripts/
│   ├── monitor.sh             # Live tail of alerts
│   └── auto_response.py       # Reads alerts, blocks malicious IPs (iptables)
├── dashboard/
│   ├── dashboard.py           # Flask dashboard reading eve.json
│   ├── templates/index.html
│   └── requirements.txt
└── docs/
    └── REPORT_TEMPLATE.md     # Lab report template for submission
```

## 1. Setup

### Install Suricata (Ubuntu/Debian)
```bash
sudo apt update
sudo apt install -y suricata
sudo suricata-update          # pulls Emerging Threats ruleset
```

### Install Snort (alternative/comparison)
```bash
sudo apt install -y snort
```

Find your monitoring interface:
```bash
ip a
```

## 2. Configure Rules & Alerts

- Suricata's main config is `/etc/suricata/suricata.yaml`. Copy `suricata/suricata.yaml` snippet values over the relevant sections (HOME_NET, af-packet interface, rule-files).
- Place `suricata/rules/custom.rules` in `/etc/suricata/rules/` and reference it in `suricata.yaml` under `rule-files:`.
- For Snort, copy `snort/rules/local.rules` to `/etc/snort/rules/local.rules` and ensure `snort.conf` includes it.

Test the config:
```bash
sudo suricata -T -c /etc/suricata/suricata.yaml -v
```

## 3. Run / Monitor Traffic

```bash
sudo suricata -c /etc/suricata/suricata.yaml -i eth0
```

Alerts log to `/var/log/suricata/eve.json` (JSON) and `fast.log` (plain text).

Live-tail alerts:
```bash
chmod +x scripts/monitor.sh
./scripts/monitor.sh
```

## 4. Automated Response

`scripts/auto_response.py` tails `eve.json`, and when an alert matches a configured severity/signature, it blocks the source IP using `iptables` and logs the action.

```bash
sudo python3 scripts/auto_response.py --eve /var/log/suricata/eve.json
```

> ⚠️ Run only in a lab/test environment first. Auto-blocking production traffic can cause outages if rules are too broad.

## 5. Dashboard / Visualization

A simple Flask dashboard summarizes alert counts, top source IPs, and signature frequency.

```bash
cd dashboard
pip install -r requirements.txt
python3 dashboard.py --eve /var/log/suricata/eve.json
```
Then open `http://localhost:5000`.

For a production-grade option, point Filebeat at `eve.json` and feed it into the **ELK stack** (Elasticsearch + Logstash + Kibana) or use **EveBox** / **SELKS**, which are purpose-built for Suricata visualization.

## Testing Your IDS

Generate benign "attack-like" traffic to confirm detection (run only against your own lab host):
```bash
nmap -sS <your-test-host>          # triggers port scan rule
curl http://<your-test-host>/etc/passwd   # triggers path traversal rule (if web server present)
```
Check `fast.log` / dashboard for resulting alerts.

## Notes for the Report
See `docs/REPORT_TEMPLATE.md` for a write-up structure covering setup, rule design, detection results, response actions, and screenshots of the dashboard.
