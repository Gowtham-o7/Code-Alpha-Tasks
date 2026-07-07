# Network Intrusion Detection System — Lab Report

## 1. Objective
Set up a network-based IDS, configure detection rules, monitor traffic, implement response mechanisms, and visualize results.

## 2. Tools Used
- Suricata (primary IDS engine)
- Snort (alternative/comparison)
- iptables (response/blocking)
- Flask + Chart.js (dashboard)

## 3. Setup Steps
- [Describe installation, interface chosen, screenshots of `suricata -T -c ... -v` success]

## 4. Rule Configuration
- List custom rules created (see `custom.rules` / `local.rules`) and what each detects.

## 5. Monitoring & Detection Results
- [Insert screenshots of `fast.log` / `eve.json` alerts]
- [Describe test traffic used: nmap scan, curl traversal attempt, etc.]

## 6. Response Mechanism
- Describe `auto_response.py` behavior, severity threshold chosen, and example of an IP being blocked.
- Include `iptables -L` output before/after.

## 7. Dashboard / Visualization
- [Insert dashboard screenshots: total alerts, top signatures, top source IPs, severity breakdown]

## 8. Challenges & Learnings
- [Your notes]

## 9. Conclusion
- [Summary of what the IDS successfully detected and how response time/effectiveness was improved]
