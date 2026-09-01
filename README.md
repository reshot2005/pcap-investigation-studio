# PCAP Investigation Studio

Filterable PCAP packet browser with beaconing and DNS tunnel heuristics. Embeds an interactive HTML table in secintel reports.

```bash
pcap-investigation-studio analyze capture.pcap --html report.html
pcap-investigation-studio analyze capture.pcap --filter "proto=TCP port=443" --json
```
