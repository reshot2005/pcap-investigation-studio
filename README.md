    # PCAP Investigation Studio — Offline Network Security Tool

    [![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
    [![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
    [![Offline](https://img.shields.io/badge/mode-offline%20first-important.svg)](#)
    [![secintel](https://img.shields.io/badge/schema-secintel%20v1-purple.svg)](https://github.com/reshot2005/secintel-core)
    [![GitHub](https://img.shields.io/badge/github-reshot2005%2Fpcap-investigation-studio-black.svg)](https://github.com/reshot2005/pcap-investigation-studio)

    > **Filterable PCAP investigation studio with beaconing and DNS-tunneling heuristics for offline network forensics and SOC threat hunting.**

    **Category:** Network Security  
    **Collection phase tool:** 6/12  
    **Schema:** [secintel-core](https://github.com/reshot2005/secintel-core) v1  
    **Repository:** https://github.com/reshot2005/pcap-investigation-studio  
    **Author account:** [reshot2005](https://github.com/reshot2005)

    ## Why PCAP Investigation Studio ranks for security search

    PCAP Investigation Studio is an **offline-first**, research-grade **network security** utility designed for practitioners who need reproducible analysis without uploading sensitive artifacts to SaaS scanners. It emits structured findings through the shared **secintel** evidence taxonomy (OBSERVED / DERIVED / INFERRED / CORRELATED / VERIFIED) so results are auditable, exportable, and CI-friendly.

    ### Primary SEO keywords
    `pcap investigation, beacon detection, DNS tunneling, SOC hunting, network IR`

    ### Topics
    `network-security` `cybersecurity` `nmap` `pcap` `threat-hunting` `infosec` `security-tools` `python` `offline-security` `blue-team` `c2-detection` `incident-response`

    ## What problem does this solve?

    Investigate PCAPs with filters plus heuristics for beaconing and DNS tunneling indicators — designed for offline incident response.

    Combines browsing + heuristics with evidence taxonomy.

    ## Key features

    - Filterable packet browser model
- Beaconing heuristics
- DNS tunneling signals
- Investigation-oriented findings
- HTML/JSON reporting

    ## Ideal use cases

    - Hunt C2 beacon patterns
- Investigate suspicious DNS traffic
- Support offline IR packet review

    ## Who should use this

    - Security engineers & AppSec / NetSec specialists
    - SOC / DFIR / malware analysts (as applicable)
    - Bug bounty hunters and penetration testers
    - DevSecOps teams needing offline/air-gapped tooling
    - Students and researchers learning network security

    ## Quick start

    ```bash
    git clone https://github.com/reshot2005/pcap-investigation-studio.git
    cd pcap-investigation-studio
    python3.12 -m venv .venv
    source .venv/bin/activate  # Windows: .venv\Scripts\Activate.ps1
    pip install -e ../secintel-core  # or: pip install -e git+https://github.com/reshot2005/secintel-core.git#egg=secintel-core
    pip install -e ".[dev]"

    pcap-investigation-studio analyze sample_data --json
    pcap-investigation-studio analyze sample_data --html report.html
    pcap-investigation-studio version
    ```

    ### Exports for interoperability

    ```bash
    pcap-investigation-studio analyze sample_data \
      --json --html report.html --csv findings.csv --sarif results.sarif
    ```

    ## Evidence quality & reproducibility

    - Findings follow **secintel** classification rules (confidence only where schema allows).
    - Provenance includes tool version, config hash, and input integrity metadata.
    - Set `SECINTEL_SOURCE_DATE_EPOCH` for deterministic timestamps in CI.

    ```bash
    export SECINTEL_SOURCE_DATE_EPOCH=1704067200
    pcap-investigation-studio analyze sample_data --json
    ```

    ## Development

    ```bash
    ruff check src tests
    mypy src
    pytest
    ```

    ## Related tools in this collection

    Browse more offline security research tools by [reshot2005](https://github.com/reshot2005?tab=repositories): network security, web AppSec, DevSecOps, digital forensics, and static malware analysis — each in its own public repository with the same secintel reporting contract.

    ## License

    MIT — free for research, education, and commercial use with attribution preserved.

    ---

    ### Discoverability blurb (search engines & GitHub)

    **PCAP Investigation Studio (pcap-investigation-studio)** — Filterable PCAP investigation studio with beaconing and DNS-tunneling heuristics for offline network forensics and SOC threat hunting. Search terms: pcap investigation, beacon detection, DNS tunneling, SOC hunting, network IR. Open-source, MIT-licensed, Python 3.12, offline cybersecurity tool by reshot2005.
