# ASN Recon

Enter an Autonomous System Number (ASN) to inventory services on networks you are authorized to assess. The CLI looks up IPv4 prefixes, checks the scan scope, and writes service and hostname-to-IP reports under `reports/`.

## Install

    git clone https://github.com/reza-ghanbari-adivi/asn-recon.git
    cd asn-recon
    python3 -m venv .venv
    source .venv/bin/activate
    python -m pip install -r requirements.txt

For live inventory, install `asnmap`, `naabu`, `nmap`, and `subfinder` on your `PATH`. These executables are not installed by pip.

## Start with an ASN

ASN lookup requires a ProjectDiscovery API key. In Bash, run these commands one at a time. Type the key only at the hidden prompt, then press Enter:

    read -rsp 'ProjectDiscovery API key: ' PDCP_API_KEY
    printf '\n'
    export PDCP_API_KEY
    python src/asn_recon.py

Enter the ASN at the prompt. For help without starting a scan, run `python src/asn_recon.py --help`.

## Scan scope

- **Initial inventory:** Put approved CIDRs in `config/approved_cidrs.txt` to restrict the scan to discovered prefixes wholly covered by those ranges. If the file is absent or empty, the CLI asks you to authorize the listed prefixes. Stop unless you have permission for every selected range.
- **DNS mapping:** An outside-range DNS answer is recorded for review. It does not grant permission to scan that address.
- **External inventory:** An address must match `config/approved_external_ips.txt` and receive separate confirmation. Answer **n** to skip this phase. This does not undo the initial inventory.

## Try it offline

From the activated virtual environment, review the synthetic report:

    python src/review_external.py examples/demo_map.csv

Answer **n** to leave everything unchanged. Answer **y** to save a review CSV. Neither choice starts a scan or changes an allowlist.

Run the offline tests with:

    python -m unittest discover -s tests -v

## Limitations

ASN lookup selects IPv4 prefixes only. A mixed IPv4/IPv6 external candidate list may fail before confirmation. The scanner reads `NAABU_RATE` directly; do not rely on `--rate` to override it.

Keep credentials, real reports, and private allowlists out of version control.
