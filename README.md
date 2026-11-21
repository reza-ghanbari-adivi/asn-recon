# ASN Recon

ASN Recon inventories services on the announced IPv4 ranges of **one ASN** and maps hostnames observed during that inventory. Enter the ASN, review its prefixes, and confirm once for the current run. **No scope files are required.**

After the initial scan and hostname enumeration finish, the CLI saves its primary reports. If any mapped public IP has a confirmed different routing ASN, it then offers to save those findings for review. **The final prompt saves a report; it never scans the other IP or ASN.**

## Try the offline example first

With Git and Python 3 installed:

    git clone https://github.com/reza-ghanbari-adivi/asn-recon.git
    cd asn-recon
    python3 src/review_external.py examples/demo_map.csv

A private repository requires GitHub access. If you already cloned it, run the last command from the project directory.

This example reads a synthetic CSV and reports one outside-range pair. Press Enter to leave everything unchanged. No API key, network lookup, or scanner is needed. The offline reviewer checks range flags in an existing file; it does not verify routing origin.

## Install the live CLI

From the repository root in Bash:

    python3 -m venv .venv
    source .venv/bin/activate
    python -m pip install -r requirements.txt

Install these separate executables using their upstream instructions: [asnmap](https://github.com/projectdiscovery/asnmap), [naabu](https://github.com/projectdiscovery/naabu), [Nmap](https://nmap.org/download.html), and [subfinder](https://github.com/projectdiscovery/subfinder). Pip does not install them. Check that your shell can find all four:

    for tool in asnmap naabu nmap subfinder; do
        command -v "$tool" || printf 'Missing from PATH: %s\n' "$tool"
    done

ASN lookup requires `PDCP_API_KEY`. Run these lines **one at a time** and type your key only at the hidden prompt:

    read -rsp 'ProjectDiscovery API key: ' PDCP_API_KEY
    printf '\n'
    export PDCP_API_KEY

The CLI also supports a private project-root `.env`. `CHAOS_API_KEY` is optional for the Chaos discovery provider. Never commit credentials.

## Run one inventory

    source .venv/bin/activate
    python src/asn_recon.py

Enter the ASN number, with or without `AS`. Alternatively, supply it with `--asn` to skip the ASN question. Both forms still display the initial scope and ask for confirmation.

1. **Review the initial scope.** The CLI lists the announced IPv4 prefixes and address count. Answer `y` only if authorized to inventory **every listed prefix**. Enter or `n` cancels before port scanning. If your permission covers only a subset, do not use this whole-ASN mode. The default initial size limit is 9,999 addresses.
2. **Wait for inventory and enumeration.** Naabu checks its top 1,000 ports profile; Nmap identifies services on discovered endpoints. The CLI extracts candidate domains from observed names, enumerates names through passive sources, and resolves DNS records. It does not port-scan those DNS answers.
3. **Read the primary reports.** The service inventory and hostname/IP map are written before the final review. An outside-range flag alone is not evidence of another ASN.
4. **Decide at the end.** For mapped public IPs outside the initial ranges, the CLI queries routing origin using Team Cymru DNS. This discloses candidate IPs to the resolver/service. Same-ASN, unknown, ambiguous, and failed results do not trigger a prompt. If confirmed different-origin mappings remain, the CLI shows them together and asks **once** whether to save a separate review CSV. Enter or `n` skips; `y` saves. Neither answer starts another scan.

## Reports

| File under `reports/` | Contents |
| --- | --- |
| `scan_report_<tag>.csv` | Services and observed names from the initial ASN inventory |
| `subdomain_ip_map_<tag>.csv` | Hostname/IP pairs, DNS record types, sources, and initial-range membership |
| `external_origin_review_<tag>.csv` | Hostname, IP, and different origin ASN; written only if you answer `y` at the end |

The tag includes the ASN and a UTC timestamp. The initial inventory is IPv4-only; DNS mappings can include IPv6. Routing origin is not proof of ownership. Results are observations, not a complete list of every service or subdomain.

## Troubleshooting and testing

- **No IPv4 prefixes:** Check the ASN, API key, connectivity, and whether the ASN announces IPv4 space.
- **Size limit reached:** The inventory stops before scanning. Check the displayed scope against your authorization rather than assuming a larger run is appropriate.
- **No final question:** Expected if no confirmed different-origin mappings were found. The primary reports are still available after a completed inventory.
- **Rate setting:** The scan function reads `NAABU_RATE` directly. Do not rely on `--rate` to override it.
- **Privacy:** Keep `.env`, `reports/`, and intermediate files under `state/` private. Use synthetic fixtures for demos.

Run the offline tests from the project root:

    .venv/bin/python -m unittest discover -s tests -v
