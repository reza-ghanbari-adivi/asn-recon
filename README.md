# ASN Recon

A Python CLI for documenting services on authorized networks and reviewing where related hostnames resolve. A DNS answer is evidence of a mapping, not permission to test the destination.

## Start with an offline example

From the repository root, run:

```bash
python3 src/review_external.py examples/demo_map.csv
```

Expect one outside-range pair. Enter **N** to leave everything unchanged, or **y** to write `examples/demo_map.review.csv` for manual review. The reviewer does not contact either address, change an allowlist, or start a scan. It refuses to overwrite an existing review file. For a video demo, use this fixture rather than a real report.

## Setup and tests

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
python src/asn_recon.py --help
```

The reviewer uses only the standard library. The scope and decision tests import the scanner and therefore need its Python dependencies, but not API keys or external scanner executables. The decision tests mock both scanner functions and use temporary allowlists.

## What the scanner does

`src/asn_recon.py` accepts an optional `--asn` (`-a`); otherwise it prompts for one. A live run requires `asnmap`, `naabu`, `nmap`, and `subfinder` on PATH and `PDCP_API_KEY` in the environment or the project-root `.env`. `CHAOS_API_KEY` is optional. Never commit real keys.

1. Looks up **IPv4** ASN prefixes. If `config/approved_cidrs.txt` is populated, it selects only discovered prefixes wholly covered by it. If empty or missing, it prompts for `AUTHORIZE` for the discovered set instead. `MAX_SCAN_IPS` limits the size of this initial scope (default 9999 addresses).
2. After port selection, discovers endpoints and identifies services. It uses PTR and certificate names to identify candidate domains and checks domain scope before subdomain enumeration (`config/approved_domains.txt`).
3. Resolves names and writes `reports/scan_report_<tag>.csv` and `reports/subdomain_ip_map_<tag>.csv`. `In_ASN_scope` compares each answer against the **selected IPv4 networks**, not all addresses owned by the organization. An IPv6 answer or an address from an unselected prefix can therefore read `no` without proving third-party ownership.
4. For the optional external phase, only discovered IPs outside those networks **and** in `config/approved_external_ips.txt` are candidates. With no match, there is no prompt and no external scan. With candidates, Enter or `n` skips it; only a trimmed, case-insensitive `y` continues. This prompt occurs **after** the initial scan and mapping. Obtain independent permission for every external target. External rows, if produced, go to `reports/external_scan_report_<tag>.csv`.

## Current limitations

- The CLI validates `--rate` but the scan function reads `NAABU_RATE` directly. Do not rely on the CLI override or assume an environment value has been validated by the scan function.
- A mixed IPv4/IPv6 external candidate list can fail while sorting for display, before the confirmation prompt.

## Before publishing

Keep `.env`, private `config/approved_*.txt`, `reports/`, `state/`, `.venv/`, and generated `*.review.csv` files out of Git. Review `git status --short`, `git ls-files`, and `git diff --cached` before pushing: ignore rules do not remove already tracked files. Use only synthetic data in examples and recordings.
