#!/usr/bin/env python3
"""
Authorized ASN reconnaissance.

Workflow:
1. ASN -> IPv4 CIDRs
2. Explicit ASN CIDR authorization
3. Naabu port discovery
4. Nmap service and TLS certificate detection
5. PTR and candidate apex discovery
6. Explicit domain authorization
7. Passive Subfinder enumeration
8. DNS resolution and ASN scope mapping
9. Optional external infrastructure scanning

External targets require a separate explicit IP/CIDR allowlist.
A hostname resolving to an IP does not grant authorization.
"""

import argparse
import csv
import ipaddress
import os
import re
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET

from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

import dns.exception
import dns.resolver
import dns.reversename
import tldextract
from dotenv import load_dotenv


ROOT = Path(__file__).resolve().parent.parent
CONFIG = ROOT / "config"
STATE = ROOT / "state"
REPORTS = ROOT / "reports"


EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=())

SCAN_COLUMNS = [
    "IP", "Port", "Protocol", "Service", "Product", "Version", "Extra",
    "Domain", "PTR_names_for_IP",
    "TLS_certificate_names_on_this_port",
]

MAP_COLUMNS = [
    "Hostname", "IP", "Record_type", "In_ASN_scope",
    "Source",
]

EXTERNAL_COLUMNS = [
    "IP", "Port", "Protocol", "Service", "Product",
    "Version", "Extra", "Scope",
]


def fail(message):
    raise RuntimeError(message)


def run_command(args, *, timeout=600, output=False, env=None):
    """Run a program without shell interpolation."""
    try:
        result = subprocess.run(
            [str(x) for x in args],
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
            env=env or os.environ.copy(),
        )
    except FileNotFoundError:
        fail(f"Required executable not found: {args[0]}")
    except subprocess.TimeoutExpired:
        fail(f"{args[0]} timed out after {timeout} seconds")

    if result.returncode != 0:
        fail(
            f"{args[0]} failed with exit code {result.returncode}:\n"
            f"{result.stderr.strip()}"
        )

    return result.stdout if output else ""


def normalize_asn(value):
    value = value.strip().upper()

    if not value.startswith("AS"):
        value = "AS" + value

    if not re.fullmatch(r"AS[0-9]+", value):
        fail(f"Invalid ASN: {value}")

    return value


def read_lines(path):
    if not path.exists():
        return []

    result = []

    for line in path.read_text(encoding="utf-8").splitlines():
        value = line.split("#", 1)[0].strip()
        if value:
            result.append(value)

    return result


def inside(ip, networks):
    address = ipaddress.ip_address(ip)
    return any(address.version == n.version and address in n for n in networks)


def load_networks(path):
    networks = []

    for line in read_lines(path):
        try:
            networks.append(ipaddress.ip_network(line, strict=False))
        except ValueError:
            fail(f"Invalid network in {path}: {line}")

    return networks


def approve_asn_networks(discovered):
    path = CONFIG / "approved_cidrs.txt"
    approved = load_networks(path)

    if not approved:
        print("\n[!] No approved CIDRs configured.")
        print("[!] The following ASN networks were discovered:")

        for network in discovered:
            print(f"    {network}")

        answer = input(
            "\nType AUTHORIZE only if you are authorized to scan "
            "these networks: "
        ).strip()

        if answer != "AUTHORIZE":
            fail("ASN scan authorization was not provided.")

        return discovered

    selected = [
        network for network in discovered
        if any(
            network.version == allowed.version
            and network.subnet_of(allowed)
            for allowed in approved
        )
    ]

    if not selected:
        fail("No discovered ASN networks match approved_cidrs.txt.")

    print(f"[+] Authorized ASN networks: {len(selected)}")
    return selected


def lookup_asn(asn):
    print(f"\n[+] Looking up {asn}...")

    api_key = os.getenv("PDCP_API_KEY", "").strip()

    if not api_key:
        fail("PDCP_API_KEY is missing from your .env file.")

    env = os.environ.copy()
    env["PDCP_API_KEY"] = api_key

    output = run_command(
        ["asnmap", "-a", asn, "-silent"],
        timeout=120,
        output=True,
        env=env,
    )

    networks = set()

    for line in output.splitlines():
        try:
            network = ipaddress.ip_network(line.strip(), strict=False)
            if network.version == 4:
                networks.add(network)
        except ValueError:
            continue

    if not networks:
        fail("asnmap returned no IPv4 CIDRs.")

    result = sorted(
        networks,
        key=lambda n: (int(n.network_address), n.prefixlen),
    )

    for network in result:
        print(f"    {network}")

    return result


def check_scope_size(networks):
    maximum = int(os.getenv("MAX_SCAN_IPS", "9999"))
    total = sum(network.num_addresses for network in networks)

    if total > maximum:
        fail(
            f"Scope contains {total} addresses, exceeding "
            f"MAX_SCAN_IPS={maximum}. Review your authorized scope "
            "and adjust the limit deliberately if appropriate."
        )


def choose_ports():
    print("\nPort selection:")
    print("  1. Top 100")
    print("  2. Top 1000")
    print("  3. Common web ports")
    print("  4. All TCP ports")
    print("  5. Custom ports")

    choice = input("Choose [1-5, default 2]: ").strip() or "2"

    if choice == "1":
        return ["-top-ports", "100"]

    if choice == "2":
        return ["-top-ports", "1000"]

    if choice == "3":
        return ["-p", "80,443,8080,8443,3000,8000,8888"]

    if choice == "4":
        return ["-p", "1-65535"]

    if choice == "5":
        ports = input("Ports, e.g. 22,80,443,8000-8010: ").strip()

        if not re.fullmatch(r"\d+(?:-\d+)?(?:,\d+(?:-\d+)?)*", ports):
            fail("Invalid port format.")

        for item in ports.split(","):
            bounds = [int(x) for x in item.split("-")]

            if any(x < 1 or x > 65535 for x in bounds):
                fail("Port number out of range.")

            if len(bounds) == 2 and bounds[0] > bounds[1]:
                fail("Invalid port range.")

        return ["-p", ports]

    fail("Invalid port selection.")


def naabu_scan(networks, port_options, tag, targets=None):
    """Scan either approved ASN CIDRs or a supplied approved IP list."""
    print("\n[+] Running Naabu...")

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".txt", delete=False
    ) as handle:
        target_file = Path(handle.name)

        if targets is not None:
            handle.write("\n".join(sorted(targets)) + "\n")
        else:
            handle.write("\n".join(map(str, networks)) + "\n")

    output_file = STATE / f"naabu_{tag}.txt"

    try:
        rate = os.getenv("NAABU_RATE", "1000")

        run_command(
            [
                "naabu",
                "-list", target_file,
                *port_options,
                "-rate", rate,
                "-silent",
                "-o", output_file,
            ],
            timeout=7200,
        )
    finally:
        target_file.unlink(missing_ok=True)

    endpoints = set()

    if not output_file.exists():
        return endpoints

    for line in output_file.read_text(encoding="utf-8").splitlines():
        try:
            ip_text, port_text = line.strip().rsplit(":", 1)
            ip = ipaddress.ip_address(ip_text)
            port = int(port_text)

            if not 1 <= port <= 65535:
                continue

            if targets is not None:
                if str(ip) not in targets:
                    continue
            elif not inside(ip, networks):
                continue

            endpoints.add((str(ip), port))

        except ValueError:
            continue

    print(f"[+] Naabu found {len(endpoints)} endpoint(s).")
    return endpoints


def certificate_names(port_node):
    names = set()

    for script in port_node.findall("./script"):
        if script.get("id") != "ssl-cert":
            continue

        text = script.get("output", "")

        for value in re.findall(r"\bDNS:([*]?[A-Za-z0-9.-]+)", text):
            name = clean_name(value)

            if name:
                names.add(value.lower().rstrip("."))

        for element in script.iter("elem"):
            if element.get("key") == "commonName":
                name = clean_name(element.text or "")

                if name:
                    names.add(name)

    return names


def clean_name(value):
    name = str(value or "").strip().lower().rstrip(".")

    if name.startswith("*."):
        name = name[2:]

    if len(name) > 253:
        return ""

    labels = name.split(".")

    if len(labels) < 2:
        return ""

    if not all(
        re.fullmatch(
            r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?",
            label,
        )
        for label in labels
    ):
        return ""

    return name


def apex_of(value):
    name = clean_name(value)

    if not name:
        return ""

    result = EXTRACTOR(name)

    if not result.domain or not result.suffix:
        return ""

    return f"{result.domain}.{result.suffix}"


def nmap_scan(endpoints, networks, tag, scope_label="ASN"):
    if not endpoints:
        return []

    print(f"\n[+] Nmap service detection: {scope_label}")

    ips = sorted(
        {ip for ip, _ in endpoints},
        key=ipaddress.ip_address,
    )

    ports = sorted({port for _, port in endpoints})

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".txt", delete=False
    ) as handle:
        target_file = Path(handle.name)
        handle.write("\n".join(ips) + "\n")

    xml_file = STATE / f"nmap_{scope_label}_{tag}.xml"

    try:
        run_command(
            [
                "nmap",
                "-iL", target_file,
                "-p", ",".join(map(str, ports)),
                "-Pn", "-n", "-sV", "--version-light",
                "--script", "ssl-cert",
                "--open", "-T3",
                "-oX", xml_file,
            ],
            timeout=7200,
        )
    finally:
        target_file.unlink(missing_ok=True)

    if not xml_file.exists():
        fail("Nmap did not create its XML report.")

    root = ET.parse(xml_file).getroot()
    rows = []

    for host in root.findall("./host"):
        address = host.find("./address[@addrtype='ipv4']")

        if address is None:
            continue

        ip = address.get("addr", "")

        if networks is not None and not inside(ip, networks):
            continue

        for node in host.findall("./ports/port"):
            state = node.find("./state")

            if state is None or state.get("state") != "open":
                continue

            port = int(node.get("portid", "0"))

            if (ip, port) not in endpoints:
                continue

            service = node.find("./service")
            attributes = service.attrib if service is not None else {}

            rows.append({
                "IP": ip,
                "Port": port,
                "Protocol": node.get("protocol", "tcp"),
                "Service": attributes.get("name", ""),
                "Product": attributes.get("product", ""),
                "Version": attributes.get("version", ""),
                "Extra": attributes.get("extrainfo", ""),
                "Domain": "",
                "PTR_names_for_IP": "",
                "TLS_certificate_names_on_this_port":
                    "; ".join(sorted(certificate_names(node))),
                "Scope": scope_label,
            })

    print(f"[+] Nmap returned {len(rows)} service row(s).")
    return rows


def dns_query(name, record_type):
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 3
    resolver.timeout = 2

    try:
        return [
            str(answer).strip().rstrip(".")
            for answer in resolver.resolve(name, record_type)
        ]
    except dns.exception.DNSException:
        return []


def ptr_for_ip(ip):
    try:
        reverse = dns.reversename.from_address(ip)
        return [
            clean_name(value)
            for value in dns_query(str(reverse), "PTR")
            if clean_name(value)
        ]
    except ValueError:
        return []


def enrich_ptr(rows):
    ips = sorted({row["IP"] for row in rows})

    with ThreadPoolExecutor(max_workers=12) as pool:
        results = dict(zip(ips, pool.map(ptr_for_ip, ips)))

    for row in rows:
        row["PTR_names_for_IP"] = "; ".join(results.get(row["IP"], []))


def candidate_apexes(rows):
    candidates = set()

    for row in rows:
        values = [
            row.get("Domain", ""),
            row.get("PTR_names_for_IP", ""),
            row.get("TLS_certificate_names_on_this_port", ""),
        ]

        for value in values:
            for name in value.split(";"):
                apex = apex_of(name)

                if apex:
                    candidates.add(apex)

    return sorted(candidates)


def approve_domains(candidates):
    path = CONFIG / "approved_domains.txt"
    entries = read_lines(path)

    if entries:
        approved = set()

        for entry in entries:
            apex = apex_of(entry)

            if not apex or clean_name(entry) != apex:
                fail(f"Only apex domains are allowed in {path}: {entry}")

            approved.add(apex)

        selected = sorted(set(candidates) & approved)

    else:
        print("\n[!] Candidate domains are NOT proof of authorization.")

        for domain in candidates:
            print(f"    {domain}")

        raw = input(
            "\nEnter authorized apex domains from this list, "
            "comma-separated (Enter to skip): "
        ).strip()

        selected = sorted({
            clean_name(x)
            for x in re.split(r"[\s,]+", raw)
            if x.strip()
        })

        invalid = set(selected) - set(candidates)

        if invalid:
            fail(f"Unrecognized candidate domains: {sorted(invalid)}")

    print(f"[+] Approved apex domains: {selected}")
    return selected


def discover_subdomains(domains):
    print("\n[+] Running passive Subfinder enumeration...")

    results = defaultdict(set)
    chaos_key = os.getenv("CHAOS_API_KEY", "").strip()

    with tempfile.TemporaryDirectory(prefix="asn_recon_") as directory:
        provider_file = Path(directory) / "provider-config.yaml"
        provider_options = []

        if chaos_key:
            provider_file.write_text(
                f"chaos:\n  - {chaos_key}\n",
                encoding="utf-8",
            )
            os.chmod(provider_file, 0o600)
            provider_options = ["-pc", str(provider_file)]

        for apex in domains:
            results[apex].add("approved_apex")

            try:
                output = run_command(
                    [
                        "subfinder",
                        "-d", apex,
                        "-silent",
                        "-max-time", "2",
                        *provider_options,
                    ],
                    timeout=180,
                    output=True,
                )
            except RuntimeError as exc:
                print(f"[!] Subfinder error for {apex}: {exc}")
                continue

            count = 0

            for line in output.splitlines():
                name = clean_name(line)

                if name and name != apex and name.endswith("." + apex):
                    results[name].add("subfinder")
                    count += 1

            print(f"[+] {apex}: {count} subdomain(s).")

    return results


def resolve_host(name):
    records = []

    for record_type in ("A", "AAAA"):
        for ip in dns_query(name, record_type):
            try:
                ipaddress.ip_address(ip)
                records.append((record_type, ip))
            except ValueError:
                continue

    return name, records


def map_names(names, asn_networks):
    print(f"\n[+] Resolving {len(names)} hostname(s)...")


    mapped = []

    with ThreadPoolExecutor(max_workers=16) as pool:
        futures = [
            pool.submit(resolve_host, name)
            for name in sorted(names)
        ]

        for future in as_completed(futures):
            name, records = future.result()

            for record_type, ip in records:
                mapped.append({
                    "Hostname": name,
                    "IP": ip,
                    "Record_type": record_type,
                    "In_ASN_scope":
                        "yes" if inside(ip, asn_networks) else "no",
                    "Source": "; ".join(sorted(names[name])),
                })

    mapped.sort(key=lambda row: (row["Hostname"], row["IP"]))

    print(f"[+] Resolved {len(mapped)} DNS record(s).")

    return mapped


def other_asn_rows(mapped, target_asn, discovered_networks):
    result = []
    origins = {}
    for row in mapped:
        ip = row["IP"]
        addr = ipaddress.ip_address(ip)
        if not addr.is_global or inside(ip, discovered_networks):
            continue
        if ip not in origins:
            origins[ip] = None
            suffix = "in-addr.arpa" if addr.version == 4 else "ip6.arpa"
            zone = "origin.asn.cymru.com." if addr.version == 4 else "origin6.asn.cymru.com."
            query = addr.reverse_pointer[:-len(suffix)] + zone
            try:
                answers = dns.resolver.resolve(query, "TXT", lifetime=4)
                numbers = {
                    number
                    for answer in answers
                    for number in b"".join(answer.strings).decode("ascii").split("|")[0].split()
                }
                if len(numbers) == 1:
                    number = next(iter(numbers))
                    if number.isdecimal() and int(number) > 0:
                        origins[ip] = f"AS{int(number)}"
            except (dns.exception.DNSException, UnicodeError):
                pass
        origin = origins[ip]
        if origin is not None and int(origin[2:]) != int(target_asn[2:]):
            result.append({"Hostname": row["Hostname"], "IP": ip, "Origin_ASN": origin})
    return result


def external_scan(mapped, port_options, tag, asn_networks):
    """
    Scan only discovered IP addresses that also match the separate
    approved_external_ips.txt allowlist.
    """
    allowlist = load_networks(CONFIG / "approved_external_ips.txt")

    if not allowlist:
        print("[!] No external allowlist configured. Skipping external scan.")
        return []

    discovered = {
        row["IP"]
        for row in mapped
        if inside(row["IP"], allowlist)
        and not inside(row["IP"], asn_networks)
    }

    if not discovered:
        print("[+] No discovered external IPs match the external allowlist.")
        return []

    print("\n[!] External infrastructure candidates:")
    for ip in sorted(discovered, key=lambda ip: (ipaddress.ip_address(ip).version, int(ipaddress.ip_address(ip)))):
        print(f"    {ip}")

    print(
        "\n[!] These targets will be scanned only because they match "
        "your separate external allowlist."
    )

    answer = input(
        "Do you explicitly authorize scanning these external IPs? [y/N]: "
    ).strip().lower()

    if answer != "y":
        print("[+] External scanning skipped.")
        return []

    print("[+] External scan authorization confirmed.")

    endpoints = naabu_scan(
        [],
        port_options,
        tag + "_external",
        targets=discovered,
    )

    # The allowlist is checked again before Nmap.
    endpoints = {
        (ip, port)
        for ip, port in endpoints
        if inside(ip, allowlist)
        and not inside(ip, asn_networks)
    }

    rows = nmap_scan(
        endpoints,
        allowlist,
        tag + "_external",
        scope_label="EXTERNAL_AUTHORIZED",
    )

    return rows


def safe_csv(value):
    text = str(value if value is not None else "")

    if text[:1] in ("=", "+", "-", "@", "\t", "\r", "\n"):
        return "'" + text

    return text


def write_csv(path, columns, rows):
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=columns,
            extrasaction="ignore",
        )

        writer.writeheader()

        for row in rows:
            writer.writerow({
                key: safe_csv(row.get(key, ""))
                for key in columns
            })

    print(f"[+] Saved: {path}")


def review_other_origins(mappings, asn, networks, tag):
    findings = other_asn_rows(mappings, asn, networks)
    if not findings:
        print("[+] No confirmed different-origin mappings. No review needed.")
        return

    print("\\nHostnames with a confirmed different routing ASN:")
    for row in findings:
        print(f"  {row['Hostname']} -> {row['IP']} ({row['Origin_ASN']})")
    try:
        answer = input("Save these findings to a separate review CSV? [y/N]: ")
    except EOFError:
        answer = ""
    if answer.strip().lower() != "y":
        print("Skipped. The primary reports are unchanged.")
        return
    write_csv(REPORTS / f"external_origin_review_{tag}.csv",
              ["Hostname", "IP", "Origin_ASN"], findings)


def main():
    load_dotenv(ROOT / ".env")
    parser = argparse.ArgumentParser(
        description="Authorized ASN and subdomain reconnaissance"
    )

    parser.add_argument(
        "-a", "--asn",
        help="Target ASN, for example AS62367",
    )

    parser.add_argument(
        "--rate",
        type=int,
        default=int(os.getenv("NAABU_RATE", "1000")),
        help="Naabu packet rate (default: 1000)",
    )

    args = parser.parse_args()

    if not 1 <= args.rate <= 10000:
        fail("Naabu rate must be between 1 and 10000.")

    for directory in (STATE, REPORTS):
        directory.mkdir(parents=True, exist_ok=True)

    for program in ("asnmap", "naabu", "nmap", "subfinder"):
        if not shutil.which(program):
            fail(f"Missing executable: {program}")

    asn = normalize_asn(
        args.asn or input("Enter ASN (example AS62367): ")
    )

    tag = (
        asn + "_"
        + datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    )

    print("\n=== Authorized ASN Reconnaissance ===")


    networks = lookup_asn(asn)
    check_scope_size(networks)
    print(f"\nInitial inventory for {asn}:")
    for network in networks:
        print(f"  {network}")
    print(f"Addresses across listed prefixes: {sum(n.num_addresses for n in networks)}")
    try:
        answer = input("Authorized to inventory ALL listed prefixes? [y/N]: ")
    except EOFError:
        answer = ""
    if answer.strip().lower() != "y":
        print("Cancelled. No port scan started.")
        return

    port_options = ["-top-ports", "1000"]

    endpoints = naabu_scan(
        networks,
        port_options,
        tag,
    )

    rows = nmap_scan(
        endpoints,
        networks,
        tag,
    )

    enrich_ptr(rows)

    candidates = candidate_apexes(rows)

    print(f"\n[+] Candidate apex domains: {candidates}")

    approved_domains = candidates  # Passive enumeration and DNS mapping only.

    observed = defaultdict(set)

    for row in rows:
        for field, source in (
            ("Domain", "report_domain"),
            ("PTR_names_for_IP", "PTR"),
            ("TLS_certificate_names_on_this_port", "TLS_certificate"),
        ):
            for value in row.get(field, "").split(";"):
                name = clean_name(value)

                if name and apex_of(name) in approved_domains:
                    observed[name].add(source)

    if approved_domains:
        discovered_names = discover_subdomains(approved_domains)

        for name, sources in discovered_names.items():
            observed[name].update(sources)

    mappings = map_names(observed, networks) if observed else []

    # Save the ASN reports separately.
    write_csv(
        REPORTS / f"scan_report_{tag}.csv",
        SCAN_COLUMNS,
        rows,
    )

    write_csv(
        REPORTS / f"subdomain_ip_map_{tag}.csv",
        MAP_COLUMNS,
        mappings,
    )


    print("\n[+] Initial inventory and hostname enumeration finished. Primary reports saved.")
    review_other_origins(mappings, asn, networks, tag)
    print("[+] Done. No external IP or second ASN was scanned.")


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, OSError, ET.ParseError, csv.Error) as exc:
        print(f"\n[-] {exc}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[-] Interrupted.", file=sys.stderr)
        sys.exit(130)
