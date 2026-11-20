"""Review external DNS answers in an existing subdomain_ip_map CSV (offline)."""
import argparse
import csv
from pathlib import Path


def external_pairs(reader):
    fields = reader.fieldnames or []
    scope = 'In_ASN_scope' if 'In_ASN_scope' in fields else 'In_scope'
    if not {'Hostname', 'IP', scope}.issubset(fields):
        raise ValueError('Expected Hostname, IP and In_ASN_scope (or legacy In_scope).')
    return sorted({(r['Hostname'], r['IP']) for r in reader if r[scope] == 'no' and r['Hostname'] and r['IP']})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('report', type=Path)
    args = parser.parse_args()
    with args.report.open(newline='', encoding='utf-8-sig') as f:
        pairs = external_pairs(csv.DictReader(f))
    if not pairs:
        print('No outside-range answers in this report.')
        return
    print(f'{len(pairs)} hostname/IP pair(s) outside the approved scan ranges.')
    try:
        keep = input('Save them for manual scan-scope review? [y/N] ').strip().lower()
    except EOFError:
        keep = ''
    if keep not in {'y', 'yes'}:
        print('Skipped. No scope changes.')
        return
    out = args.report.with_suffix('.review.csv')
    with out.open('x', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['Hostname', 'IP', 'Decision'])
        writer.writerows((name, ip, 'needs authorization') for name, ip in pairs)
    print(f'Saved {out}. No scan was started.')


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, csv.Error) as exc:
        raise SystemExit(str(exc))
