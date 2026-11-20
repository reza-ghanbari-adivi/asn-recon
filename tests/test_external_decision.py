import ipaddress
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from src import asn_recon as scanner


class ExternalDecisionTests(unittest.TestCase):
    def check_skip(self, allowed, candidate, answer, expect_prompt):
        with tempfile.TemporaryDirectory() as folder:
            config = Path(folder)
            if allowed:
                (config / 'approved_external_ips.txt').write_text(allowed + '\n')
            with patch.object(scanner, 'CONFIG', config), patch('builtins.input', return_value=answer) as prompt, patch.object(scanner, 'naabu_scan') as naabu, patch.object(scanner, 'nmap_scan') as nmap:
                result = scanner.external_scan([{'IP': candidate}], [], 'test', [ipaddress.ip_network('192.0.2.0/24')])
                self.assertEqual(result, [])
                self.assertEqual(prompt.call_count, int(expect_prompt))
                naabu.assert_not_called()
                nmap.assert_not_called()

    def test_decline_and_default_skip(self):
        for answer in ('n', ''):
            with self.subTest(answer=answer):
                self.check_skip('198.51.100.8', '198.51.100.8', answer, True)

    def test_missing_allowlist(self):
        self.check_skip(None, '198.51.100.8', 'y', False)

    def test_unlisted_candidate(self):
        self.check_skip('198.51.100.9', '198.51.100.8', 'y', False)

    def test_inside_candidate_is_not_external(self):
        self.check_skip('192.0.2.8', '192.0.2.8', 'y', False)
