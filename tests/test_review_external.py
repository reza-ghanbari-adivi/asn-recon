import csv
import io
import unittest
from src.review_external import external_pairs


class ReviewTests(unittest.TestCase):
    def test_report_column_names(self):
        for col in ('In_ASN_scope', 'In_scope'):
            with self.subTest(col=col):
                report = f'Hostname,IP,{col}\na.example,192.0.2.4,yes\nb.example,198.51.100.9,no\n'
                self.assertEqual(external_pairs(csv.DictReader(io.StringIO(report))), [('b.example', '198.51.100.9')])

    def test_missing_scope_column(self):
        with self.assertRaises(ValueError):
            external_pairs(csv.DictReader(['Hostname,IP']))
