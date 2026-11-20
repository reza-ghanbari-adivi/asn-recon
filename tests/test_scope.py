import ipaddress
import unittest


from src.asn_recon import inside


class ScopeTests(unittest.TestCase):

    def test_ip_inside_network(self):
        networks = [ipaddress.ip_network("192.0.2.0/24")]
        self.assertTrue(inside("192.0.2.10", networks))

    def test_ip_outside_network(self):
        networks = [ipaddress.ip_network("192.0.2.0/24")]
        self.assertFalse(inside("198.51.100.10", networks))

    def test_ipv6_network(self):
        networks = [ipaddress.ip_network("2001:db8::/32")]
        self.assertTrue(inside("2001:db8::1", networks))

    def test_mixed_networks(self):
        networks = [
            ipaddress.ip_network("192.0.2.0/24"),
            ipaddress.ip_network("2001:db8::/32"),
        ]
        self.assertTrue(inside("192.0.2.20", networks))
        self.assertTrue(inside("2001:db8::5", networks))
        self.assertFalse(inside("198.51.100.20", networks))


if __name__ == "__main__":
    unittest.main()
