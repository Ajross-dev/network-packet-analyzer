#Unit tests for analyzer.py

# to run: cd ~/network-packet-analyzer .venv/bin/python -m unittest -v test_analyzer.py

import sys
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from analyzer import get_ip_addresses, parse_arguments


class TestIPAddresses(unittest.TestCase):

    def test_ipv4_packet(self):
        packet = SimpleNamespace(
            ip=SimpleNamespace(src="192.168.1.10", dst="8.8.8.8")
        )

        self.assertEqual(
            get_ip_addresses(packet),
            ("192.168.1.10", "8.8.8.8")
        )

    def test_packet_without_ipv4(self):
        packet = SimpleNamespace()

        self.assertEqual(get_ip_addresses(packet), ("", ""))


class TestArguments(unittest.TestCase):

    def parse_with(self, *arguments):
        # Simulate CLI arguments without running the actual program.
        with patch.object(sys, "argv", ["analyzer.py", *arguments]):
            return parse_arguments()

    def test_defaults(self):
        args = self.parse_with()

        self.assertEqual(args.count, 5)
        self.assertEqual(args.interface, "eth0")
        self.assertIsNone(args.protocol)
        self.assertIsNone(args.output)

    def test_protocol_is_uppercase(self):
        args = self.parse_with("--protocol", "tcp")
        self.assertEqual(args.protocol, "TCP")

    def test_valid_csv_filename(self):
        args = self.parse_with("--output", "packets.csv")
        self.assertEqual(args.output, "packets.csv")

    def test_nonpositive_count_is_rejected(self):
        for count in ("0", "-3"):
            with self.subTest(count=count):
                with self.assertRaises(SystemExit):
                    self.parse_with("--count", count)

    def test_invalid_csv_filename_is_rejected(self):
        with self.assertRaises(SystemExit):
            self.parse_with("--output", "../packets.csv")


if __name__ == "__main__":
    unittest.main()
