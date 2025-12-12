"""
Tests for IP Address Validation

This test verifies that IP addresses are properly normalized and validated
to prevent whitespace-related lookup failures when managing executors.
"""

import os
import sys
import unittest

# Add src to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from utils.validation import (
    ValidationError,
    normalize_executor_address,
    normalize_ip_address,
    validate_port,
)


class TestIPAddressNormalization(unittest.TestCase):
    """Tests for IP address normalization."""

    def test_valid_ipv4_unchanged(self):
        """Valid IPv4 address should be returned as-is."""
        result = normalize_ip_address("192.168.1.1")
        self.assertEqual(result, "192.168.1.1")

    def test_valid_ipv6_unchanged(self):
        """Valid IPv6 address should be returned in canonical form."""
        result = normalize_ip_address("::1")
        self.assertEqual(result, "::1")

    def test_trailing_whitespace_stripped(self):
        """Trailing whitespace should be stripped."""
        result = normalize_ip_address("192.168.1.1 ")
        self.assertEqual(result, "192.168.1.1")

    def test_leading_whitespace_stripped(self):
        """Leading whitespace should be stripped."""
        result = normalize_ip_address("  192.168.1.1")
        self.assertEqual(result, "192.168.1.1")

    def test_both_leading_and_trailing_whitespace(self):
        """Both leading and trailing whitespace should be stripped."""
        result = normalize_ip_address("  192.168.1.1  ")
        self.assertEqual(result, "192.168.1.1")

    def test_newline_stripped(self):
        """Newlines should be stripped."""
        result = normalize_ip_address("192.168.1.1\n")
        self.assertEqual(result, "192.168.1.1")

    def test_tab_stripped(self):
        """Tabs should be stripped."""
        result = normalize_ip_address("\t192.168.1.1\t")
        self.assertEqual(result, "192.168.1.1")

    def test_internal_whitespace_rejected(self):
        """Internal whitespace should be rejected with clear error."""
        with self.assertRaises(ValidationError) as cm:
            normalize_ip_address("192.168. 1.1")
        self.assertIn("whitespace", str(cm.exception).lower())

    def test_empty_string_rejected(self):
        """Empty string should be rejected."""
        with self.assertRaises(ValidationError) as cm:
            normalize_ip_address("")
        self.assertIn("empty", str(cm.exception).lower())

    def test_whitespace_only_rejected(self):
        """Whitespace-only string should be rejected."""
        with self.assertRaises(ValidationError) as cm:
            normalize_ip_address("   ")
        self.assertIn("empty", str(cm.exception).lower())

    def test_invalid_ip_format_rejected(self):
        """Invalid IP format should be rejected."""
        with self.assertRaises(ValidationError) as cm:
            normalize_ip_address("not.an.ip.address")
        self.assertIn("invalid", str(cm.exception).lower())

    def test_ip_with_port_rejected(self):
        """IP with port suffix should be rejected (port is separate param)."""
        with self.assertRaises(ValidationError):
            normalize_ip_address("192.168.1.1:8001")

    def test_hostname_rejected(self):
        """Hostnames should be rejected (only IPs allowed)."""
        with self.assertRaises(ValidationError):
            normalize_ip_address("localhost")

    def test_ipv4_with_leading_zeros_rejected(self):
        """IPv4 with leading zeros should be rejected (ambiguous notation)."""
        # Leading zeros are rejected by Python's ipaddress module because
        # they could be interpreted as octal notation in some contexts
        with self.assertRaises(ValidationError):
            normalize_ip_address("192.168.001.001")


class TestPortValidation(unittest.TestCase):
    """Tests for port number validation."""

    def test_valid_port(self):
        """Valid port should be returned."""
        self.assertEqual(validate_port(8001), 8001)

    def test_port_min_boundary(self):
        """Port 1 should be valid."""
        self.assertEqual(validate_port(1), 1)

    def test_port_max_boundary(self):
        """Port 65535 should be valid."""
        self.assertEqual(validate_port(65535), 65535)

    def test_port_zero_rejected(self):
        """Port 0 should be rejected."""
        with self.assertRaises(ValidationError):
            validate_port(0)

    def test_port_negative_rejected(self):
        """Negative port should be rejected."""
        with self.assertRaises(ValidationError):
            validate_port(-1)

    def test_port_too_high_rejected(self):
        """Port above 65535 should be rejected."""
        with self.assertRaises(ValidationError):
            validate_port(65536)


class TestExecutorAddressNormalization(unittest.TestCase):
    """Tests for combined executor address and port validation."""

    def test_valid_address_and_port(self):
        """Valid address and port should be returned normalized."""
        addr, port = normalize_executor_address("192.168.1.1 ", 8001)
        self.assertEqual(addr, "192.168.1.1")
        self.assertEqual(port, 8001)

    def test_invalid_address_raises(self):
        """Invalid address should raise ValidationError."""
        with self.assertRaises(ValidationError):
            normalize_executor_address("invalid", 8001)

    def test_invalid_port_raises(self):
        """Invalid port should raise ValidationError."""
        with self.assertRaises(ValidationError):
            normalize_executor_address("192.168.1.1", 0)


class TestWhitespaceScenario(unittest.TestCase):
    """Test for whitespace handling in IP addresses."""

    def test_whitespace_mismatch_scenario(self):
        """
        Test that stored IP with whitespace matches user input without whitespace.
        
        User added executor with IP that got stored with trailing space.
        When trying to remove, the lookup should still work after normalization.
        """
        # Simulate the stored IP (with trailing space as reported)
        stored_ip = "192.168.1.100 "
        
        # User tries to remove with clean IP
        user_input = "192.168.1.100"
        
        # Both should normalize to the same value
        stored_normalized = normalize_ip_address(stored_ip)
        user_normalized = normalize_ip_address(user_input)
        
        self.assertEqual(stored_normalized, user_normalized)
        self.assertEqual(stored_normalized, "192.168.1.100")


if __name__ == '__main__':
    unittest.main(verbosity=2)
