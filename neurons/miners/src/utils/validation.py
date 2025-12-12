"""
Input validation utilities for the miner CLI and services.

These validators prevent input-based issues such as:
- Whitespace in IP addresses causing executor lookup failures
- Malformed IP addresses that could cause unexpected behavior
- Port number out of valid range
"""

import ipaddress
import logging
import re

logger = logging.getLogger(__name__)


class ValidationError(Exception):
    """Raised when input validation fails."""
    pass


def normalize_ip_address(ip: str) -> str:
    """
    Normalize and validate an IP address string.
    
    Strips leading/trailing whitespace and validates format.
    
    Args:
        ip: Raw IP address string from user input
        
    Returns:
        Normalized IP address string
        
    Raises:
        ValidationError: If IP address is invalid
    """
    if not ip:
        raise ValidationError("IP address cannot be empty")
    
    # Strip whitespace
    normalized = ip.strip()
    
    if not normalized:
        raise ValidationError("IP address cannot be empty or whitespace only")
    
    # Check for internal whitespace (e.g., "192.168. 1.1")
    if re.search(r'\s', normalized):
        raise ValidationError(
            f"IP address contains invalid whitespace: '{ip}'. "
            "Please remove any spaces from the IP address."
        )
    
    # Validate IP address format
    try:
        # This handles both IPv4 and IPv6
        parsed = ipaddress.ip_address(normalized)
        # Return the canonical string representation
        return str(parsed)
    except ValueError as e:
        raise ValidationError(f"Invalid IP address format: '{normalized}'. {e}")


def validate_port(port: int) -> int:
    """
    Validate a port number is within valid range.
    
    Args:
        port: Port number
        
    Returns:
        Validated port number
        
    Raises:
        ValidationError: If port is out of valid range
    """
    if not isinstance(port, int):
        raise ValidationError(f"Port must be an integer, got {type(port).__name__}")
    
    if port < 1 or port > 65535:
        raise ValidationError(
            f"Port {port} is out of valid range (1-65535)"
        )
    
    return port


def normalize_executor_address(address: str, port: int) -> tuple[str, int]:
    """
    Normalize and validate executor address and port together.
    
    This is the main entry point for validating executor connection info.
    
    Args:
        address: IP address string
        port: Port number
        
    Returns:
        Tuple of (normalized_address, validated_port)
        
    Raises:
        ValidationError: If either address or port is invalid
    """
    normalized_address = normalize_ip_address(address)
    validated_port = validate_port(port)
    
    logger.debug(
        f"Normalized executor address: '{address}' -> '{normalized_address}', "
        f"port: {port}"
    )
    
    return normalized_address, validated_port
