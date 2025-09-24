"""
Centralized logging configuration for the BACnet protocol module.
This module provides a shared logger instance to avoid circular imports.
"""
import logging

# Create a logger instance that can be imported by other modules
_log = logging.getLogger("protocol_proxy.protocol.bacnet")


def get_logger():
    """Get the BACnet protocol logger instance."""
    return _log
