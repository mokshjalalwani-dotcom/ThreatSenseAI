"""
Rate limiting configuration using slowapi.
"""

from slowapi import Limiter
from slowapi.util import get_remote_address

# Initialize Limiter with IP-based rate limiting
limiter = Limiter(key_func=get_remote_address)
