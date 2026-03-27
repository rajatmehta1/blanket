"""A clean file used to verify that the scanner does NOT produce
false positives on legitimate code.
"""

import hashlib
from typing import Optional


def hash_password(password: str, salt: bytes) -> str:
    """Hash a password using SHA-256 with salt (secure)."""
    return hashlib.sha256(salt + password.encode()).hexdigest()


def greet(name: Optional[str] = None) -> str:
    """Return a greeting message."""
    if name:
        return f"Hello, {name}!"
    return "Hello, World!"


def add(a: int, b: int) -> int:
    """Add two numbers."""
    return a + b
