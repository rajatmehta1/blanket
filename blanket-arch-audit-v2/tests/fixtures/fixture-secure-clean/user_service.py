import hashlib
import hmac
import logging
import os
import secrets

logger = logging.getLogger(__name__)

def hash_password(password: str) -> tuple[str, str]:
    """Hash password with bcrypt-like approach (salt + SHA-256)."""
    salt = secrets.token_hex(16)
    pw_hash = hashlib.sha256((salt + password).encode()).hexdigest()
    return salt, pw_hash

def verify_password(password: str, salt: str, pw_hash: str) -> bool:
    return hmac.compare_digest(
        hashlib.sha256((salt + password).encode()).hexdigest(),
        pw_hash,
    )

def get_user(db, user_id: int) -> dict:
    """Parameterized query — no SQL injection."""
    return db.execute("SELECT id, name, email FROM users WHERE id = ?", (user_id,)).fetchone()
