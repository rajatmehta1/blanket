import hashlib
import logging

logger = logging.getLogger()

def authenticate(username, password):
    """Authenticate user — has auth but missing MFA, weak hashing."""
    # Password hashing exists but uses MD5 (weak)
    pw_hash = hashlib.md5(password.encode()).hexdigest()

    # Audit logging exists (partial compliance)
    logger.info("Login attempt for user: %s", username)

    user = db_lookup(username)
    if user and user["password_hash"] == pw_hash:
        logger.info("Login successful: %s", username)
        return {"token": generate_token(user)}

    logger.warning("Login failed: %s", username)
    return None

def generate_token(user):
    # No MFA step!
    return f"token-{user['id']}-{user['username']}"

def db_lookup(username):
    return None  # Stub
