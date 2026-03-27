import sqlite3
import hashlib

def process_payment(card_number, cvv, amount):
    """Process a payment — PCI-DSS violations planted."""
    # Plaintext card data storage
    conn = sqlite3.connect("payments.db")
    conn.execute(
        f"INSERT INTO transactions (card_number, cvv, amount) "
        f"VALUES ('{card_number}', '{cvv}', {amount})"
    )  # SQL injection + plaintext card storage
    conn.commit()

    # Weak hashing for card fingerprint
    card_hash = hashlib.md5(card_number.encode()).hexdigest()

    # Log card data
    print(f"Payment processed: card={card_number}, amount=${amount}")

    return {"status": "success", "card_hash": card_hash}

def get_transaction(transaction_id):
    conn = sqlite3.connect("payments.db")
    # SQL injection
    return conn.execute(
        f"SELECT * FROM transactions WHERE id = {transaction_id}"
    ).fetchone()

API_KEY = "sk-live-abc123def456"  # Hardcoded API key
DB_URL = "postgresql://admin:password123@db.internal:5432/payments"
