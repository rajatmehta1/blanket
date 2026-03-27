import logging
import sqlite3

logger = logging.getLogger()

def get_patient(patient_id):
    """Retrieve patient record — HIPAA violations planted."""
    conn = sqlite3.connect("patients.db")  # No encryption at rest
    cursor = conn.cursor()
    # PHI in logs violation
    cursor.execute(f"SELECT * FROM patients WHERE id = {patient_id}")
    patient = cursor.fetchone()
    logger.info("Retrieved patient: %s, SSN: %s, DOB: %s",
                patient[1], patient[2], patient[3])  # PHI in logs!
    return patient

def search_patients(query):
    conn = sqlite3.connect("patients.db")
    # SQL injection + PHI exposure
    results = conn.execute(f"SELECT * FROM patients WHERE name LIKE '%{query}%'")
    return results.fetchall()

password = "admin123"  # Hardcoded credential
