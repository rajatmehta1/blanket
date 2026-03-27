from flask import Flask, jsonify, request
app = Flask(__name__)

@app.route("/api/patients/<int:patient_id>")
def get_patient_endpoint(patient_id):
    # No authentication check!
    # No audit logging!
    return jsonify(get_patient(patient_id))

@app.route("/api/patients/search")
def search_patients_endpoint():
    query = request.args.get("q", "")
    # PHI transmitted without TLS enforcement
    return jsonify(search_patients(query))
