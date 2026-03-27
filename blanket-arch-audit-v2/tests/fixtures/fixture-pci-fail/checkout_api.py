from flask import Flask, request, jsonify
app = Flask(__name__)

DEBUG = True  # Debug mode in production

@app.route("/api/checkout", methods=["POST"])
def checkout():
    # No rate limiting on payment endpoint
    # No CSRF protection
    data = request.json
    card = data.get("card_number")
    cvv = data.get("cvv")
    result = process_payment(card, cvv, data.get("amount", 0))
    return jsonify(result)
