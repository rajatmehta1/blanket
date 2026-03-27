from flask import Flask, jsonify, request, abort
from functools import wraps

app = Flask(__name__)

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("Authorization")
        if not token or not validate_token(token):
            abort(401)
        return f(*args, **kwargs)
    return decorated

@app.route("/api/users/<int:user_id>")
@require_auth
def get_user_endpoint(user_id):
    user = get_user(db, user_id)
    if not user:
        abort(404)
    return jsonify({"id": user[0], "name": user[1]})

def validate_token(token):
    return token.startswith("Bearer ")  # Simplified for fixture
