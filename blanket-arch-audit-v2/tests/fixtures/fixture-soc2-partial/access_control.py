import os

ROLES = {
    "admin": ["read", "write", "delete", "manage_users"],
    "user": ["read", "write", "delete"],  # Users can delete — too permissive
}

def check_permission(user_role, action):
    """Check if role has permission — exists but overly permissive."""
    return action in ROLES.get(user_role, [])

def deploy():
    # No change management process
    os.system("git push origin main && kubectl apply -f deploy.yaml")
