from pydantic import BaseModel
from app.models.common import CustomerProfile


class AuditRequest(BaseModel):
    repo_url: str
    customer_profile: CustomerProfile = CustomerProfile.STARTUP
