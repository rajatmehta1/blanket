from __future__ import annotations
from enum import Enum

class CustomerProfile(str, Enum):
    """customer segment that drives audit weight and recommendations"""
    SAAS = "saas"
    STARTUP = "startup"
    AI_TEAM = "ai_team"

class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class FindingCategory(str, Enum):
    ARCHITECTURE_RISK = "architecture_risk"
    SCALABILITY = "scalability"
    SECURITY = "security"
    COST_OPTIMIZATION = "cost_optimization"
    PERFORMANCE = "performance"
    MAINTAINABILITY = "maintainability"

class OWASPCategory(str, Enum):
    """OWASP ASVS (Application Security Verification Standard) V1-V14"""
    V1_ARCHITECTURE_DESIGN = "V1 - Architecture, Design and Threat Modeling"
    V2_AUTHENTICATION = "V2 - Authentication"
    V3_SESSION_MANAGEMENT = "V3 - Session Management"
    V4_ACCESS_CONTROL = "V4 - Access Control"
    V5_INPUT_VALIDATION = "V5 - Validation, Sanitization and Encoding"
    V6_CRYPTOGRAPHY = "V6 - Stored Cryptography"
    V7_ERROR_HANDLING_LOGGING = "V7 - Error Handling and Logging"
    V8_DATA_PROTECTION = "V8 - Data Protection"
    V9_COMMUNICATION_SECURITY = "V9 - Communication Security"
    V10_MALICIOUS_CODE = "V10 - Malicious Code"
    V11_BUSINESS_LOGIC = "V11 - Business Logic"
    V12_FILES_RESOURCES = "V12 - Files and Resources"
    V13_API_WEB_SERVICE = "V13 - API and Web Service"
    V14_CONFIGURATION = "V14 - Configuration"
