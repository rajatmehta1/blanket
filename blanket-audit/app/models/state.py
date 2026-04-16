import operator
from typing import List, Optional, Any, Dict

from typing_extensions import TypedDict, Annotated

from app.models.common import CustomerProfile


class AuditState(TypedDict):
    repo_url: str
    customer_profile: CustomerProfile

    # ingestion output
    repo_metadata: Optional[Dict[str, Any]]
    parsed_files: Annotated[List[Dict[str, Any]], operator.add]
    graph_populated: bool
    embeddings_populated: bool

    # analysis agent outputs (parallel, using reducer)
    architecture_findings: Annotated[List[Dict[str, Any]], operator.add]
    scalability_findings: Annotated[List[Dict[str, Any]], operator.add]
    security_findings: Annotated[List[Dict[str, Any]], operator.add]
    cost_findings: Annotated[List[Dict[str, Any]], operator.add]

    # domain detection output
    domain_findings: Annotated[List[Dict[str, Any]], operator.add]
    detected_domains: List[str]

    # execution metadata
    errors: Annotated[List[str], operator.add]
    agent_logs: Annotated[List[str], operator.add]
