"""Kubernetes manifest parser — extracts Deployment, Service, Ingress details."""
from __future__ import annotations

from typing import Any

import yaml
import structlog

logger = structlog.get_logger()

from pydantic import BaseModel


class K8sResource(BaseModel):
    """One Kubernetes resource extracted from a manifest."""
    kind: str              # Deployment, Service, Ingress, etc.
    name: str
    namespace: str = "default"
    file_path: str
    api_version: str = ""

    # Security-relevant fields
    image: str = ""
    replicas: int = 0
    service_type: str = ""      # ClusterIP, NodePort, LoadBalancer
    ports: list[int] = []
    runs_as_root: bool = False
    privileged: bool = False
    read_only_root: bool = False
    resource_limits: bool = False   # Whether limits are set
    host_network: bool = False


class K8sExtractionResult(BaseModel):
    """All resources from one K8s manifest file."""
    file_path: str
    resources: list[K8sResource] = []


class K8sExtractor:
    """Extract security-relevant info from Kubernetes YAML manifests."""

    def extract(self, file_path: str, content: str) -> K8sExtractionResult:
        result = K8sExtractionResult(file_path=file_path)

        try:
            docs = list(yaml.safe_load_all(content))
        except yaml.YAMLError as exc:
            logger.warning("k8s_extractor.parse_error", file=file_path, error=str(exc)[:200])
            return result

        for doc in docs:
            if not isinstance(doc, dict):
                continue
            if "kind" not in doc:
                continue

            resource = self._extract_resource(doc, file_path)
            if resource:
                result.resources.append(resource)

        return result

    def _extract_resource(self, doc: dict, file_path: str) -> K8sResource | None:
        kind = doc.get("kind", "")
        metadata = doc.get("metadata", {})
        name = metadata.get("name", "unknown")
        namespace = metadata.get("namespace", "default")
        api_version = doc.get("apiVersion", "")

        resource = K8sResource(
            kind=kind,
            name=name,
            namespace=namespace,
            file_path=file_path,
            api_version=api_version,
        )

        spec = doc.get("spec", {})

        if kind in ("Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob"):
            resource.replicas = spec.get("replicas", 1)

            # Dig into pod template
            template = spec.get("template", {})
            pod_spec = template.get("spec", {})
            resource.host_network = pod_spec.get("hostNetwork", False)

            containers = pod_spec.get("containers", [])
            for container in containers:
                if container.get("image"):
                    resource.image = container["image"]

                # Security context
                sec_ctx = container.get("securityContext", {})
                if sec_ctx.get("runAsUser") == 0 or sec_ctx.get("runAsNonRoot") is False:
                    resource.runs_as_root = True
                if sec_ctx.get("privileged"):
                    resource.privileged = True
                if sec_ctx.get("readOnlyRootFilesystem"):
                    resource.read_only_root = True

                # Resource limits
                resources = container.get("resources", {})
                if resources.get("limits"):
                    resource.resource_limits = True

                # Ports
                for port in container.get("ports", []):
                    if "containerPort" in port:
                        resource.ports.append(port["containerPort"])

        elif kind == "Service":
            resource.service_type = spec.get("type", "ClusterIP")
            for port in spec.get("ports", []):
                if "port" in port:
                    resource.ports.append(port["port"])

        elif kind == "Ingress":
            rules = spec.get("rules", [])
            for rule in rules:
                http = rule.get("http", {})
                for path_rule in http.get("paths", []):
                    backend = path_rule.get("backend", {})
                    svc = backend.get("service", {})
                    port_info = svc.get("port", {})
                    if port_info.get("number"):
                        resource.ports.append(port_info["number"])

        return resource
