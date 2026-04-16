"""Terraform configuration extractor — resource blocks via regex."""
from __future__ import annotations

import re
from typing import Any

import structlog

logger = structlog.get_logger()

from pydantic import BaseModel


class TerraformResource(BaseModel):
    """One Terraform resource block."""
    resource_type: str       # aws_s3_bucket, azurerm_key_vault, etc.
    name: str                # Logical name in the config
    file_path: str
    line_number: int
    provider: str = ""       # aws, azurerm, google, etc.
    # Security-relevant
    encryption_enabled: bool | None = None
    public_access: bool | None = None
    logging_enabled: bool | None = None


class TerraformExtractionResult(BaseModel):
    """All resources from Terraform files."""
    file_path: str
    resources: list[TerraformResource] = []
    variables: list[str] = []
    outputs: list[str] = []
    providers: list[str] = []


# Match resource "type" "name" { ... }
_RESOURCE_RE = re.compile(
    r'^resource\s+"([^"]+)"\s+"([^"]+)"\s*\{',
    re.MULTILINE,
)
_VARIABLE_RE = re.compile(r'^variable\s+"([^"]+)"\s*\{', re.MULTILINE)
_OUTPUT_RE = re.compile(r'^output\s+"([^"]+)"\s*\{', re.MULTILINE)
_PROVIDER_RE = re.compile(r'^provider\s+"([^"]+)"\s*\{', re.MULTILINE)

# Security-relevant patterns inside resource blocks
_ENCRYPTION_PATTERNS = re.compile(
    r"(encryption|kms_key_id|server_side_encryption|encrypted)\s*=\s*(true|\"aws:kms\"|\"AES256\")",
    re.IGNORECASE,
)
_PUBLIC_ACCESS_PATTERNS = re.compile(
    r"(public_access_block_configuration|restrict_public_buckets|block_public_acls|"
    r"acl\s*=\s*\"public|publicly_accessible\s*=\s*true)",
    re.IGNORECASE,
)
_LOGGING_PATTERNS = re.compile(
    r"(logging|access_logs|enable_logging)\s*\{|"
    r"(logging_enabled|enable_access_logs)\s*=\s*true",
    re.IGNORECASE,
)


class TerraformExtractor:
    """Extract resource blocks from Terraform .tf files."""

    def extract(self, file_path: str, content: str) -> TerraformExtractionResult:
        result = TerraformExtractionResult(file_path=file_path)

        # Extract resources
        for match in _RESOURCE_RE.finditer(content):
            res_type = match.group(1)
            res_name = match.group(2)
            line_number = content[:match.start()].count("\n") + 1

            # Infer provider from resource type
            provider = res_type.split("_")[0] if "_" in res_type else ""

            # Extract the block content (find matching closing brace)
            block_start = match.end()
            block_content = self._extract_block(content, block_start)

            resource = TerraformResource(
                resource_type=res_type,
                name=res_name,
                file_path=file_path,
                line_number=line_number,
                provider=provider,
            )

            # Check security patterns
            if _ENCRYPTION_PATTERNS.search(block_content):
                resource.encryption_enabled = True
            elif "encrypt" in block_content.lower():
                resource.encryption_enabled = False  # Mentioned but not enabled

            if _PUBLIC_ACCESS_PATTERNS.search(block_content):
                resource.public_access = True

            if _LOGGING_PATTERNS.search(block_content):
                resource.logging_enabled = True

            result.resources.append(resource)

        # Extract variables, outputs, providers
        result.variables = [m.group(1) for m in _VARIABLE_RE.finditer(content)]
        result.outputs = [m.group(1) for m in _OUTPUT_RE.finditer(content)]
        result.providers = [m.group(1) for m in _PROVIDER_RE.finditer(content)]

        return result

    @staticmethod
    def _extract_block(content: str, start: int) -> str:
        """Extract content between { and matching } starting from *start*."""
        depth = 1
        i = start
        while i < len(content) and depth > 0:
            if content[i] == "{":
                depth += 1
            elif content[i] == "}":
                depth -= 1
            i += 1
        return content[start:i]
