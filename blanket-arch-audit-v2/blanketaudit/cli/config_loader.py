"""Load and merge configuration: audit.yaml → env vars → CLI flags.

CLI flags win over env vars, which win over audit.yaml, which win over defaults.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from blanketaudit.config import Settings, get_settings


_YAML_TO_SETTINGS_MAP: dict[str, str] = {
    "frameworks": "active_frameworks",
    "domain": "domain",
}


def _deep_merge(base: dict, override: dict) -> dict:
    """Recursively merge *override* into *base* (mutates *base*)."""
    for key, value in override.items():
        if key in base and isinstance(base[key], dict) and isinstance(value, dict):
            _deep_merge(base[key], value)
        else:
            base[key] = value
    return base


def _flatten_yaml(yaml_data: dict) -> dict[str, Any]:
    """Convert the audit.yaml structure into a flat dict matching Settings fields."""
    flat: dict[str, Any] = {}

    # Top-level simple keys
    for yaml_key, settings_key in _YAML_TO_SETTINGS_MAP.items():
        if yaml_key in yaml_data:
            flat[settings_key] = yaml_data[yaml_key]

    # scan section
    scan = yaml_data.get("scan", {})
    if "repos" in scan:
        flat["repos"] = scan["repos"]
    if "paths" in scan:
        flat["paths"] = scan["paths"]

    # Nested sections that map 1:1
    for section in ("llm", "cost", "output", "cache", "agents"):
        if section in yaml_data:
            flat[section] = yaml_data[section]

    return flat


def load_yaml(path: Path) -> dict:
    """Read and parse an audit.yaml file.  Returns empty dict if missing."""
    if not path.exists():
        return {}
    with open(path) as f:
        data = yaml.safe_load(f)
    return data if isinstance(data, dict) else {}


def load_config(
    yaml_path: Path | str | None = None,
    cli_overrides: dict[str, Any] | None = None,
) -> Settings:
    """Build a fully-merged Settings object.

    1. Start with defaults (from Settings model)
    2. Layer audit.yaml values
    3. Env vars are picked up automatically by pydantic-settings
    4. CLI overrides applied last (highest priority)
    """
    # Load yaml
    yaml_data: dict = {}
    if yaml_path is not None:
        yaml_data = load_yaml(Path(yaml_path))

    # Flatten yaml into settings-shaped dict
    yaml_flat = _flatten_yaml(yaml_data) if yaml_data else {}

    # Merge CLI overrides on top
    if cli_overrides:
        _deep_merge(yaml_flat, cli_overrides)

    # Clear cached settings so we get a fresh one
    get_settings.cache_clear()

    # Build settings — pydantic-settings reads env vars automatically;
    # we pass yaml+CLI values as init kwargs
    settings = Settings(**yaml_flat)

    return settings
