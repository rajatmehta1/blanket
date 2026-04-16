"""Ingestion and entity extraction data models (Pydantic v2)."""
from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import BaseModel, Field, field_validator


class FileType(str, Enum):
    """Classification of a source file by its role in the project."""

    SOURCE = "source"
    CONFIG = "config"
    BUILD = "build"
    IAC = "iac"  # Infrastructure as code (Terraform, K8s)
    CICD = "cicd"  # CI/CD pipelines
    TEST = "test"
    DOC = "doc"
    OTHER = "other"


class FileMetadata(BaseModel):
    """Metadata for a single source file."""

    path: str
    repo_name: str
    language: str
    loc: int = 0
    file_type: FileType = FileType.SOURCE
    content_sha256: str = ""
    size_bytes: int = 0
    last_modified: str = ""


class RepoInfo(BaseModel):
    """Summary info for one repository."""

    name: str
    url: str = ""
    branch: str = "main"
    commit_sha: str = ""
    language: str = ""  # Primary language
    file_count: int = 0
    total_lines: int = 0


class ProjectInfo(BaseModel):
    """Top-level project info aggregating all repos."""

    name: str
    tagline: str = ""
    domain: str = "general"
    repos: list[RepoInfo] = []


class ImportInfo(BaseModel):
    """One import statement extracted from a source file."""

    source_file: str
    imported_module: str
    imported_names: list[str] = []
    line_number: int = 0
    is_relative: bool = False


class ClassInfo(BaseModel):
    """A class/interface extracted from source code."""

    name: str
    file_path: str
    repo_name: str
    line_start: int
    line_end: int
    methods: list[str] = []  # Method names defined in this class
    bases: list[str] = []  # Base class / interface names
    decorators: list[str] = []
    loc: int = 0


class MethodInfo(BaseModel):
    """A function/method extracted from source code."""

    name: str
    qualified_name: str  # e.g., "MyClass.my_method" or module-level "my_func"
    file_path: str
    repo_name: str
    line_start: int
    line_end: int
    parameters: list[str] = []
    return_type: str = ""
    decorators: list[str] = []
    is_entry_point: bool = False  # e.g., route handler, main()
    loc: int = 0
    complexity: int = 0  # Cyclomatic complexity


class CallInfo(BaseModel):
    """A function call extracted from source code."""

    caller: str  # Qualified name of the calling method
    callee: str  # Qualified name of the called method
    file_path: str
    line_number: int
    call_type: Literal["direct", "method", "constructor", "http", "async"] = "direct"


class EntryPointInfo(BaseModel):
    """An HTTP or event entry point (route handler, Lambda, etc.)."""

    method_name: str
    file_path: str
    repo_name: str
    http_method: str = ""  # GET, POST, etc.
    route: str = ""  # /api/patients/{id}
    framework: str = ""  # fastapi, spring, express
    line_number: int = 0


class AnalysisContext(BaseModel):
    """Aggregated context passed from ingestion to orchestration."""

    repo_name: str
    root_path: str
    files: list[FileMetadata] = []
    classes: list[ClassInfo] = []
    methods: list[MethodInfo] = []
    calls: list[CallInfo] = []
    imports: list[ImportInfo] = []
    entry_points: list[EntryPointInfo] = []
    total_loc: int = 0
    total_methods: int = 0
    total_classes: int = 0
