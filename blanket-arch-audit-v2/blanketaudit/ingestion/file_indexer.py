"""File metadata indexing — walk a repo, classify files, compute metadata.

Design doc §2.1 Tier 2: file metadata indexing.
"""
from __future__ import annotations

import hashlib
import os
from datetime import datetime, timezone
from pathlib import Path

import structlog
from pathspec import PathSpec

from blanketaudit.ingestion.models import FileMetadata, FileType

logger = structlog.get_logger()

# Directories to always skip
SKIP_DIRS: set[str] = {
    ".git", "node_modules", "vendor", "__pycache__", ".venv", "venv",
    "build", "dist", ".next", ".nuxt", "target", "bin", "obj",
    ".mypy_cache", ".pytest_cache", ".ruff_cache", ".tox",
    "coverage", ".coverage", "htmlcov",
}

# Binary / non-text extensions to skip
BINARY_EXTENSIONS: set[str] = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".webp",
    ".woff", ".woff2", ".ttf", ".eot",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx",
    ".zip", ".tar", ".gz", ".bz2", ".7z", ".rar",
    ".exe", ".dll", ".so", ".dylib", ".o", ".a",
    ".pyc", ".pyo", ".class", ".jar", ".war",
    ".db", ".sqlite", ".sqlite3",
    ".mp3", ".mp4", ".avi", ".mov", ".wav",
}

# Extension → language mapping
EXTENSION_TO_LANGUAGE: dict[str, str] = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".java": "java",
    ".go": "go",
    ".rs": "rust",
    ".cs": "csharp",
    ".rb": "ruby",
    ".php": "php",
    ".swift": "swift",
    ".kt": "kotlin",
    ".scala": "scala",
    ".c": "c",
    ".cpp": "cpp",
    ".h": "c",
    ".hpp": "cpp",
    ".sql": "sql",
    ".sh": "shell",
    ".bash": "shell",
    ".ps1": "powershell",
}

# Extension → FileType for non-source files
EXTENSION_TO_FILE_TYPE: dict[str, FileType] = {
    ".yaml": FileType.CONFIG,
    ".yml": FileType.CONFIG,
    ".json": FileType.CONFIG,
    ".toml": FileType.CONFIG,
    ".ini": FileType.CONFIG,
    ".cfg": FileType.CONFIG,
    ".env": FileType.CONFIG,
    ".tf": FileType.IAC,
    ".hcl": FileType.IAC,
    ".md": FileType.DOC,
    ".rst": FileType.DOC,
    ".txt": FileType.DOC,
}

# Filename patterns for special file types
FILENAME_TO_FILE_TYPE: dict[str, FileType] = {
    "Dockerfile": FileType.IAC,
    "docker-compose.yml": FileType.IAC,
    "docker-compose.yaml": FileType.IAC,
    "Makefile": FileType.BUILD,
    "Rakefile": FileType.BUILD,
    "Jenkinsfile": FileType.CICD,
    ".gitlab-ci.yml": FileType.CICD,
}


def _classify_file_type(path: Path) -> FileType:
    """Classify a file into a FileType based on name and extension."""
    name = path.name

    # Check exact filename matches first
    if name in FILENAME_TO_FILE_TYPE:
        return FILENAME_TO_FILE_TYPE[name]

    # GitHub Actions
    parts = path.parts
    if ".github" in parts and "workflows" in parts and name.endswith((".yml", ".yaml")):
        return FileType.CICD

    # Kubernetes manifests (heuristic: yaml with apiVersion)
    # We can't read content here cheaply, so classify k8s by path patterns
    lower_parts = [p.lower() for p in parts]
    if any(k in lower_parts for k in ("k8s", "kubernetes", "helm", "charts")):
        if path.suffix in (".yaml", ".yml"):
            return FileType.IAC

    # Test files
    if name.startswith("test_") or name.endswith("_test.py") or name.endswith(".test.ts") or name.endswith(".test.js") or name.endswith("Test.java") or "tests" in parts or "__tests__" in parts:
        return FileType.TEST

    # Extension-based classification
    if path.suffix in EXTENSION_TO_FILE_TYPE:
        return EXTENSION_TO_FILE_TYPE[path.suffix]

    # Build files
    if name in ("pom.xml", "build.gradle", "build.gradle.kts", "CMakeLists.txt", "setup.py", "setup.cfg", "pyproject.toml", "package.json", "Cargo.toml", "go.mod"):
        return FileType.BUILD

    # Source code
    if path.suffix in EXTENSION_TO_LANGUAGE:
        return FileType.SOURCE

    return FileType.OTHER


def _detect_language(path: Path) -> str:
    """Detect programming language from file extension."""
    return EXTENSION_TO_LANGUAGE.get(path.suffix, "")


def _count_lines(file_path: Path) -> int:
    """Count lines in a text file. Return 0 on error."""
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            return sum(1 for _ in f)
    except (OSError, UnicodeDecodeError):
        return 0


def _compute_sha256(file_path: Path) -> str:
    """Compute SHA-256 of file content."""
    h = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
    except OSError:
        return ""
    return h.hexdigest()


def _load_ignore_spec(repo_path: Path) -> PathSpec | None:
    """Load .gitignore + .blanketauditignore patterns."""
    patterns: list[str] = []
    for ignore_file in (".gitignore", ".blanketauditignore"):
        p = repo_path / ignore_file
        if p.exists():
            try:
                patterns.extend(p.read_text(encoding="utf-8", errors="replace").splitlines())
            except OSError:
                pass
    if patterns:
        return PathSpec.from_lines("gitwildmatch", patterns)
    return None


class FileIndexer:
    """Walk a repository and compute metadata for each file."""

    def index_project(self, repo_path: Path, repo_name: str) -> list[FileMetadata]:
        """Walk *repo_path*, classify files, compute metadata.

        Respects .gitignore and .blanketauditignore.
        Skips: binaries, node_modules, vendor, __pycache__, .git, etc.
        """
        repo_path = Path(repo_path)
        if not repo_path.is_dir():
            logger.warning("file_indexer.not_a_directory", path=str(repo_path))
            return []

        ignore_spec = _load_ignore_spec(repo_path)
        results: list[FileMetadata] = []

        for root, dirs, files in os.walk(repo_path):
            # Prune skip directories (in-place mutation of dirs)
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]

            root_path = Path(root)
            for fname in files:
                file_path = root_path / fname
                rel_path = file_path.relative_to(repo_path)
                rel_str = str(rel_path).replace("\\", "/")

                # Skip binary extensions
                if file_path.suffix.lower() in BINARY_EXTENSIONS:
                    continue

                # Skip ignored files
                if ignore_spec and ignore_spec.match_file(rel_str):
                    continue

                language = _detect_language(file_path)
                file_type = _classify_file_type(rel_path)
                loc = _count_lines(file_path)

                try:
                    stat = file_path.stat()
                    size_bytes = stat.st_size
                    last_modified = datetime.fromtimestamp(
                        stat.st_mtime, tz=timezone.utc
                    ).isoformat()
                except OSError:
                    size_bytes = 0
                    last_modified = ""

                content_sha256 = _compute_sha256(file_path)

                results.append(FileMetadata(
                    path=rel_str,
                    repo_name=repo_name,
                    language=language,
                    loc=loc,
                    file_type=file_type,
                    content_sha256=content_sha256,
                    size_bytes=size_bytes,
                    last_modified=last_modified,
                ))

        logger.info(
            "file_indexer.indexed",
            repo_name=repo_name,
            file_count=len(results),
            total_loc=sum(f.loc for f in results),
        )
        return results
