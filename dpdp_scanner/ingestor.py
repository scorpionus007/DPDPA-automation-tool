"""
Ingestor module.

Responsible for fetching and preparing repository files for analysis.
"""

from __future__ import annotations

import os
import re
import shutil
import tempfile
import time
from typing import Dict, List, Pattern, Tuple

from git import GitCommandError, Repo
from rich.console import Console


console = Console()


SKIP_DIRS = {
    "node_modules",
    ".git",
    "venv",
    ".venv",
    "env",
    "__pycache__",
    "dist",
    "build",
    ".idea",
    ".vscode",
    "vendor",
    "target",
    "Pods",
    ".gradle",
    "bin",
    "obj",
    # "pkg" omitted on purpose — Go projects commonly store library source under pkg/.
    "deps",
    "coverage",
    ".bundle",
    "__tests__",
    "spec",
    "test",
    "tests",
    ".yarn",
    ".pnp",
    "assets",
    "storage",
    "locale",
    "locales",
    "i18n",
    "docs",
    "doc",
    "log",
    "logs",
    "tmp",
    "temp",
}

SKIP_FILES = {
    "yarn.lock",
    "package-lock.json",
    "pnpm-lock.yaml",
    "Gemfile.lock",
    "Cargo.lock",
    "composer.lock",
    "Pipfile.lock",
    "poetry.lock",
    "yarn-4.6.0.cjs",
    "yarn-3.6.4.cjs",
}

# Patterns always applied (minified, lockfiles, etc.)
_SKIP_FILE_PATTERNS_CORE: List[Pattern[str]] = [
    re.compile(r"yarn-\d+\.\d+\.\d+\.cjs$", re.IGNORECASE),
    re.compile(r"\.min\.js$", re.IGNORECASE),
    re.compile(r"\.min\.css$", re.IGNORECASE),
    re.compile(r"\.bundle\.js$", re.IGNORECASE),
    re.compile(r"\.chunk\.js$", re.IGNORECASE),
    re.compile(r"-lock\.\w+$", re.IGNORECASE),
    re.compile(r"\.generated\.\w+$", re.IGNORECASE),
]

# Optional: omit when include_test_files or DPDP_INCLUDE_TESTS=1
_SKIP_FILE_PATTERNS_TEST_ONLY: List[Pattern[str]] = [
    re.compile(r"_test\.go$", re.IGNORECASE),
    re.compile(r"_spec\.rb$", re.IGNORECASE),
]

# Backward compatibility for imports
SKIP_FILE_PATTERNS = _SKIP_FILE_PATTERNS_CORE + _SKIP_FILE_PATTERNS_TEST_ONLY


def _active_skip_file_patterns(include_test_files: bool) -> List[Pattern[str]]:
    if include_test_files:
        return list(_SKIP_FILE_PATTERNS_CORE)
    return list(_SKIP_FILE_PATTERNS_CORE) + list(_SKIP_FILE_PATTERNS_TEST_ONLY)


def _env_include_tests() -> bool:
    v = os.environ.get("DPDP_INCLUDE_TESTS", "").strip().lower()
    return v in ("1", "true", "yes", "on")


EXTENSION_LANGUAGE_MAP = {
    ".py": "python",
    ".js": "javascript",
    ".ts": "typescript",
    ".java": "java",
    ".go": "go",
    ".rb": "ruby",
    ".php": "php",
    ".cs": "csharp",
    ".kt": "kotlin",
    ".kts": "kotlin",
    ".rs": "rust",
    ".swift": "swift",
    ".scala": "scala",
    ".jsx": "javascript",
    ".tsx": "typescript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".vue": "javascript",
    ".svelte": "javascript",
    ".sql": "sql",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".toml": "toml",
}


def _clean_path(path: str) -> str:
    """Remove Jinja/cookiecutter template placeholders from paths."""
    cleaned = re.sub(r"\{\{[^}]+\}\}", "[template]", path)
    return cleaned


def _clone_repo(target: str, token: str | None = None) -> str:
    """
    Clone a remote Git URL to a temporary directory.

    Supports private GitHub repos via token injection and mitigates flaky networks
    (curl 56 / early EOF) via shallow clone, HTTP tuning, and retries.

    Env:
    - DPDP_GIT_CLONE_RETRIES: attempts (default 3)
    - DPDP_GIT_CLONE_DEPTH: history depth; 0 = full clone (default 1)
    """
    clone_url = target
    if token and "github.com" in target and target.startswith("https://") and "@" not in target:
        clone_url = target.replace("https://", f"https://{token}@")

    retries = max(1, int(os.getenv("DPDP_GIT_CLONE_RETRIES", "3")))
    depth_raw = os.getenv("DPDP_GIT_CLONE_DEPTH", "1").strip()
    try:
        depth = int(depth_raw) if depth_raw else 1
    except ValueError:
        depth = 1

    multi_options: List[str] = [
        "-c",
        "http.postBuffer=524288000",
        "-c",
        "http.version=HTTP/1.1",
    ]
    if depth > 0:
        multi_options.extend(["--depth", str(depth)])

    for attempt in range(retries):
        temp_dir = tempfile.mkdtemp()
        env_vars = os.environ.copy()
        env_vars.update(
            {
                "GIT_TERMINAL_PROMPT": "0",
                "GIT_ASKPASS": "echo",
                "GCM_INTERACTIVE": "never",
                "GCM_PROVIDER": "empty",
            }
        )
        try:
            Repo.clone_from(
                clone_url,
                temp_dir,
                env=env_vars,
                multi_options=multi_options,
                config="credential.helper=",
                allow_unsafe_options=True,
            )
            if attempt > 0:
                console.print(f"[green]Clone succeeded on attempt {attempt + 1}/{retries}[/green]")
            return temp_dir
        except GitCommandError as exc:
            shutil.rmtree(temp_dir, ignore_errors=True)
            err_txt = str(exc).lower()
            transient = any(
                x in err_txt
                for x in (
                    "rpc failed",
                    "recv failure",
                    "connection was reset",
                    "early eof",
                    "invalid index-pack",
                    "unexpected disconnect",
                    "couldn't connect",
                    "timed out",
                    "empty reply",
                )
            )
            if attempt < retries - 1 and transient:
                wait_s = 2**attempt
                console.print(
                    f"[yellow]Git clone failed ({attempt + 1}/{retries}), "
                    f"retrying in {wait_s}s…[/yellow]"
                )
                time.sleep(wait_s)
                continue
            err_msg = str(exc)
            if token:
                err_msg = err_msg.replace(token, "********")
            msg = f"Failed to clone repository from '{target}'. Git error: {err_msg}"
            console.print(f"[red bold]Error:[/red bold] {msg}")
            raise Exception(msg) from exc
        except Exception as exc:  # pragma: no cover - defensive
            shutil.rmtree(temp_dir, ignore_errors=True)
            msg = f"Unexpected error while cloning '{target}': {exc}"
            console.print(f"[red bold]Error:[/red bold] {msg}")
            raise Exception(msg) from exc

    raise RuntimeError(f"clone loop exited unexpectedly for '{target}'")


def _resolve_root(target: str, token: str | None = None) -> str:
    """
    Resolve the repository root directory from the target.

    :param target: GitHub URL or local path.
    :param token: Optional GitHub token.
    :return: Filesystem path to repository root.
    """
    if target.startswith("https://") or target.startswith("git@") or target.endswith(".git"):
        # Treat as GitHub/Git URL
        return _clone_repo(target, token=token)

    # Treat as local directory path
    if not os.path.exists(target):
        console.print(
            f"[red bold]Error:[/red bold] Target path does not exist: '{target}'"
        )
        raise Exception(f"Target path does not exist: '{target}'")

    if not os.path.isdir(target):
        console.print(
            f"[red bold]Error:[/red bold] Target is not a directory: '{target}'"
        )
        raise Exception(f"Target is not a directory: '{target}'")

    return os.path.abspath(target)


def _walk_files(root_dir: str, skip_file_patterns: List[Pattern[str]]) -> Tuple[List[Dict], List[Dict]]:
    """Walk repo directory and return (repo_files, skipped_files)."""
    repo_files: List[Dict[str, str]] = []
    skipped_files: List[Dict[str, str]] = []

    for dirpath, dirnames, filenames in os.walk(root_dir):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]

        for filename in filenames:
            if filename == "Gemfile.lock":
                continue
            if filename in SKIP_FILES:
                continue
            full_path = os.path.join(dirpath, filename)
            normalized_path = full_path.replace("\\", "/")
            if any(pat.search(normalized_path) for pat in skip_file_patterns):
                continue
            rel_path = os.path.relpath(full_path, root_dir).replace(os.sep, "/")
            try:
                fsize = os.path.getsize(full_path)
                if fsize > 500_000:
                    skipped_files.append({"path": rel_path, "reason": "size", "detail": f"{fsize} bytes"})
                    continue
            except OSError:
                continue
            ext = os.path.splitext(filename)[1].lower()
            if ext not in EXTENSION_LANGUAGE_MAP:
                continue
            if any(f"/{skip}/" in normalized_path for skip in SKIP_DIRS):
                continue

            content = None
            try:
                with open(full_path, "r", encoding="utf-8") as f:
                    content = f.read()
            except UnicodeDecodeError:
                try:
                    with open(full_path, "r", encoding="latin-1") as f:
                        content = f.read()
                except Exception:
                    skipped_files.append({"path": rel_path, "reason": "encoding"})
                    continue

            if content is None:
                continue

            language = EXTENSION_LANGUAGE_MAP.get(ext)
            if not language:
                continue

            file_dict = {
                "path": rel_path,
                "content": content,
                "language": language,
            }
            file_dict["display_path"] = _clean_path(rel_path)
            repo_files.append(file_dict)

    return repo_files, skipped_files


def ingest(
    target: str,
    include_test_files: bool = False,
    github_token: str | None = None,
) -> Tuple[List[Dict], str]:
    """
    Ingest the target repository or path.

    :param target: GitHub URL or local path to scan.
    :param include_test_files: If True, include *_test.go and *_spec.rb. Also set
        DPDP_INCLUDE_TESTS=1 (or true/yes/on) to enable without the CLI flag.
    :param github_token: Optional GitHub token for private repositories.
    :return: (repo_files, repo_path) where repo_files is a list of file dicts,
             repo_path is the path to the cloned or local repo root (for git commands).
             repo_files[0] may contain a "_skipped_files" metadata entry.
    """
    include_tests = bool(include_test_files) or _env_include_tests()
    root_dir = _resolve_root(target, token=github_token)
    patterns = _active_skip_file_patterns(include_tests)
    repo_files, skipped_files = _walk_files(root_dir, patterns)
    if skipped_files:
        repo_files.append({"_skipped_files": skipped_files})
    return repo_files, root_dir
