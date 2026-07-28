"""Tests for ingest path skipping (e.g. Go pkg/)."""
import os
import tempfile

from dpdp_scanner.ingestor import _walk_files, _active_skip_file_patterns


def test_pkg_directory_not_skipped_go_file_indexed():
    with tempfile.TemporaryDirectory() as tmp:
        pkg_dir = os.path.join(tmp, "pkg", "api")
        os.makedirs(pkg_dir, exist_ok=True)
        go_file = os.path.join(pkg_dir, "handler.go")
        with open(go_file, "w", encoding="utf-8") as f:
            f.write("package api\n\nfunc Hello() {}\n")

        patterns = _active_skip_file_patterns(include_test_files=False)
        files = _walk_files(tmp, patterns)
        rels = {f["path"].replace("\\", "/") for f in files}
        assert "pkg/api/handler.go" in rels
