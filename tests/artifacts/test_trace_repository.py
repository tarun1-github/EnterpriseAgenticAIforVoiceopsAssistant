"""Tests for VoiceOps persistent trace artifact repository and manifest management."""

import gzip
import pytest
from pathlib import Path
from datetime import datetime

from app.artifacts.models import TraceManifest
from app.artifacts.manifest import save_manifest_to_file, load_manifest_from_file
from app.artifacts.repository import TraceArtifactRepository


@pytest.fixture
def temp_storage(tmp_path):
    """Provide a clean temporary storage workspace for testing."""
    storage_dir = tmp_path / "voiceops_traces"
    return storage_dir


@pytest.fixture
def repository(temp_storage):
    """Provide a TraceArtifactRepository initialized with temp_storage."""
    return TraceArtifactRepository(storage_dir=temp_storage)


class TestTraceManifest:
    """Test TraceManifest model serialization and properties."""

    def test_manifest_creation_and_dict(self):
        manifest = TraceManifest(
            request_id="req_001",
            node="10_197_206_141",
            original_filename="SDL001_100_000087.txt.gzo",
            normalized_filename="SDL001_100_000087.txt",
            cucm_timestamp="2026-09-20T12:00:00",
            trace_type="SDL_TRACE",
            original_extension=".gzo",
            raw_path="/path/to/raw",
            extracted_path="/path/to/extracted",
            raw_size=5000,
            extracted_size=5000,
            raw_sha256="abc123raw",
            extracted_sha256="abc123ext",
            collection_timestamp="2026-09-20T12:05:00",
            transfer_method="sftp_file_get",
            extraction_method="plain_copy_no_gunzip",
            validation_status="Validated",
        )

        d = manifest.to_dict()
        assert d["request_id"] == "req_001"
        assert d["original_filename"] == "SDL001_100_000087.txt.gzo"
        assert d["normalized_filename"] == "SDL001_100_000087.txt"
        assert d["raw_size"] == 5000
        assert d["validation_status"] == "Validated"

        reconstituted = TraceManifest.from_dict(d)
        assert reconstituted.request_id == manifest.request_id
        assert reconstituted.node == manifest.node
        assert reconstituted.original_filename == manifest.original_filename
        assert reconstituted.normalized_filename == manifest.normalized_filename
        assert reconstituted.raw_sha256 == manifest.raw_sha256
        assert reconstituted.extraction_method == manifest.extraction_method


class TestManifestFileIO:
    """Test saving and loading manifests to/from JSON."""

    def test_save_and_load_manifest(self, tmp_path):
        m_file = tmp_path / "manifests" / "req_002.json"
        manifest = TraceManifest(
            request_id="req_002",
            node="10_197_206_141",
            original_filename="test.txt",
            normalized_filename="test.txt",
            raw_size=100,
            extracted_size=100,
        )

        save_manifest_to_file(manifest, m_file)
        assert m_file.exists()

        loaded = load_manifest_from_file(m_file)
        assert loaded is not None
        assert loaded.request_id == "req_002"
        assert loaded.raw_size == 100

    def test_load_nonexistent_manifest(self, tmp_path):
        assert load_manifest_from_file(tmp_path / "nonexistent.json") is None


class TestTraceArtifactRepository:
    """Test TraceArtifactRepository storage layout, artifact processing, and queries."""

    def test_directory_structure_created(self, repository, temp_storage):
        assert (temp_storage / "raw").is_dir()
        assert (temp_storage / "extracted").is_dir()
        assert (temp_storage / "manifests").is_dir()

    def test_store_gzo_trace(self, repository):
        """Verify .gzo is stored raw and copied to .txt without gunzip."""
        raw_content = b"09/20/2026 12:00:00.123 | Cisco CallManager SDL trace log line 1\n"
        manifest = repository.process_and_store_artifact(
            request_id="req_gzo_1",
            node="10_197_206_141",
            filename="SDL001_100_000087.txt.gzo",
            raw_bytes=raw_content,
            cucm_timestamp="2026-09-20T12:00:00",
            trace_type="SDL_TRACE",
        )

        assert manifest.request_id == "req_gzo_1"
        assert manifest.original_filename == "SDL001_100_000087.txt.gzo"
        assert manifest.normalized_filename == "SDL001_100_000087.txt"
        assert manifest.extraction_method == "plain_copy_no_gunzip"
        assert manifest.raw_size == len(raw_content)
        assert manifest.extracted_size == len(raw_content)
        assert manifest.validation_status == "Validated"

        # Check file exists locally in expected structure
        raw_path = Path(manifest.raw_path)
        ext_path = Path(manifest.extracted_path)
        assert raw_path.exists()
        assert ext_path.exists()
        assert "raw" in raw_path.parts
        assert "extracted" in ext_path.parts
        assert "req_gzo_1" in raw_path.parts
        assert "req_gzo_1" in ext_path.parts

        # Read back
        assert repository.get_raw_bytes(manifest) == raw_content
        assert repository.get_extracted_text(manifest) == raw_content.decode("utf-8")

    def test_store_gz_trace(self, repository):
        """Verify .gz is stored raw and decompressed to .txt."""
        plain_text = b"Decompressed SDL trace content from gzip\n"
        gz_bytes = gzip.compress(plain_text)

        manifest = repository.process_and_store_artifact(
            request_id="req_gz_1",
            node="10_197_206_141",
            filename="SDL001_100_000050.txt.gz",
            raw_bytes=gz_bytes,
        )

        assert manifest.normalized_filename == "SDL001_100_000050.txt"
        assert manifest.extraction_method == "gzip_decompress"
        assert manifest.raw_size == len(gz_bytes)
        assert manifest.extracted_size == len(plain_text)
        assert repository.get_extracted_text(manifest) == plain_text.decode("utf-8")

    def test_store_txt_trace(self, repository):
        """Verify .txt is preserved and copied to extracted .txt."""
        txt_content = b"Plain text SDL trace\n"
        manifest = repository.process_and_store_artifact(
            request_id="req_txt_1",
            node="10_197_206_141",
            filename="SDL001_100_000010.txt",
            raw_bytes=txt_content,
        )

        assert manifest.normalized_filename == "SDL001_100_000010.txt"
        assert manifest.extraction_method == "plain_copy"
        assert manifest.raw_size == len(txt_content)
        assert manifest.extracted_size == len(txt_content)

    def test_reject_index_file(self, repository):
        """Verify .index metadata file is rejected from storage."""
        with pytest.raises(ValueError, match="Cannot store .index metadata file"):
            repository.process_and_store_artifact(
                request_id="req_idx_1",
                node="10_197_206_141",
                filename="SDL001_100.index",
                raw_bytes=b"metadata",
            )

    def test_reconstruct_inventory_after_restart(self, temp_storage):
        """Verify scanning manifests reconstructs inventory without running CUCM discovery."""
        # Session 1: Create repository and store 2 files
        repo1 = TraceArtifactRepository(storage_dir=temp_storage)
        repo1.process_and_store_artifact(
            request_id="req_inv_1",
            node="10_197_206_141",
            filename="SDL001_100_000087.txt.gzo",
            raw_bytes=b"trace 1",
        )
        repo1.process_and_store_artifact(
            request_id="req_inv_2",
            node="10_197_206_141",
            filename="SDL001_100_000086.txt.gzo",
            raw_bytes=b"trace 2",
        )

        # Session 2: Fresh repository instance simulating application startup
        repo2 = TraceArtifactRepository(storage_dir=temp_storage)
        manifests = repo2.list_manifests()

        assert len(manifests) == 2
        req_ids = {m.request_id for m in manifests}
        assert req_ids == {"req_inv_1", "req_inv_2"}

    def test_delete_trace(self, repository):
        """Verify deleting a trace cleans up raw, extracted, and manifest files."""
        manifest = repository.process_and_store_artifact(
            request_id="req_del_1",
            node="10_197_206_141",
            filename="SDL001_100_000099.txt.gzo",
            raw_bytes=b"to be deleted",
        )

        raw_path = Path(manifest.raw_path)
        ext_path = Path(manifest.extracted_path)
        manifest_path = repository.get_manifest_path(manifest.request_id)

        assert raw_path.exists()
        assert ext_path.exists()
        assert manifest_path.exists()

        success = repository.delete_trace(manifest.request_id)
        assert success is True

        assert not raw_path.exists()
        assert not ext_path.exists()
        assert not manifest_path.exists()
        assert repository.load_manifest(manifest.request_id) is None

    def test_generate_trace_export_text(self, repository):
        """Verify trace export formats header without modifying canonical file."""
        manifest = repository.process_and_store_artifact(
            request_id="req_export_1",
            node="10_197_206_141",
            filename="SDL001_100_000087.txt.gzo",
            raw_bytes=b"Original raw trace data line\n",
            cucm_timestamp="2026-09-20 12:45:00",
        )

        export_text = repository.generate_trace_export_text(manifest, download_timestamp="2026-09-20 16:45:32 IST")

        assert "VoiceOps AI - CUCM Trace Evidence" in export_text
        assert "Device IP   : 10.197.206.141" in export_text
        assert "Node        : 10.197.206.141" in export_text
        assert "CUCM File   : SDL001_100_000087.txt.gzo" in export_text
        assert "Normalized  : SDL001_100_000087.txt" in export_text
        assert "CUCM Time   : 2026-09-20 12:45:00" in export_text
        assert "Downloaded  : 2026-09-20 16:45:32 IST" in export_text
        assert f"SHA256      : {manifest.extracted_sha256}" in export_text
        assert "TRACE\n=====\n\nOriginal raw trace data line" in export_text

        # Ensure canonical on-disk extracted file is untouched
        canonical_content = Path(manifest.extracted_path).read_text()
        assert canonical_content == "Original raw trace data line\n"
        assert "VoiceOps AI - CUCM Trace Evidence" not in canonical_content

