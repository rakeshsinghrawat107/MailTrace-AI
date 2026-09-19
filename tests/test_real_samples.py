"""
MailTrace.AI - Real-World Dataset Validation Suite
Verifies forensic micro-engines directly against user dataset in backend/samples/1/
"""
import pytest
from pathlib import Path
from backend.app.core.config import SAMPLES_DIR
from backend.app.api.routes import execute_full_forensics

def test_real_dataset_samples():
    assert SAMPLES_DIR.exists() and SAMPLES_DIR.is_dir()
    sample_files = list(SAMPLES_DIR.glob("*.eml"))
    assert len(sample_files) > 0, "Real sample dataset backend/samples/1/ must contain .eml files"

    # Select 5 random/distinct samples to verify end-to-end processing
    test_batch = sample_files[:5]
    
    for sample_path in test_batch:
        raw_bytes = sample_path.read_bytes()
        assert len(raw_bytes) > 0
        
        result = execute_full_forensics(raw_bytes, sample_path.name)
        assert "case_id" in result
        assert len(result["evidence_sha256"]) == 64
        assert 0.0 <= result["fraud_score"] <= 100.0
        assert result["risk_tier"] in ("BENIGN", "SUSPICIOUS", "MALICIOUS", "CRITICAL")
        assert len(result["vector_32d"]) == 32
        assert "headers" in result
        assert "hops" in result
        assert "sub_scores" in result
