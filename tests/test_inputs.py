"""Tests for CBOM and SARIF parsers."""
import json
import tempfile
from pathlib import Path
import pytest
from pqc_sandbox.inputs.cbom import parse_cbom
from pqc_sandbox.inputs.sarif import parse_sarif


_SAMPLE_CBOM = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.6",
    "components": [
        {
            "name": "auth-service",
            "version": "1.0",
            "algorithm": "ECDSA",
            "cryptoProperties": {
                "algorithmProperties": {"primitive": "signature", "curve": "P-256"}
            },
        },
        {
            "name": "key-exchange",
            "version": "1.0",
            "algorithm": "ECDH",
            "cryptoProperties": {
                "algorithmProperties": {"primitive": "KE"}
            },
        },
    ],
}

_SAMPLE_SARIF = {
    "version": "2.1.0",
    "runs": [
        {
            "tool": {"driver": {"name": "TestScanner", "rules": []}},
            "results": [
                {
                    "ruleId": "CRYPTO001",
                    "message": {"text": "RSA-2048 usage detected"},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": "src/main.py"},
                                "region": {"startLine": 10},
                            }
                        }
                    ],
                }
            ],
        }
    ],
}


def test_parse_cbom():
    with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as f:
        json.dump(_SAMPLE_CBOM, f)
        name = f.name
    result = parse_cbom(name)
    assert len(result.components) == 2
    assert result.components[0].detected_classical in ("ECDSA-P256", "ECDH-P256", "ECDSA")
    assert result.components[0].recommended_pqc


def test_parse_sarif():
    with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as f:
        json.dump(_SAMPLE_SARIF, f)
        name = f.name
    result = parse_sarif(name)
    assert result.tool_name == "TestScanner"
    assert len(result.findings) == 1
    assert "rsa" in result.findings[0].detected_algorithm.lower() or \
           result.findings[0].detected_algorithm in ("RSA-2048 (PKCS#1 v1.5)", "ECDSA-P256")


def test_cbom_sample_file():
    sample = Path(__file__).parent.parent / "assets" / "sample.cbom.json"
    result = parse_cbom(sample)
    assert len(result.components) == 3
    assert result.unique_algorithms


def test_sarif_sample_file():
    sample = Path(__file__).parent.parent / "assets" / "sample.sarif.json"
    result = parse_sarif(sample)
    assert result.tool_name == "CryptoScan"
    assert len(result.findings) == 2
