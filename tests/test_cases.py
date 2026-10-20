import base64
import json
import pytest
from unittest.mock import patch, MagicMock

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography import x509
from cryptography.x509.oid import NameOID
import datetime

import util
import merkle_proof
from merkle_proof import DefaultHasher, RootMismatchError
import main


# Helper fixture to generate test ECDSA key pair and self-signed cert
@pytest.fixture
def cert_and_key():
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u"test.example.com"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1))
        .sign(private_key, hashes.SHA256())
    )

    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    pub_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    return cert_pem, pub_key_pem, private_key


# Test 1: util.py - extract_public_key
def test_extract_public_key(cert_and_key):
    cert_pem, pub_key_pem, _ = cert_and_key
    extracted_key = util.extract_public_key(cert_pem)
    assert extracted_key == pub_key_pem


# Test 2: util.py - verify_artifact_signature
def test_verify_artifact_signature(tmp_path, cert_and_key):
    cert_pem, pub_key_pem, private_key = cert_and_key

    # Create dummy artifact file
    artifact_path = tmp_path / "test_artifact.txt"
    data = b"hello world artifact content"
    artifact_path.write_bytes(data)

    # Sign data using private key
    signature = private_key.sign(data, ec.ECDSA(hashes.SHA256()))

    # Should execute without throwing unhandled exceptions
    util.verify_artifact_signature(signature, pub_key_pem, str(artifact_path))


# Test 3: merkle_proof.py - compute_leaf_hash
def test_compute_leaf_hash():
    raw_bytes = b"sample leaf payload"
    encoded_body = base64.b64encode(raw_bytes).decode('utf-8')
    
    leaf_hash = merkle_proof.compute_leaf_hash(encoded_body)
    assert isinstance(leaf_hash, str)
    assert len(leaf_hash) == 64  # SHA256 hex string length


# Test 4: merkle_proof.py - Hasher basic functions
def test_hasher_methods():
    hasher = DefaultHasher
    assert hasher.size() == 32
    leaf_h = hasher.hash_leaf(b"test")
    node_h = hasher.hash_children(leaf_h, leaf_h)
    assert len(leaf_h) == 32
    assert len(node_h) == 32


# Test 5: merkle_proof.py - verify_inclusion success
def test_verify_inclusion_success():
    hasher = DefaultHasher
    leaf_bytes = b"leaf payload"
    leaf_hash = hasher.hash_leaf(leaf_bytes).hex()

    # Tree size 1 inclusion proof
    proof = []
    root_hash = hasher.hash_leaf(leaf_bytes).hex()

    merkle_proof.verify_inclusion(hasher, 0, 1, leaf_hash, proof, root_hash, debug=True)


# Test 6: merkle_proof.py - verify_inclusion index out of bounds exception
def test_verify_inclusion_out_of_bounds():
    hasher = DefaultHasher
    with pytest.raises(ValueError, match="index is beyond size"):
        merkle_proof.verify_inclusion(hasher, 2, 1, "aa" * 32, [], "aa" * 32)


# Test 7: merkle_proof.py - verify_consistency validation errors
def test_verify_consistency_errors():
    hasher = DefaultHasher
    # size2 < size1
    with pytest.raises(ValueError, match="size2"):
        merkle_proof.verify_consistency(hasher, 5, 2, [], "aa" * 32, "bb" * 32)

    # size1 == size2 with non-empty proof
    with pytest.raises(ValueError, match="size1=size2"):
        merkle_proof.verify_consistency(hasher, 2, 2, ["cc" * 32], "aa" * 32, "aa" * 32)


# Test 8: merkle_proof.py - RootMismatchError formatting
def test_root_mismatch_error():
    err = RootMismatchError(b"expected", b"calculated")
    assert "does not match expected root" in str(err)


# Test 9: main.py - get_log_entry validation
def test_get_log_entry_invalid_index():
    with pytest.raises(ValueError, match="Log index must be a non-negative integer"):
        main.get_log_entry(-1)

    with pytest.raises(ValueError, match="Log index must be a non-negative integer"):
        main.get_log_entry(True)


# Test 10: main.py - get_latest_checkpoint with mock HTTP
@patch("requests.get")
def test_get_latest_checkpoint(mock_get):
    mock_resp = MagicMock()
    mock_resp.json.return_value = {"treeSize": 100, "rootHash": "abcd"}
    mock_get.return_value = mock_resp

    checkpoint = main.get_latest_checkpoint()
    assert checkpoint["treeSize"] == 100
    assert checkpoint["rootHash"] == "abcd"


# Test 11: main.py - inclusion input validation
def test_inclusion_invalid_args(tmp_path):
    with pytest.raises(ValueError, match="Log index must be a non-negative integer"):
        main.inclusion(-1, "nonexistent.file")

    with pytest.raises(ValueError, match="Artifact filepath must point to an existing file"):
        main.inclusion(0, "nonexistent.file")


# Test 12: main.py - consistency with empty checkpoint
def test_consistency_empty_checkpoint(capsys):
    main.consistency(None)
    captured = capsys.readouterr()
    assert "prev checkpoint empty" in captured.out


# Test 13: main.py - consistency success with mock HTTP
@patch("requests.get")
def test_consistency_success(mock_get, capsys):
    mock_resp = MagicMock()
    # Mock return values for get_latest_checkpoint and proof endpoint
    mock_resp.json.side_effect = [
        {"treeSize": 2, "rootHash": "00" * 32, "treeID": "123"},
        {"hashes": []}
    ]
    mock_get.return_value = mock_resp

    prev_checkpoint = {
        "treeID": "123",
        "treeSize": 2,
        "rootHash": "00" * 32
    }

    main.consistency(prev_checkpoint)
    captured = capsys.readouterr()
    assert "Consistency verification successful" in captured.out

    # Test 14: util.py - verify_artifact_signature with invalid signature
def test_verify_artifact_signature_invalid(tmp_path, cert_and_key):
    _, pub_key_pem, _ = cert_and_key
    artifact_path = tmp_path / "test_artifact.txt"
    artifact_path.write_bytes(b"some data")

    # Pass dummy/corrupted signature
    invalid_signature = b"invalid_signature_bytes"
    
    # Should catch InvalidSignature internally and print without raising exception
    util.verify_artifact_signature(invalid_signature, pub_key_pem, str(artifact_path))


# Test 15: main.py - full inclusion workflow mock
@patch("main.get_log_entry")
@patch("main.verify_artifact_signature")
@patch("main.verify_inclusion")
def test_inclusion_full_flow(mock_verify_inc, mock_verify_sig, mock_get_entry, tmp_path, cert_and_key):
    cert_pem, _, _ = cert_and_key
    artifact_path = tmp_path / "test_artifact.txt"
    artifact_path.write_bytes(b"content")

    # Mock entry structure matching Rekor API response format
    spec_body = {
        "spec": {
            "signature": {
                "content": base64.b64encode(b"sig").decode(),
                "publicKey": {"content": base64.b64encode(cert_pem).decode()}
            }
        }
    }
    raw_body = json.dumps(spec_body).encode()
    
    mock_get_entry.return_value = {
        "body": base64.b64encode(raw_body).decode(),
        "verification": {
            "inclusionProof": {
                "logIndex": 0,
                "treeSize": 1,
                "hashes": [],
                "rootHash": "00" * 32
            }
        }
    }

    main.inclusion(0, str(artifact_path))
    assert mock_verify_sig.called
    assert mock_verify_inc.called


# Test 16: main.py - inclusion entry code field branch
@patch("main.get_log_entry")
def test_inclusion_entry_code_error(mock_get_entry, tmp_path, capsys):
    artifact_path = tmp_path / "test.txt"
    artifact_path.write_bytes(b"data")
    mock_get_entry.return_value = {"code": "ENTRY_NOT_FOUND"}

    main.inclusion(0, str(artifact_path))
    captured = capsys.readouterr()
    assert "ENTRY_NOT_FOUND" in captured.out


# Test 17: main.py - CLI entry point main()
@patch("sys.argv", ["main.py", "-c"])
@patch("main.get_latest_checkpoint")
def test_main_cli_checkpoint(mock_checkpoint):
    mock_checkpoint.return_value = {"treeSize": 10}
    main.main()
    assert mock_checkpoint.called