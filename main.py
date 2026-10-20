import argparse
import base64
import json
import os

import requests

from merkle_proof import (
    DefaultHasher,
    compute_leaf_hash,
    verify_consistency,
    verify_inclusion,
)
from util import extract_public_key, verify_artifact_signature


def get_log_entry(log_index, debug=False):
    if isinstance(log_index, bool) or not isinstance(log_index, int) or log_index < 0:
        raise ValueError("Log index must be a non-negative integer")

    endpoint = "https://rekor.sigstore.dev/api/v1/log/entries"
    response = requests.get(endpoint, params={"logIndex": log_index}, timeout=5)
    response.raise_for_status()
    data = response.json()

    entry = data[next(iter(data.keys()))]
    return entry


def get_verification_proof(entry):
    inclusion_proof = entry["verification"]["inclusionProof"]
    return (
        inclusion_proof["logIndex"],
        inclusion_proof["treeSize"],
        inclusion_proof["hashes"],
        inclusion_proof["rootHash"],
    )


def inclusion(log_index, artifact_filepath, debug=False):
    if isinstance(log_index, bool) or not isinstance(log_index, int) or log_index < 0:
        raise ValueError("Log index must be a non-negative integer")

    if not artifact_filepath or not os.path.isfile(artifact_filepath):
        raise ValueError("Artifact filepath must point to an existing file")

    # Fetch the entry once and reuse it throughout verification.
    entry = get_log_entry(log_index, debug)

    if "code" in entry:
        print(entry["code"])
        return

    body = json.loads(base64.b64decode(entry["body"]).decode())

    # Extract signature and certificate.
    spec_sig = body["spec"]["signature"]
    signature = base64.b64decode(spec_sig["content"])
    certificate = base64.b64decode(spec_sig["publicKey"]["content"])
    public_key = extract_public_key(certificate)

    # Verify the artifact's signature.
    verify_artifact_signature(signature, public_key, artifact_filepath)

    # Calculate the leaf hash and reuse the fetched entry's proof.
    leaf_hash = str(compute_leaf_hash(entry["body"]))

    inc_log_index, tree_size, hashes, root_hash = (
        get_verification_proof(entry)
    )

    verify_inclusion(
        DefaultHasher,
        inc_log_index,
        tree_size,
        leaf_hash,
        hashes,
        root_hash,
    )

    print("Offline verification successful")


def get_latest_checkpoint(debug=False):
    endpoint = "https://rekor.sigstore.dev/api/v1/log/"
    response = requests.get(endpoint, timeout=5)
    response.raise_for_status()
    return response.json()


def consistency(prev_checkpoint, debug=False):
    if not prev_checkpoint:
        print("prev checkpoint empty")
        return

    latest_checkpoint = get_latest_checkpoint()

    latest_size = latest_checkpoint["treeSize"]
    prev_size = prev_checkpoint["treeSize"]
    tree_id = prev_checkpoint["treeID"]
    latest_root = latest_checkpoint["rootHash"]
    prev_root = prev_checkpoint["rootHash"]

    url = (
        "https://rekor.sigstore.dev/api/v1/log/proof"
        f"?firstSize={prev_size}"
        f"&lastSize={latest_size}"
        f"&treeID={tree_id}"
    )

    response = requests.get(url, timeout=5)
    response.raise_for_status()
    proof = response.json()["hashes"]

    verify_consistency(
        DefaultHasher,
        prev_size,
        latest_size,
        proof,
        prev_root,
        latest_root,
    )

    print("Consistency verification successful")


def main():
    debug = False
    parser = argparse.ArgumentParser(description="Rekor Verifier")

    parser.add_argument(
        "-d", "--debug",
        help="Debug mode",
        action="store_true",
    )
    parser.add_argument(
        "-c", "--checkpoint",
        help="Obtain latest checkpoint from Rekor Server public instance",
        action="store_true",
    )
    parser.add_argument(
        "--inclusion",
        help="Verify inclusion of an entry using its log index",
        type=int,
    )
    parser.add_argument(
        "--artifact",
        help="Artifact filepath for verifying signature",
    )
    parser.add_argument(
        "--consistency",
        help="Verify consistency of a given checkpoint with the latest checkpoint",
        action="store_true",
    )
    parser.add_argument(
        "--tree-id",
        help="Tree ID for consistency proof",
    )
    parser.add_argument(
        "--tree-size",
        help="Tree size for consistency proof",
        type=int,
    )
    parser.add_argument(
        "--root-hash",
        help="Root hash for consistency proof",
    )

    args = parser.parse_args()

    if args.debug:
        debug = True
        print("enabled debug mode")

    if args.checkpoint:
        checkpoint = get_latest_checkpoint(debug)
        print(json.dumps(checkpoint, indent=4))

    # Explicitly check for None so log index 0 is valid.
    if args.inclusion is not None:
        if not args.artifact:
            parser.error("--artifact is required with --inclusion")
        inclusion(args.inclusion, args.artifact, debug)

    if args.consistency:
        if not args.tree_id:
            parser.error("--tree-id is required with --consistency")
        if args.tree_size is None:
            parser.error("--tree-size is required with --consistency")
        if args.tree_size < 0:
            parser.error("--tree-size must be non-negative")
        if not args.root_hash:
            parser.error("--root-hash is required with --consistency")

        prev_checkpoint = {
            "treeID": args.tree_id,
            "treeSize": args.tree_size,
            "rootHash": args.root_hash,
        }

        consistency(prev_checkpoint, debug)


if __name__ == "__main__":
    main()
