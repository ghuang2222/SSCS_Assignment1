import argparse
from util import extract_public_key, verify_artifact_signature
from merkle_proof import DefaultHasher, verify_consistency, verify_inclusion, compute_leaf_hash
import requests
import json
import base64

def get_log_entry(log_index, debug=False):
    # TODO: verify that log index value is sane
    endpoint = "https://rekor.sigstore.dev/api/v1/log/entries"
    response = requests.get(endpoint + "?logIndex=" + str(log_index)).json()
    response.raise_for_status()
    entry = response[list(response.keys())[0]]    
    return entry

def get_verification_proof(log_index, debug=False):
    # TODO: verify that log index value is sane
    entry = get_log_entry(log_index)  
    verif = entry["verification"]
    inclusion_proof = verif["inclusionProof"]
    return inclusion_proof["logIndex"], inclusion_proof["treeSize"], \
            inclusion_proof["hashes"],inclusion_proof["rootHash"]

def inclusion(log_index, artifact_filepath, debug=False):
    # TODO
    # verify that log index and artifact filepath values are sane
    
    #verify log index sanity
    entry = get_log_entry(log_index, debug)
    
    #print(entry)
    if "code" in entry:
        print(entry["code"])
        return 
    else:
        body = entry["body"]
        body = json.loads(base64.b64decode(body).decode())
        #print(body.keys())
        #print(body) 
        #print("Valid log index")
    
    #verify artifact filepath sanity
    try:
        file = open(artifact_filepath, 'r')
        #print("Valid artifact filepath")
    except Exception as e:
        raise(e)
    finally:
        file.close()

    # extract signature and certificate

    spec_sig = body['spec']['signature']
    signature = base64.b64decode(spec_sig["content"])
    #print("signature: ", signature)
    certificate = base64.b64decode(spec_sig["publicKey"]["content"])
    #print("certificate: ", certificate)
    public_key = extract_public_key(certificate)
    verify_artifact_signature(signature, public_key, artifact_filepath)
    
    body = entry["body"]
    leaf_hash = compute_leaf_hash(entry["body"])
    leaf_hash = str(leaf_hash)
    #print("leaf_hash: ", leaf_hash)
    inc_log_index, tree_size, hashes, root_hash = get_verification_proof(log_index)
    verify_inclusion(DefaultHasher, inc_log_index, tree_size, leaf_hash, hashes, root_hash)
    print("Offline verification successful")

def get_latest_checkpoint(debug=False):
    # TODO: Fetch the latest checkpoint from rekor
    endpoint = "https://rekor.sigstore.dev/api/v1/log/"
    response = requests.get(endpoint).json()    
    return response 

def consistency(prev_checkpoint, debug=False):
    # TODO: 
    # verify that prev checkpoint is not empty
    if (len(prev_checkpoint) == 0):
        print("prev checkpoint empty")
        return 
    latest_checkpoint = get_latest_checkpoint()
    latestSize = latest_checkpoint["treeSize"] 
    prevSize = prev_checkpoint["treeSize"]
    treeID = prev_checkpoint["treeID"]
    latest_root = latest_checkpoint["rootHash"] #root for latest_checkpoint
    prev_root = prev_checkpoint["rootHash"] 
    url = (
    "https://rekor.sigstore.dev/api/v1/log/proof"
    f"?firstSize={prev_checkpoint['treeSize']}"
    f"&lastSize={latest_checkpoint['treeSize']}"
    f"&treeID={treeID}"
    ) 
    #print(url) 
    proof = requests.get(url).json()["hashes"]
    #print(proof)
    verify_consistency(DefaultHasher, prevSize, latestSize, proof, prev_root, latest_root) 
    print("Consistency verfication successful")


def main():
    debug = False
    parser = argparse.ArgumentParser(description="Rekor Verifier")
    parser.add_argument('-d', '--debug', help='Debug mode',
                        required=False, action='store_true') # Default false
    parser.add_argument('-c', '--checkpoint', help='Obtain latest checkpoint\
                        from Rekor Server public instance',
                        required=False, action='store_true')
    parser.add_argument('--inclusion', help='Verify inclusion of an\
                        entry in the Rekor Transparency Log using log index\
                        and artifact filename.\
                        Usage: --inclusion 126574567',
                        required=False, type=int)
    parser.add_argument('--artifact', help='Artifact filepath for verifying\
                        signature',
                        required=False)
    parser.add_argument('--consistency', help='Verify consistency of a given\
                        checkpoint with the latest checkpoint.',
                        action='store_true')
    parser.add_argument('--tree-id', help='Tree ID for consistency proof',
                        required=False)
    parser.add_argument('--tree-size', help='Tree size for consistency proof',
                        required=False, type=int)
    parser.add_argument('--root-hash', help='Root hash for consistency proof',
                        required=False)
    args = parser.parse_args()
    if args.debug:
        debug = True
        print("enabled debug mode")
    if args.checkpoint:
        # get and print latest checkpoint from server
        # if debug is enabled, store it in a file checkpoint.json
        checkpoint = get_latest_checkpoint(debug)
        print(json.dumps(checkpoint, indent=4))
    if args.inclusion:
        inclusion(args.inclusion, args.artifact, debug)
    if args.consistency:
        if not args.tree_id:
            print("please specify tree id for prev checkpoint")
            return
        if not args.tree_size:
            print("please specify tree size for prev checkpoint")
            return
        if not args.root_hash:
            print("please specify root hash for prev checkpoint")
            return

        prev_checkpoint = {}
        prev_checkpoint["treeID"] = args.tree_id
        prev_checkpoint["treeSize"] = args.tree_size
        prev_checkpoint["rootHash"] = args.root_hash

        consistency(prev_checkpoint, debug)

if __name__ == "__main__":
    main()
