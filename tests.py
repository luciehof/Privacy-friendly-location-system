from typing import List, Tuple
from jsonpickle.unpickler import decode
from petrelic.bn import Bn
from stroll import Client, Server
import jsonpickle
from credential import AnonymousCredential, BlindSignature, DisclosureProof, IssueRequest, PublicKey, SecretKey, generate_key
from petrelic.multiplicative.pairing import G1, G1Element, G2, G2Element, GT

from issuer import Issuer
from user import User

"""
============================================
========= SECRET STROLL TESTING ============
============================================
"""


## Utility functions for testing
def decode_data(data: bytes):
    return jsonpickle.decode(data.decode())

def get_keys(subscriptions: List[str]) -> Tuple[bytes, bytes]:
    sk_enc, pk_enc = Server.generate_ca(["username"] + subscriptions)
    return sk_enc, pk_enc

#### =============
#### SUCCESS CASES
#### =============

## Test that the keys were generated correctly by the server
def test_key_generation():
    subscriptions = ["t1", "t2", "t3"]
    sk_enc, pk_enc = get_keys(subscriptions)
    sk: SecretKey = decode_data(sk_enc)
    pk: PublicKey = decode_data(pk_enc)

    # Test private key attributes
    assert len(sk.y) is len(subscriptions) + 1
    assert isinstance(sk.x, Bn) and isinstance(sk.X1, G1Element)

    # Test public key attributes
    assert len(pk.Y1) is len(subscriptions) + 1
    assert len(pk.Y2) is len(subscriptions) + 1

    for y1 in pk.Y1: 
        assert isinstance(y1, G1Element)
    for y2 in pk.Y2:
        assert isinstance(y2, G2Element)

    assert isinstance(pk.g1, G1Element) and isinstance(pk.g2, G2Element)
    
    
## Test the successful generation of a credential step by step, as well as a stroll request
def test_successful_request():
    subscriptions = ["t1", "t2", "t3"]
    queried_subscriptions = ["t1", "t2"]
    username = "test"
    message = b'30.00.00'
    sk, pk = get_keys(subscriptions)
    server, client = Server(), Client()
    

    # Generate issue request and test it
    issue_request_enc, user_state = client.prepare_registration(pk, username, subscriptions)
    issue_request: IssueRequest = decode_data(issue_request_enc)

    assert issue_request.challenge is not None
    assert isinstance(issue_request.commitment, G1Element)
    assert len(user_state.hidden_attributes) == 1
    assert len(issue_request.list_ss) == len(user_state.hidden_attributes) + 1
    assert len(user_state.all_attributes) == 4

    # Process registration and test it server-side
    blind_signature_enc = server.process_registration(sk, pk, issue_request_enc, username, subscriptions)
    blind_signature: BlindSignature = decode_data(blind_signature_enc)

    assert len(blind_signature) == 2
    assert isinstance(blind_signature[0], G1Element) and isinstance(blind_signature[1], G1Element)


    # Obtain credential client side and test it 
    credential_enc = client.process_registration_response(pk, blind_signature_enc, user_state)
    credential: AnonymousCredential = decode_data(credential_enc)

    assert credential is not None
    assert isinstance(credential.credential[0], G1Element) and isinstance(credential.credential[1], G1Element)
    assert credential.all_attributes == [b"test", b"t1", b"t2", b"t3"]


    # Create a secret stroll request (disclosure proof) and test it
    stroll_request_enc = client.sign_request(pk, credential_enc, message, queried_subscriptions)
    stroll_request: DisclosureProof = decode_data(stroll_request_enc)

    assert isinstance(stroll_request.signature[0], G1Element) and isinstance(stroll_request.signature[1], G1Element)
    assert stroll_request.commitment is not None


    # Test that the request is valid
    assert server.check_request_signature(pk, message, queried_subscriptions, stroll_request_enc)
    

### Two credentials generated from the same set of attributes should be
### different. Credentials should not be linked.
def test_credential_should_be_different():
    subscriptions = ["t1", "t2", "t3"]
    username = "test"
    sk, pk = get_keys(subscriptions)

    server, client = Server(), Client()

    ### Credential for user 1
    issue_request_enc_1, user_state_1 = client.prepare_registration(pk, username, subscriptions)
    blind_signature_enc_1 = server.process_registration(sk, pk, issue_request_enc_1, username, subscriptions)
    credential_enc_1 = client.process_registration_response(pk, blind_signature_enc_1, user_state_1)


    ### Credential for user 2
    issue_request_enc_2, user_state_2 = client.prepare_registration(pk, username, subscriptions)
    blind_signature_enc_2 = server.process_registration(sk, pk, issue_request_enc_2, username, subscriptions)
    credential_enc_2 = client.process_registration_response(pk, blind_signature_enc_2, user_state_1)

    
    assert credential_enc_1 != credential_enc_2 # credential was tampered, it should be None. 


### =============
### FAILING CASES 
### =============

### If any hidden attribute of a credential is changed, the system should fail 
### and not return any credential
def test_credential_request_hidden_tampering():
    subscriptions = ["t1", "t2", "t3"]
    username = "test"
    sk, pk = get_keys(subscriptions)

    server, client = Server(), Client()

    issue_request_enc, user_state = client.prepare_registration(pk, username, subscriptions)
    blind_signature_enc = server.process_registration(sk, pk, issue_request_enc, username, subscriptions)

    # change some hidden user attributes after the registration has been registered by the server
    # attributes[0] is a hidden attribute here - the username.
    user_state.all_attributes[0] = b"tampered_attribute_hidden"
    user_state.hidden_attributes[0] = b"tampered_attribute_hidden"
    
    credential_enc = client.process_registration_response(pk, blind_signature_enc, user_state)
    credential: AnonymousCredential = decode_data(credential_enc)
    assert credential is None # credential was tampered, it should be None. 


## If any disclosed attribute of a signed issue request is changed, 
## the system should fail and not return any credential
def test_credential_request_disclosed_tampering():
    subscriptions = ["t1", "t2", "t3"]
    username = "test"
    sk, pk = get_keys(subscriptions)

    server, client = Server(), Client()

    issue_request_enc, user_state = client.prepare_registration(pk, username, subscriptions)
    blind_signature_enc = server.process_registration(sk, pk, issue_request_enc, username, subscriptions)

    # change some disclosed user attributes after the registration has been registered by the server
    user_state.all_attributes[1] = b"tampered_attribute_disclosed"
    
    credential_enc = client.process_registration_response(pk, blind_signature_enc, user_state)
    credential: AnonymousCredential = decode_data(credential_enc)
    assert credential is None # credential was tampered, it should be None. 


## After a stroll request has been signed over a set of subscriptions (disclosed attributes) 
## with a credential, the server's signature check should fail if any subscription was changed. 
## A stroll request should only be valid over its given set of disclosed attributes.
def test_disclosure_proof_tampering():
    subscriptions = ["t1", "t2", "t3"]
    username = "test"
    message = b'30.00.00'
    sk, pk = get_keys(subscriptions)
    server, client = Server(), Client()

    # Generate issue request and test it
    issue_request_enc, user_state = client.prepare_registration(pk, username, subscriptions)

    # Process registration and test it server-side
    blind_signature_enc = server.process_registration(sk, pk, issue_request_enc, username, subscriptions)

    # Obtain credential client side and test it 
    credential_enc = client.process_registration_response(pk, blind_signature_enc, user_state)

    # Create a secret stroll request (disclosure proof) and test it
    queried_types = ["t1", "t2"]
    stroll_request_enc = client.sign_request(pk, credential_enc, message, queried_types)

    # Change some subscriptions
    tampered_subscriptions = ["t1", "t3"]

    # Test that the request signature is invalid, 
    assert not server.check_request_signature(pk, message, tampered_subscriptions, stroll_request_enc)
    

## After a stroll request has been signed over a given message with a credential,
## the server's signature check should fail if this message was changed. 
def test_message_tampering():
    subscriptions = ["t1", "t2", "t3"]
    username = "test"
    message = b'30.00.00'
    sk, pk = get_keys(subscriptions)
    server, client = Server(), Client()

    # Generate issue request and test it
    issue_request_enc, user_state = client.prepare_registration(pk, username, subscriptions)

    # Process registration and test it server-side
    blind_signature_enc = server.process_registration(sk, pk, issue_request_enc, username, subscriptions)

    # Obtain credential client side and test it 
    credential_enc = client.process_registration_response(pk, blind_signature_enc, user_state)

    # Create a secret stroll request (disclosure proof) and test it
    queried_types = ["t1", "t2"]
    stroll_request_enc = client.sign_request(pk, credential_enc, message, queried_types)

    # Change request message
    tampered_message = "jajajaja"

    # Test that the request signature is invalid, 
    assert not server.check_request_signature(pk, message, tampered_message, stroll_request_enc)


## Stroll requests should only work on valid POI types, e.g. the ones that are subscribed too
## during the registration phase and the issuance of the credential. If an invalid POI type is
## queried, the request should fail. 
def test_invalid_queried_type():
    subscriptions = ["t1", "t2", "t3"] # set of valid query types
    username = "test"
    message = b'30.00.00'
    sk, pk = get_keys(subscriptions)
    server, client = Server(), Client()

    # Generate issue request and test it
    issue_request_enc, user_state = client.prepare_registration(pk, username, subscriptions)

    # Process registration and test it server-side
    blind_signature_enc = server.process_registration(sk, pk, issue_request_enc, username, subscriptions)

    # Obtain credential client side and test it 
    credential_enc = client.process_registration_response(pk, blind_signature_enc, user_state)

    # Create a secret stroll request (disclosure proof) and test it
    queried_types = ["invalid", "t2"]
    stroll_request_enc = client.sign_request(pk, credential_enc, message, queried_types)

    # Test that the request signature is invalid, 
    assert not server.check_request_signature(pk, message, queried_types, stroll_request_enc)


# print("RUNNING ALL TESTS")

# test_key_generation()
# test_successful_request()
# test_credential_request_hidden_tampering()
# test_credential_request_disclosed_tampering()
# test_credential_should_be_different()
# test_message_tampering()
# test_invalid_queried_type()
# test_disclosure_proof_tampering()

# print("ALL TESTS PASSED!")