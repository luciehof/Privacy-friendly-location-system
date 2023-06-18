import matplotlib.pyplot as plt
from scipy.stats import sem
import time
import math
from timeit import default_timer as timer
from typing import List, Tuple
from jsonpickle.unpickler import decode
from petrelic.bn import Bn
from stroll import Client, Server
import jsonpickle
from credential import AnonymousCredential, BlindSignature, DisclosureProof, IssueRequest, PublicKey, SecretKey, generate_key
from petrelic.multiplicative.pairing import G1, G1Element, G2, G2Element, GT

from issuer import Issuer
from user import User

## Utility functions for testing
def decode_data(data: bytes):
    return jsonpickle.decode(data.decode())

def get_keys(subscriptions: List[str]) -> Tuple[bytes, bytes]:
    sk_enc, pk_enc = Server.generate_ca(["username"] + subscriptions)
    return sk_enc, pk_enc

#### =============
#### SUCCESS CASES
#### =============

subscriptions = ["t1", "t2", "t3"]
queried_subscriptions = ["t1", "t2"]
username = "test"
message = b'30.00.00'
server, client = Server(), Client()

sk, pk = get_keys(subscriptions)
packets = [[], [], [], []]

## Test that the keys were generated correctly by the server
def key_generation():
    sk_enc, pk_enc = get_keys(subscriptions)
    sk: SecretKey = decode_data(sk_enc)
    pk: PublicKey = decode_data(pk_enc)    

    return sk, pk
    
## Test the successful generation of a credential step by step, as well as a stroll request
def credential_issuance():
    # Generate issue request and test it
    issue_request_enc, user_state = client.prepare_registration(pk, username, subscriptions)
    issue_request: IssueRequest = decode_data(issue_request_enc)

    # Process registration and test it server-side
    blind_signature_enc = server.process_registration(sk, pk, issue_request_enc, username, subscriptions)
    blind_signature: BlindSignature = decode_data(blind_signature_enc)

    # Obtain credential client side and test it 
    credential_enc = client.process_registration_response(pk, blind_signature_enc, user_state)
    credential: AnonymousCredential = decode_data(credential_enc)

    packets[0] += [len(credential_enc)] + [len(blind_signature_enc) * 2] + [len(issue_request_enc) * 2]

    return credential_enc
    

def credential_showing(credential_enc):
    # Create a secret stroll request (disclosure proof) and test it
    stroll_request_enc = client.sign_request(pk, credential_enc, message, queried_subscriptions)
    stroll_request: DisclosureProof = decode_data(stroll_request_enc)

    packets[1] += [len(credential_enc) * 2] + [len(stroll_request_enc) * 2]

    

    return stroll_request_enc

def credential_verification(stroll_request_enc):
  server.check_request_signature(pk, message, queried_subscriptions, stroll_request_enc)

  packets[2].append(len(stroll_request_enc))


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


    # Process registration and test it server-side
    blind_signature_enc = server.process_registration(sk, pk, issue_request_enc, username, subscriptions)
    blind_signature: BlindSignature = decode_data(blind_signature_enc)

    # Obtain credential client side and test it 
    credential_enc = client.process_registration_response(pk, blind_signature_enc, user_state)
    credential: AnonymousCredential = decode_data(credential_enc)

    # Create a secret stroll request (disclosure proof) and test it
    stroll_request_enc = client.sign_request(pk, credential_enc, message, queried_subscriptions)
    stroll_request: DisclosureProof = decode_data(stroll_request_enc)

    packets[3] += [(len(issue_request_enc) * 2 + len(blind_signature_enc) * 2) * 1.25] + [(len(credential_enc) * 2 + len(stroll_request_enc) * 2) * 1.25]

    # Test that the request is valid
    assert server.check_request_signature(pk, message, queried_subscriptions, stroll_request_enc)


### Perf eval
num_iter = 5000

res = [[], [], [], [], []]
fun = [key_generation, credential_issuance, credential_showing, credential_verification, test_successful_request]
for i in range(num_iter):
  cred = None
  issuance = None
  for j in range(0, 5):
    start = timer()
    if j == 1:
      cred = fun[j]()
    elif j == 2:
      issuance = fun[j](cred)
    elif j == 3:
      fun[j](issuance)
    else:
      fun[j]()

    end = timer()
    res[j].append(end - start)


# time
stems = list(map(lambda x: sem(x) * 150, res))
means = list(map(lambda x: sum(x) / len(x), res))

# com
stems_com = list(map(lambda x : sem(x)* 10, packets))
means_com = list(map(lambda x: sum(x) / len(x), packets))

plt.errorbar(["Key gen.", "Cred. issuance", "Cred. showing", "Req. verification", "Full request"], means, stems, linestyle='None', marker='s')
plt.ylabel("Execution Time (in ms)")
plt.savefig("exec_time.png")
plt.show()

plt.errorbar(["Credential issuance", "Credential showing", "Request verification", "Full request"], means_com, stems_com, linestyle='None', marker='s')
plt.ylabel("Packets Exchanged (bytes length)")
plt.savefig("packets.png")
plt.show()