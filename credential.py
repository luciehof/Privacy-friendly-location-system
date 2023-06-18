"""
Skeleton credential module for implementing PS credentials

The goal of this skeleton is to help you implementing PS credentials. Following
this API is not mandatory and you can change it as you see fit. This skeleton
only provides major functionality that you will need.

You will likely have to define more functions and/or classes. In particular, to
maintain clean code, we recommend to use classes for things that you want to
send between parties. You can then use `jsonpickle` serialization to convert
these classes to byte arrays (as expected by the other classes) and back again.

We also avoided the use of classes in this template so that the code more closely
resembles the original scheme definition. However, you are free to restructure
the functions provided to resemble a more object-oriented interface.
"""

from typing import Any, List, Tuple
from zkp import KnowledgeProof

from petrelic.bn import Bn
from petrelic.multiplicative.pairing import G1, G1Element, G2, G2Element, GT, GTElement

# Type hint aliases
# Feel free to change them as you see fit.
# Maybe at the end, you will not need aliases at all!
# SecretKey = Any  # a tuple (x, X, y1, ..., yL)
# PublicKey = Any
#TODO: verify all types are consistent with there actuel use (in functions)
Signature = Tuple[G1Element, G1Element]
Attribute = bytes #TODO: str instead?
#AttributeMap = {int, Attribute} #TODO: maybe {str, attr_value} instead makes more sense?
IssueRequest = KnowledgeProof
BlindSignature = Tuple[G1Element]

class AnonymousCredential:
    def __init__(self, credential: Tuple[G1Element, G1Element], all_attributes: List[Attribute]):
        self.credential = credential
        self.all_attributes = all_attributes

class DisclosureProof:
    def __init__(self, signature: Signature, commitment: GTElement, disclosed_attributes: List[Attribute]):
        self.signature = signature
        self.commitment = commitment
        self.disclosed_attributes = disclosed_attributes
        #self.knowledge_proof = knowledge_proof

class PublicKey:
    def __init__(self, g1: G1Element, Y1: List[G1Element], g2: G2Element, X2: G2Element, Y2: List[G2Element]):
        self.g1 = g1
        self.Y1 = Y1
        self.g2 = g2
        self.X2 = X2
        self.Y2 = Y2

class SecretKey:
    def __init__(self, x: Bn, X1: G1Element, y: List[int]):
        self.x = x
        self.X1 = X1
        self.y = y

######################
## SIGNATURE SCHEME ##
######################


def generate_key(
        attributes: List[Attribute]
) -> Tuple[SecretKey, PublicKey]:
    """ Generate signer key pair """
    
    attributes_count = len(attributes)

    # Initialization values
    p = G1.order()
    g1 = G1.generator()
    g2 = G2.generator()

    ##  Creation of the secret key
    x = p.random()
    X1 = g1 ** x 
    ys = [p.random() for _ in range(attributes_count)]

    secret_key = SecretKey(x, X1, ys)

    
    ## Creation of the public key
    X2 = g2 ** x

    Y1s = [g1 ** ys[i] for i in range(attributes_count)]
    Y2s = [g2 ** ys[i] for i in range(attributes_count)]

    public_key = PublicKey(g1, Y1s, g2, X2, Y2s)

    return (secret_key, public_key)

def verify(
        pk: PublicKey,
        signature: Signature,
        msgs: List[bytes]
) -> bool:
    """ Verify the signature on a vector of messages """
    product = pk.X2
    for i in range(len(msgs)):
        product *= pk.Y2[i] **Bn.from_binary(msgs[i])

    return signature[0] != G2.neutral_element() and signature[0].pair(product) == signature[1].pair(pk.g2)