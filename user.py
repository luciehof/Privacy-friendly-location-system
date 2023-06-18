from typing import List

from credential import PublicKey, IssueRequest, BlindSignature, AnonymousCredential, Attribute, verify, \
    DisclosureProof
from petrelic.multiplicative.pairing import G1, G2, GT, Bn, G1Element

from zkp import KnowledgeProof


class User:
    """Corresponds to a user or a prover in our protocol. 
    The user has a username, a total list of attributes and a list of hidden attributes. 
    """

    def __init__(self, username: str, attributes: List[Attribute], hidden_attributes: List[Attribute]):
        self.t = 0 # used for the signature scheme, initialized later

        self.username = username
        self.all_attributes = attributes
        self.hidden_attributes = hidden_attributes


    ## ISSUANCE PROTOCOL ##
    def create_issue_request(
            self,
            pk: PublicKey,
            user_attributes: List[Attribute] #TODO: changed hidden_attribute by user_attr since equal, verify funciton still consistent
    ) -> IssueRequest:
        """ Create an issuance request

        This corresponds to the "user commitment" step in the issuance protocol.

        *Warning:* You may need to pass state to the `obtain_credential` function.
        """
        self.t = G1.order().random()

        # Compute issue request commitment
        commitment = pk.g1 ** self.t
        for i,a in enumerate(user_attributes):
            commitment *= pk.Y1[i] ** Bn.from_binary(a)

        # Generate the list of secrets and parse them to big numbers
        list_secrets = [Bn.from_binary(secret) for secret in user_attributes]
        list_secrets += [self.t] # t is a random value considered a secret too

        # Fetch the list of public generators from the public key. One per secret attribute
        list_generators = [pk.Y1[idx] for idx in list(range(len(user_attributes)))]
        list_generators += [pk.g1] # generator for t

        knowledge_proof = KnowledgeProof.create_commitment(
            list_secrets, 
            list_generators, 
            commitment
        )

        return knowledge_proof

    def obtain_credential(
            self,
            pk: PublicKey,
            response: BlindSignature
    ) -> AnonymousCredential:
        """ Derive a credential from the issuer's response

        This corresponds to the "Unblinding signature" step.
        """
        
        # Derive the credential from the response 
        s = response[0], response[1] / (response[0] ** self.t)

        # Verify the signature
        if not verify(pk, s, self.all_attributes):
            return None
        
        return AnonymousCredential(s, self.all_attributes)

    ### SHOWING PROTOCOL ##
    def create_disclosure_proof(
            self,
            pk: PublicKey,
            credential: AnonymousCredential,
            message: bytes,
            revealed_attributes: List[Attribute] # queried types for a location request, it is not the set of all subscriptions
    ) -> DisclosureProof:
        """ Create a disclosure proof """

        # generation of randomized signature
        r = G1.order().random()
        t = G1.order().random()

        randomized_signature = (credential.credential[0] ** r, (credential.credential[1] * (credential.credential[0] ** t)) ** r)

        # create a commitment based on all hidden attributes
        commitment = randomized_signature[0].pair(pk.g2) ** t
        for i, attribute in enumerate(self.hidden_attributes):
            generator = randomized_signature[0].pair(pk.Y2[i])
            commitment *= generator ** Bn.from_binary(attribute)
        
        # create a non-interactive challenge over the queried types and the message to prevent tampering
        challenge = KnowledgeProof.get_challenge(None, revealed_attributes, commitment, message)
        commitment = commitment ** challenge 

        # store all user's public subscriptions in the disclosure proof so the issuer can access them
        disclosed_attributes = [x for x in self.all_attributes if x not in self.hidden_attributes]

        return DisclosureProof(randomized_signature, commitment, disclosed_attributes)
