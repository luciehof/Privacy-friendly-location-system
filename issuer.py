from typing import List

from credential import SecretKey, PublicKey, IssueRequest, BlindSignature, generate_key, DisclosureProof, Attribute
from petrelic.multiplicative.pairing import G1, G2, GT, Bn
from zkp import KnowledgeProof


class Issuer:
    """Correspond to the issuer/verifier in our scheme. It signs and verifies requests from the user.
    """

    def __init__(self, sk, pk):
        self.sk, self.pk = sk, pk

    ## ISSUANCE PROTOCOL ##
    def sign_issue_request(
            self,
            sk: SecretKey,
            pk: PublicKey,
            request: IssueRequest,
            issuer_attributes: List[Attribute]
    ) -> BlindSignature:
        """ Create a signature corresponding to the user's request

        This corresponds to the "Issuer signing" step in the issuance protocol.
        """
        
        # Random value used as an exponent
        u = G1.order().random()

        # Generate the list of public generators, one per secret, to verify the commitment
        public_generators = pk.Y1[:len(request.list_ss) - 1]
        public_generators += [pk.g1] # one more generator for _t_

        if not KnowledgeProof.verify_commitment(request, public_generators):
            return None

        # Create a signature corresponding to the user's request on disclosed attributes
        prod = sk.X1 * request.commitment
        n_hidden_attr = len(pk.Y1) - len(issuer_attributes)
        for i,a in enumerate(issuer_attributes):
            prod *= pk.Y1[n_hidden_attr+i] ** Bn.from_binary(a)

        s_prime = (pk.g1 ** u, prod ** u)
        return s_prime

    ## SHOWING PROTOCOL ##
    def verify_disclosure_proof(
            self,
            pk: PublicKey,
            disclosure_proof: DisclosureProof,
            message: bytes,
            revealed_attributes: List[Attribute] # queried types for a location request, it is not the set of all subscriptions
    ) -> bool:
        """ Verify the disclosure proof

        Hint: The verifier may also want to retrieve the disclosed attributes
        """

        # recompute the commitment from the set of all subscriptions (stored in the disclosure proof)
        com_prime = disclosure_proof.signature[1].pair(pk.g2)
        for i, a in enumerate(disclosure_proof.disclosed_attributes):
            com_prime /= disclosure_proof.signature[0].pair(pk.Y2[i + 1]) ** Bn.from_binary(a)
            
        com_prime /= disclosure_proof.signature[0].pair(pk.X2)

        # compute the challenge over the queried types and the message to prevent tampering
        challenge = KnowledgeProof.get_challenge(None, revealed_attributes, com_prime, message)
        com_prime = com_prime ** challenge

        is_signature_valid = com_prime.eq(disclosure_proof.commitment)
            
        return disclosure_proof.signature[0] != G1.neutral_element() and is_signature_valid
