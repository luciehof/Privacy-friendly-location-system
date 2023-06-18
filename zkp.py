import hashlib
from typing import Any, List
from petrelic.bn import Bn
from petrelic.multiplicative.pairing import G1, G2, GT
import serialization
import jsonpickle



class KnowledgeProof:
    """Class to generate a proof of knowledge
    we use perdsen's scheme as seen in the exercises
    + the fiat shamir heuristic to make the proof non-interactive. 
    """

    def __init__(self, challenge: int, list_ss: List[Any], commitment: Any):
        self.challenge = challenge
        self.list_ss = list_ss
        self.commitment = commitment

    @staticmethod
    def get_challenge(R: Bn, public_generators: List[Any], commitment: Bn, message: bytes) -> int:
        """Generate a non-interactive challenge for the PK by hashing
        the public values (fiat-shamir heuristic). Those values are: R, the list
        of public generators, the user commitment, as well as an optional message
        """

        # Compute the hash
        sha256 = hashlib.sha256()
        sha256.update(jsonpickle.encode(R).encode())
        sha256.update(jsonpickle.encode(commitment).encode())
        sha256.update(message)

        # Add all generators to the hash
        for g in public_generators:
            sha256.update(jsonpickle.encode(g).encode())

        # Return the hash as an int value
        return int.from_bytes(sha256.digest(), 'big')


    @staticmethod
    def create_commitment(secrets: List[bytes], public_generators: List[Any], commitment: Any, message=b"", group=G1) -> 'KnowledgeProof':
        """Create a proof of knowledge for a prover to prove knowledge of a [secrets] list
        using the pedersen's PK scheme. Called by the prover.
        """

        # Generate the big R over the list of the secrets for the prover. 
        list_rs = [group.order().random() for _ in range(len(secrets))]
        big_R  = group.neutral_element()
        for idx, r in enumerate(list_rs):
            big_R *= public_generators[idx] ** r


        # Generate the non interactive challenge _c_
        challenge = KnowledgeProof.get_challenge(big_R, public_generators, commitment, message)

        # Generate the list of parameters allowing to verify the proof of knowledge for the verifier (s_i)
        list_ss = [None for _ in secrets]
        for i, r in enumerate(list_rs):
            list_ss[i] = (r - challenge * secrets[i]) % group.order()

        return KnowledgeProof(challenge, list_ss, commitment)


    @staticmethod
    def verify_commitment(knowledge_proof: 'KnowledgeProof', public_generators: List[Any], message=b""):
        """Verify a commitment for a proof of knowledge using pedersen's scheme. 
        Called by the verifier.
        """

        # Reconstruct the challenge from the given data and check if it is the same
        # as the one given by the prover. 
        R = knowledge_proof.commitment ** knowledge_proof.challenge
        for i, s in enumerate(knowledge_proof.list_ss):
            R *= public_generators[i] ** s

        c_prime = KnowledgeProof.get_challenge(R, public_generators, knowledge_proof.commitment, message)

        return c_prime == knowledge_proof.challenge