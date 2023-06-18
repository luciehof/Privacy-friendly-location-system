"""
Classes that you need to complete.
"""

from typing import Any, Dict, List, Union, Tuple
from zkp import KnowledgeProof

# Optional import
from credential import generate_key
from issuer import Issuer
from serialization import jsonpickle

# Type aliases
from user import User

State = User


class Server:
    """Server"""

    def __init__(self):
        """
        Server constructor.
        """
        ###############################################
        # TODO: Complete this function.
        ###############################################
        self.issuer = None

    @staticmethod
    def generate_ca(
            subscriptions: List[str]
    ) -> Tuple[bytes, bytes]:
        """Initializes the credential system. Runs exactly once in the
        beginning. Decides on schemes public parameters and choses a secret key
        for the server.

        Args:
            subscriptions: a list of all valid attributes. Users cannot get a
                credential with a attribute which is not included here.

        Returns:
            tuple containing:
                - server's secret key
                - server's public information
            You are free to design this as you see fit, but the return types
            should be encoded as bytes.
        """
        ###############################################
        # TODO: Complete this function.
        ###############################################
        # generate secret and public key based on attributes (subscriptions) ;
        # we consider the public key to be the public param (maybe we will find others later?)
        sk, pk = generate_key(
            subscriptions)  # TODO: define clear types --> for now Attributes are bytes and not string hence the type pb here
        return jsonpickle.encode(sk).encode(), jsonpickle.encode(pk).encode()

    def process_registration(
            self,
            server_sk: bytes,
            server_pk: bytes,
            issuance_request: bytes,
            username: str,
            subscriptions: List[str]
    ) -> bytes:
        """ Registers a new account on the server.

        Args:
            server_sk: the server's secret key (serialized)
            issuance_request: The issuance request (serialized)
            username: username
            subscriptions: attributes


        Return:
            serialized response (the client should be able to build a
                credential with this response).
        """
        ###############################################
        # TODO: Complete this function.
        ###############################################
        sk = jsonpickle.decode(server_sk.decode())
        pk = jsonpickle.decode(server_pk.decode())
        request = jsonpickle.decode(issuance_request.decode())

        self.issuer = Issuer(sk, pk)
        issuer_attributes = []
        for i in range(len(subscriptions)):
            issuer_attributes.append(subscriptions[i].encode())

        blindSignature = self.issuer.sign_issue_request(self.issuer.sk, self.issuer.pk, request, issuer_attributes)
        
        return jsonpickle.encode(blindSignature).encode()

    def check_request_signature(
            self,
            server_pk: bytes,
            message: bytes,
            revealed_attributes: List[str], # contains the queried types for a location request
            signature: bytes
    ) -> bool:
        """ Verify the signature on the location request

        Args:
            server_pk: the server's public key (serialized)
            message: The message to sign
            revealed_attributes: revealed attributes
            signature: user's authorization (serialized)

        Returns:
            whether a signature is valid
        """
        ###############################################
        # TODO: Complete this function.
        ###############################################
        pk = jsonpickle.decode(server_pk.decode())
        s = jsonpickle.decode(signature.decode())

        ## Check that the queried types are part of the valid subscriptions
        queried_types = list(map(lambda x: x.encode(), revealed_attributes))
        for queried_type in queried_types:
            if not queried_type in s.disclosed_attributes:
                return False


        self.issuer = Issuer(None, pk)
        return self.issuer.verify_disclosure_proof(pk, s, message, queried_types)


class Client:
    """Client"""

    def __init__(self):
        """
        Client constructor.
        """
        ###############################################
        # TODO: Complete this function.
        ###############################################
        self.user = None

    def prepare_registration(
            self,
            server_pk: bytes,
            username: str,
            subscriptions: List[str]
    ) -> Tuple[bytes, User]:
        """Prepare a request to register a new account on the server.

        Args:
            server_pk: a server's public key (serialized)
            username: user's name
            subscriptions: user's subscriptions

        Return:
            A tuple containing:
                - an issuance request
                - A private state. You can use state to store and transfer information
                from prepare_registration to proceed_registration_response.
                You need to design the state yourself.
        """
        ###############################################
        # TODO: Complete this function.
        ###############################################
        pk = jsonpickle.decode(server_pk.decode())

        all_attributes = [username.encode()]
        for i in range(len(subscriptions)):
            all_attributes.append(subscriptions[i].encode())

        hidden_attributes = [username.encode()]

        user = User(username, all_attributes,
                    hidden_attributes)
        
        issue_req = user.create_issue_request(pk, hidden_attributes)

        return jsonpickle.encode(issue_req).encode(), user

    def process_registration_response(
            self,
            server_pk: bytes,
            server_response: bytes,
            private_state: State
    ) -> bytes:
        """Process the response from the server.

        Args:
            server_pk a server's public key (serialized)
            server_response: the response from the server (serialized)
            private_state: state from the prepare_registration
            request corresponding to this response

        Return:
            credentials: create an attribute-based credential for the user
        """
        ###############################################
        # TODO: Complete this function.
        ###############################################
        pk = jsonpickle.decode(server_pk.decode())
        response = jsonpickle.decode(server_response.decode())
        credentials = private_state.obtain_credential(pk, response)
        
        return jsonpickle.encode(credentials).encode()

    def sign_request(
            self,
            server_pk: bytes,
            credentials: bytes,
            message: bytes,
            types: List[str]
    ) -> bytes:
        """Signs the request with the client's credential.

        Arg:
            server_pk: a server's public key (serialized)
            credential: client's credential (serialized)
            message: message to sign
            types: which attributes should be sent along with the request?

        Returns:
            A message's signature (serialized)
        """
        ###############################################
        # TODO: Complete this function.
        ###############################################

        pk = jsonpickle.decode(server_pk.decode())
        creds = jsonpickle.decode(credentials.decode())

        username = creds.all_attributes[0]
        queried_types = list(map(lambda x: x.encode(), types))

        user = User(username, creds.all_attributes, [username])
        proof = user.create_disclosure_proof(pk, creds, message, queried_types)

        return jsonpickle.encode(proof).encode()
