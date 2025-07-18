"""
ECDSA Handler Module
Handles Elliptic Curve Digital Signature Algorithm operations for
authentication and message signing.
"""

import base64
import logging
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature
from .ecc_operations import ecc_ops

logger = logging.getLogger(__name__)

class ECDSAHandler:
    """Handles ECDSA operations for authentication"""
    
    def __init__(self):
        self.hash_algorithm = hashes.SHA256()
    
    def sign_message(self, private_key, message):
        """
        Sign a message using ECDSA
        
        Args:
            private_key: cryptography private key object
            message: Message to sign (bytes or string)
            
        Returns:
            str: Base64 encoded signature
        """
        try:
            if isinstance(message, str):
                message = message.encode('utf-8')
            
            signature = private_key.sign(
                message,
                ec.ECDSA(self.hash_algorithm)
            )
            
            return base64.b64encode(signature).decode('utf-8')
        except Exception as e:
            logger.error(f"Error signing message: {e}")
            raise
    
    def verify_signature(self, public_key, message, signature):
        """
        Verify an ECDSA signature
        
        Args:
            public_key: cryptography public key object
            message: Original message (bytes or string)
            signature: Base64 encoded signature
            
        Returns:
            bool: True if signature is valid, False otherwise
        """
        try:
            if isinstance(message, str):
                message = message.encode('utf-8')
            
            if isinstance(signature, str):
                signature = base64.b64decode(signature)
            
            public_key.verify(
                signature,
                message,
                ec.ECDSA(self.hash_algorithm)
            )
            return True
        except InvalidSignature:
            logger.warning("Invalid signature detected")
            return False
        except Exception as e:
            logger.error(f"Error verifying signature: {e}")
            return False
    
    def sign_challenge(self, private_key, nonce):
        """
        Sign a challenge nonce for authentication
        
        Args:
            private_key: cryptography private key object
            nonce: Challenge nonce (bytes or string)
            
        Returns:
            str: Base64 encoded signature
        """
        try:
            if isinstance(nonce, str):
                nonce = nonce.encode('utf-8')
            
            signature = private_key.sign(
                nonce,
                ec.ECDSA(self.hash_algorithm)
            )
            
            return base64.b64encode(signature).decode('utf-8')
        except Exception as e:
            logger.error(f"Error signing challenge: {e}")
            raise
    
    def verify_challenge(self, public_key, nonce, signature):
        """
        Verify a challenge signature
        
        Args:
            public_key: cryptography public key object
            nonce: Original challenge nonce (bytes or string)
            signature: Base64 encoded signature
            
        Returns:
            bool: True if signature is valid, False otherwise
        """
        try:
            if isinstance(nonce, str):
                nonce = nonce.encode('utf-8')
            
            if isinstance(signature, str):
                signature = base64.b64decode(signature)
            
            public_key.verify(
                signature,
                nonce,
                ec.ECDSA(self.hash_algorithm)
            )
            return True
        except InvalidSignature:
            logger.warning("Invalid challenge signature detected")
            return False
        except Exception as e:
            logger.error(f"Error verifying challenge signature: {e}")
            return False
    
    def create_authentication_signature(self, private_key, user_id, timestamp, nonce):
        """
        Create a comprehensive authentication signature
        
        Args:
            private_key: cryptography private key object
            user_id: User identifier
            timestamp: Authentication timestamp
            nonce: Challenge nonce
            
        Returns:
            str: Base64 encoded signature
        """
        try:
            # Create a structured message for signing
            message_parts = [
                str(user_id),
                str(timestamp),
                nonce if isinstance(nonce, str) else nonce.decode('utf-8')
            ]
            message = "|".join(message_parts).encode('utf-8')
            
            signature = private_key.sign(
                message,
                ec.ECDSA(self.hash_algorithm)
            )
            
            return base64.b64encode(signature).decode('utf-8')
        except Exception as e:
            logger.error(f"Error creating authentication signature: {e}")
            raise
    
    def verify_authentication_signature(self, public_key, user_id, timestamp, nonce, signature):
        """
        Verify a comprehensive authentication signature
        
        Args:
            public_key: cryptography public key object
            user_id: User identifier
            timestamp: Authentication timestamp
            nonce: Challenge nonce
            signature: Base64 encoded signature
            
        Returns:
            bool: True if signature is valid, False otherwise
        """
        try:
            # Recreate the structured message
            message_parts = [
                str(user_id),
                str(timestamp),
                nonce if isinstance(nonce, str) else nonce.decode('utf-8')
            ]
            message = "|".join(message_parts).encode('utf-8')
            
            if isinstance(signature, str):
                signature = base64.b64decode(signature)
            
            public_key.verify(
                signature,
                message,
                ec.ECDSA(self.hash_algorithm)
            )
            return True
        except InvalidSignature:
            logger.warning("Invalid authentication signature detected")
            return False
        except Exception as e:
            logger.error(f"Error verifying authentication signature: {e}")
            return False

# Global instance for easy access
ecdsa_handler = ECDSAHandler() 