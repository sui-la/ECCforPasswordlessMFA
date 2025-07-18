"""
ECDH Handler Module
Handles Elliptic Curve Diffie-Hellman key exchange operations for
secure session establishment.
"""

import base64
import logging
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from .ecc_operations import ecc_ops

logger = logging.getLogger(__name__)

class ECDHHandler:
    """Handles ECDH operations for secure key exchange"""
    
    def __init__(self):
        self.curve = ec.SECP256R1()
    
    def generate_ephemeral_keypair(self):
        """
        Generate ephemeral keypair for session establishment
        
        Returns:
            tuple: (private_key, public_key) as cryptography objects
        """
        try:
            private_key = ec.generate_private_key(self.curve)
            public_key = private_key.public_key()
            return private_key, public_key
        except Exception as e:
            logger.error(f"Error generating ephemeral keypair: {e}")
            raise
    
    def compute_shared_secret(self, private_key, peer_public_key):
        """
        Compute shared secret using ECDH
        
        Args:
            private_key: Local private key
            peer_public_key: Peer's public key
            
        Returns:
            bytes: Shared secret
        """
        try:
            shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)
            return shared_secret
        except Exception as e:
            logger.error(f"Error computing shared secret: {e}")
            raise
    
    def derive_session_key(self, shared_secret, salt=None, info=b"ecc_mfa_session"):
        """
        Derive session key from shared secret using HKDF
        
        Args:
            shared_secret: ECDH shared secret
            salt: Optional salt for HKDF
            info: Optional info for HKDF
            
        Returns:
            tuple: (session_key, salt) where session_key is bytes and salt is bytes
        """
        try:
            if salt is None:
                salt = ecc_ops.generate_nonce(32)
            
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=32,  # 256-bit session key
                salt=salt,
                info=info,
            )
            session_key = hkdf.derive(shared_secret)
            return session_key, salt
        except Exception as e:
            logger.error(f"Error deriving session key: {e}")
            raise
    
    def establish_secure_session(self, client_private_key, server_public_key, salt=None):
        """
        Establish a secure session using ECDH
        
        Args:
            client_private_key: Client's private key
            server_public_key: Server's public key
            salt: Optional salt for key derivation
            
        Returns:
            tuple: (session_key, salt) where both are base64 encoded strings
        """
        try:
            # Compute shared secret
            shared_secret = self.compute_shared_secret(client_private_key, server_public_key)
            
            # Derive session key
            session_key, derived_salt = self.derive_session_key(shared_secret, salt)
            
            # Encode for transmission
            session_key_b64 = base64.b64encode(session_key).decode('utf-8')
            salt_b64 = base64.b64encode(derived_salt).decode('utf-8')
            
            return session_key_b64, salt_b64
        except Exception as e:
            logger.error(f"Error establishing secure session: {e}")
            raise
    
    def verify_session_establishment(self, server_private_key, client_public_key, expected_session_key, salt):
        """
        Verify session establishment on server side
        
        Args:
            server_private_key: Server's private key
            client_public_key: Client's public key
            expected_session_key: Expected session key (base64 encoded)
            salt: Salt used for key derivation (base64 encoded)
            
        Returns:
            bool: True if session keys match, False otherwise
        """
        try:
            # Decode inputs
            if isinstance(expected_session_key, str):
                expected_session_key = base64.b64decode(expected_session_key)
            if isinstance(salt, str):
                salt = base64.b64decode(salt)
            
            # Compute shared secret
            shared_secret = self.compute_shared_secret(server_private_key, client_public_key)
            
            # Derive session key
            session_key, _ = self.derive_session_key(shared_secret, salt)
            
            # Compare session keys
            return session_key == expected_session_key
        except Exception as e:
            logger.error(f"Error verifying session establishment: {e}")
            return False
    
    def serialize_public_key_for_transmission(self, public_key):
        """
        Serialize public key for secure transmission
        
        Args:
            public_key: cryptography public key object
            
        Returns:
            str: Base64 encoded public key
        """
        try:
            pem = ecc_ops.serialize_public_key(public_key)
            # Convert PEM to base64 for easier transmission
            return base64.b64encode(pem.encode('utf-8')).decode('utf-8')
        except Exception as e:
            logger.error(f"Error serializing public key for transmission: {e}")
            raise
    
    def deserialize_public_key_from_transmission(self, encoded_key):
        """
        Deserialize public key from transmission format
        
        Args:
            encoded_key: Base64 encoded public key
            
        Returns:
            cryptography public key object
        """
        try:
            # Decode from base64
            pem_data = base64.b64decode(encoded_key).decode('utf-8')
            return ecc_ops.deserialize_public_key(pem_data)
        except Exception as e:
            logger.error(f"Error deserializing public key from transmission: {e}")
            raise
    
    def create_session_token(self, session_key, user_id, timestamp):
        """
        Create a session token using the derived session key
        
        Args:
            session_key: Derived session key (base64 encoded)
            user_id: User identifier
            timestamp: Session creation timestamp
            
        Returns:
            str: Base64 encoded session token
        """
        try:
            if isinstance(session_key, str):
                session_key_bytes = base64.b64decode(session_key)
            else:
                session_key_bytes = session_key
            
            # Create token data
            token_data = f"{user_id}:{timestamp}".encode('utf-8')
            
            # Use HKDF to derive a token from session key
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=session_key_bytes[:16],  # Use first 16 bytes as salt
                info=b"session_token",
            )
            token = hkdf.derive(session_key_bytes)
            
            return base64.b64encode(token).decode('utf-8')
        except Exception as e:
            logger.error(f"Error creating session token: {e}")
            raise

# Global instance for easy access
ecdh_handler = ECDHHandler() 