"""
ECC Operations Module
Handles Elliptic Curve Cryptography operations including key generation,
serialization, and basic cryptographic operations.
"""

import base64
import os
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.exceptions import InvalidKey
import logging

logger = logging.getLogger(__name__)

class ECCOperations:
    """Handles ECC operations using SECP256R1 curve"""
    
    def __init__(self, curve=ec.SECP256R1()):
        self.curve = curve
        self.curve_name = "SECP256R1"
    
    def generate_keypair(self):
        """
        Generate a new ECC keypair
        
        Returns:
            tuple: (private_key, public_key) as cryptography objects
        """
        try:
            private_key = ec.generate_private_key(self.curve)
            public_key = private_key.public_key()
            return private_key, public_key
        except Exception as e:
            logger.error(f"Error generating ECC keypair: {e}")
            raise
    
    def serialize_public_key(self, public_key):
        """
        Serialize public key to PEM format
        
        Args:
            public_key: cryptography public key object
            
        Returns:
            str: PEM encoded public key
        """
        try:
            pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            return pem.decode('utf-8')
        except Exception as e:
            logger.error(f"Error serializing public key: {e}")
            raise
    
    def serialize_private_key(self, private_key, password=None):
        """
        Serialize private key to PEM format
        
        Args:
            private_key: cryptography private key object
            password: Optional password for encryption
            
        Returns:
            str: PEM encoded private key
        """
        try:
            if password:
                encryption_algorithm = serialization.BestAvailableEncryption(password.encode())
            else:
                encryption_algorithm = serialization.NoEncryption()
            
            pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=encryption_algorithm
            )
            return pem.decode('utf-8')
        except Exception as e:
            logger.error(f"Error serializing private key: {e}")
            raise
    
    def deserialize_public_key(self, pem_data):
        """
        Deserialize public key from PEM format
        
        Args:
            pem_data: PEM encoded public key string
            
        Returns:
            cryptography public key object
        """
        try:
            if isinstance(pem_data, str):
                pem_data = pem_data.encode('utf-8')
            
            public_key = serialization.load_pem_public_key(pem_data)
            return public_key
        except Exception as e:
            logger.error(f"Error deserializing public key: {e}")
            raise
    
    def deserialize_private_key(self, pem_data, password=None):
        """
        Deserialize private key from PEM format
        
        Args:
            pem_data: PEM encoded private key string
            password: Optional password for decryption
            
        Returns:
            cryptography private key object
        """
        try:
            if isinstance(pem_data, str):
                pem_data = pem_data.encode('utf-8')
            
            if password:
                password = password.encode()
            
            private_key = serialization.load_pem_private_key(pem_data, password=password)
            return private_key
        except Exception as e:
            logger.error(f"Error deserializing private key: {e}")
            raise
    
    def generate_nonce(self, size=32):
        """
        Generate a cryptographically secure nonce
        
        Args:
            size: Size of nonce in bytes (default: 32)
            
        Returns:
            bytes: Random nonce
        """
        try:
            return os.urandom(size)
        except Exception as e:
            logger.error(f"Error generating nonce: {e}")
            raise
    
    def derive_shared_secret(self, private_key, peer_public_key):
        """
        Derive shared secret using ECDH
        
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
            logger.error(f"Error deriving shared secret: {e}")
            raise
    
    def derive_session_key(self, shared_secret, salt=None, info=b"session_key"):
        """
        Derive session key from shared secret using HKDF
        
        Args:
            shared_secret: ECDH shared secret
            salt: Optional salt for HKDF
            info: Optional info for HKDF
            
        Returns:
            bytes: Derived session key
        """
        try:
            if salt is None:
                salt = os.urandom(32)
            
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                info=info,
            )
            session_key = hkdf.derive(shared_secret)
            return session_key, salt
        except Exception as e:
            logger.error(f"Error deriving session key: {e}")
            raise
    
    def get_public_key_bytes(self, public_key):
        """
        Get raw bytes of public key for storage
        
        Args:
            public_key: cryptography public key object
            
        Returns:
            bytes: Raw public key bytes
        """
        try:
            return public_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        except Exception as e:
            logger.error(f"Error getting public key bytes: {e}")
            raise
    
    def public_key_from_bytes(self, key_bytes):
        """
        Reconstruct public key from raw bytes
        
        Args:
            key_bytes: Raw public key bytes
            
        Returns:
            cryptography public key object
        """
        try:
            return serialization.load_der_public_key(key_bytes)
        except Exception as e:
            logger.error(f"Error reconstructing public key from bytes: {e}")
            raise

# Global instance for easy access
ecc_ops = ECCOperations() 