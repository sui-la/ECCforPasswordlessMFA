"""
Registration Module
Handles user registration with ECC key pair generation and storage.
"""

import logging
import base64
from datetime import datetime
from crypto.ecc_operations import ecc_ops
from crypto.ecdsa_handler import ecdsa_handler
from database.db_operations import DatabaseManager

logger = logging.getLogger(__name__)

class RegistrationHandler:
    """Handles user registration with ECC authentication"""
    
    def __init__(self, db_manager):
        self.db_manager = db_manager
    
    def register_user(self, email, public_key_pem, name=None, ip_address=None, user_agent=None):
        """
        Register a new user with ECC public key
        
        Args:
            email: User's email address
            public_key_pem: PEM formatted public key from client
            name: Optional user name
            ip_address: Optional IP address
            user_agent: Optional user agent
            
        Returns:
            dict: Registration result with user info
        """
        try:
            # Validate email
            if not email or '@' not in email:
                raise ValueError("Invalid email address")
            
            # Validate and deserialize public key
            try:
                public_key = ecc_ops.deserialize_public_key(public_key_pem)
            except Exception as e:
                logger.error(f"Invalid public key format: {e}")
                raise ValueError("Invalid public key format")
            
            # Get public key bytes for storage
            public_key_bytes = ecc_ops.get_public_key_bytes(public_key)
            
            # Create user in database
            user = self.db_manager.create_user(
                email=email,
                public_key_bytes=public_key_bytes,
                public_key_pem=public_key_pem,
                name=name
            )
            
            # Log registration event
            self.db_manager.log_auth_event(
                user_id=user.user_id,
                event_type='registration',
                success=True,
                ip_address=ip_address,
                user_agent=user_agent,
                details={'email': email, 'name': name}
            )
            
            logger.info(f"User registered successfully: {user.user_id}")
            
            return {
                'success': True,
                'user_id': str(user.user_id),
                'email': user.email,
                'name': user.name,
                'created_at': user.created_at.isoformat(),
                'message': 'User registered successfully'
            }
            
        except ValueError as e:
            logger.warning(f"Registration validation error: {e}")
            return {
                'success': False,
                'error': str(e)
            }
        except Exception as e:
            logger.error(f"Registration error: {e}")
            return {
                'success': False,
                'error': 'Internal server error'
            }
    
    def verify_registration(self, email, challenge_nonce, signature, ip_address=None, user_agent=None):
        """
        Verify user registration with challenge-response
        
        Args:
            email: User's email address
            challenge_nonce: Challenge nonce sent to user
            signature: Signature of the challenge
            ip_address: Optional IP address
            user_agent: Optional user agent
            
        Returns:
            dict: Verification result
        """
        try:
            # Get user by email
            user = self.db_manager.get_user_by_email(email)
            if not user:
                return {
                    'success': False,
                    'error': 'User not found'
                }
            
            # Deserialize public key
            public_key = ecc_ops.deserialize_public_key(user.public_key_pem)
            
            # Verify signature
            if isinstance(challenge_nonce, str):
                challenge_nonce = base64.b64decode(challenge_nonce)
            
            is_valid = ecdsa_handler.verify_challenge(
                public_key=public_key,
                nonce=challenge_nonce,
                signature=signature
            )
            
            if is_valid:
                # Log successful verification
                self.db_manager.log_auth_event(
                    user_id=user.user_id,
                    event_type='registration_verification',
                    success=True,
                    ip_address=ip_address,
                    user_agent=user_agent
                )
                
                return {
                    'success': True,
                    'user_id': str(user.user_id),
                    'message': 'Registration verified successfully'
                }
            else:
                # Log failed verification
                self.db_manager.log_auth_event(
                    user_id=user.user_id,
                    event_type='registration_verification',
                    success=False,
                    ip_address=ip_address,
                    user_agent=user_agent,
                    details={'error': 'Invalid signature'}
                )
                
                return {
                    'success': False,
                    'error': 'Invalid signature'
                }
                
        except Exception as e:
            logger.error(f"Registration verification error: {e}")
            return {
                'success': False,
                'error': 'Internal server error'
            }
    
    def generate_registration_challenge(self, email, ip_address=None):
        """
        Generate a challenge for registration verification
        
        Args:
            email: User's email address
            ip_address: Optional IP address
            
        Returns:
            dict: Challenge information
        """
        try:
            # Check if user exists
            user = self.db_manager.get_user_by_email(email)
            if not user:
                return {
                    'success': False,
                    'error': 'User not found'
                }
            
            # Generate challenge nonce
            nonce = ecc_ops.generate_nonce(32)
            nonce_b64 = base64.b64encode(nonce).decode('utf-8')
            
            # Store challenge in database (optional, for audit purposes)
            # For registration verification, we might not need to store the challenge
            # as it's a one-time verification process
            
            logger.info(f"Registration challenge generated for user: {user.user_id}")
            
            return {
                'success': True,
                'challenge_id': str(user.user_id),  # Using user_id as challenge_id for registration
                'nonce': nonce_b64,
                'expires_in': 300,  # 5 minutes
                'message': 'Registration challenge generated'
            }
            
        except Exception as e:
            logger.error(f"Error generating registration challenge: {e}")
            return {
                'success': False,
                'error': 'Internal server error'
            }
    
    def check_email_availability(self, email):
        """
        Check if email is available for registration
        
        Args:
            email: Email address to check
            
        Returns:
            dict: Availability result
        """
        try:
            if not email or '@' not in email:
                return {
                    'success': False,
                    'error': 'Invalid email address'
                }
            
            user = self.db_manager.get_user_by_email(email)
            
            return {
                'success': True,
                'available': user is None,
                'message': 'Email is available' if user is None else 'Email is already registered'
            }
            
        except Exception as e:
            logger.error(f"Error checking email availability: {e}")
            return {
                'success': False,
                'error': 'Internal server error'
            } 