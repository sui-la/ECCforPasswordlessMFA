"""
Authentication Module
Handles ECC-based authentication with challenge-response mechanism.
"""

import logging
import base64
import uuid
from datetime import datetime, timedelta
from crypto.ecc_operations import ecc_ops
from crypto.ecdsa_handler import ecdsa_handler
from crypto.ecdh_handler import ecdh_handler
from database.db_operations import DatabaseManager

logger = logging.getLogger(__name__)

class AuthenticationHandler:
    """Handles ECC-based authentication"""
    
    def __init__(self, db_manager, jwt_secret):
        self.db_manager = db_manager
        self.jwt_secret = jwt_secret
    
    def initiate_login(self, email, ip_address=None, user_agent=None):
        """
        Initiate login process by generating a challenge
        
        Args:
            email: User's email address
            ip_address: Optional IP address
            user_agent: Optional user agent
            
        Returns:
            dict: Challenge information
        """
        try:
            # Get user by email
            user = self.db_manager.get_user_by_email(email)
            if not user:
                return {
                    'success': False,
                    'error': 'User not found'
                }
            
            # Generate challenge nonce
            nonce = ecc_ops.generate_nonce(32)
            nonce_b64 = base64.b64encode(nonce).decode('utf-8')
            
            # Create challenge in database
            challenge = self.db_manager.create_challenge(
                user_id=user.user_id,
                nonce=nonce,
                ip_address=ip_address
            )
            
            # Log challenge generation
            self.db_manager.log_auth_event(
                user_id=user.user_id,
                event_type='challenge_generated',
                success=True,
                ip_address=ip_address,
                user_agent=user_agent,
                details={'challenge_id': str(challenge.challenge_id)}
            )
            
            logger.info(f"Login challenge generated for user: {user.user_id}")
            
            return {
                'success': True,
                'challenge_id': str(challenge.challenge_id),
                'nonce': nonce_b64,
                'expires_in': 300,  # 5 minutes
                'message': 'Challenge generated successfully'
            }
            
        except Exception as e:
            logger.error(f"Error initiating login: {e}")
            return {
                'success': False,
                'error': 'Internal server error'
            }
    
    def verify_login(self, challenge_id, signature, ip_address=None, user_agent=None):
        """
        Verify login challenge and create session
        
        Args:
            challenge_id: Challenge UUID
            signature: Signature of the challenge
            ip_address: Optional IP address
            user_agent: Optional user agent
            
        Returns:
            dict: Authentication result with session info
        """
        try:
            # Get challenge from database
            challenge = self.db_manager.get_valid_challenge(challenge_id, None)  # We'll find user from challenge
            if not challenge:
                return {
                    'success': False,
                    'error': 'Invalid or expired challenge'
                }
            
            # Get user
            user = self.db_manager.get_user_by_id(challenge.user_id)
            if not user:
                return {
                    'success': False,
                    'error': 'User not found'
                }
            
            # Deserialize public key
            public_key = ecc_ops.deserialize_public_key(user.public_key_pem)
            
            # Verify signature
            is_valid = ecdsa_handler.verify_challenge(
                public_key=public_key,
                nonce=challenge.nonce,
                signature=signature
            )
            
            if not is_valid:
                # Log failed authentication
                self.db_manager.log_auth_event(
                    user_id=user.user_id,
                    event_type='login',
                    success=False,
                    ip_address=ip_address,
                    user_agent=user_agent,
                    details={'error': 'Invalid signature', 'challenge_id': str(challenge_id)}
                )
                
                return {
                    'success': False,
                    'error': 'Invalid signature'
                }
            
            # Mark challenge as used
            self.db_manager.mark_challenge_used(challenge_id)
            
            # Update last login
            self.db_manager.update_last_login(user.user_id)
            
            # Generate session token
            session_token = self._generate_session_token(user.user_id)
            
            # Create session in database
            session = self.db_manager.create_session(
                user_id=user.user_id,
                session_token=session_token,
                ip_address=ip_address,
                user_agent=user_agent
            )
            
            # Log successful authentication
            self.db_manager.log_auth_event(
                user_id=user.user_id,
                event_type='login',
                success=True,
                ip_address=ip_address,
                user_agent=user_agent,
                details={'session_id': str(session.session_id)}
            )
            
            logger.info(f"User authenticated successfully: {user.user_id}")
            
            return {
                'success': True,
                'user_id': str(user.user_id),
                'email': user.email,
                'name': user.name,
                'session_token': session_token,
                'expires_at': session.expires_at.isoformat(),
                'message': 'Authentication successful'
            }
            
        except Exception as e:
            logger.error(f"Error verifying login: {e}")
            return {
                'success': False,
                'error': 'Internal server error'
            }
    
    def logout(self, session_token, ip_address=None, user_agent=None):
        """
        Logout user by invalidating session
        
        Args:
            session_token: Session token
            ip_address: Optional IP address
            user_agent: Optional user agent
            
        Returns:
            dict: Logout result
        """
        try:
            # Get session
            session = self.db_manager.get_valid_session(session_token)
            if not session:
                return {
                    'success': False,
                    'error': 'Invalid session'
                }
            
            # Invalidate session
            self.db_manager.invalidate_session(session_token)
            
            # Log logout event
            self.db_manager.log_auth_event(
                user_id=session.user_id,
                event_type='logout',
                success=True,
                ip_address=ip_address,
                user_agent=user_agent
            )
            
            logger.info(f"User logged out: {session.user_id}")
            
            return {
                'success': True,
                'message': 'Logged out successfully'
            }
            
        except Exception as e:
            logger.error(f"Error during logout: {e}")
            return {
                'success': False,
                'error': 'Internal server error'
            }
    
    def validate_session(self, session_token):
        """
        Validate session token
        
        Args:
            session_token: Session token
            
        Returns:
            dict: Session validation result
        """
        try:
            session = self.db_manager.get_valid_session(session_token)
            if not session:
                return {
                    'success': False,
                    'error': 'Invalid or expired session'
                }
            
            # Get user info
            user = self.db_manager.get_user_by_id(session.user_id)
            if not user:
                return {
                    'success': False,
                    'error': 'User not found'
                }
            
            return {
                'success': True,
                'user_id': str(user.user_id),
                'email': user.email,
                'name': user.name,
                'session_id': str(session.session_id),
                'expires_at': session.expires_at.isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error validating session: {e}")
            return {
                'success': False,
                'error': 'Internal server error'
            }
    
    def establish_secure_session(self, user_id, client_public_key_pem, ip_address=None, user_agent=None):
        """
        Establish a secure session using ECDH
        
        Args:
            user_id: User's UUID
            client_public_key_pem: Client's ephemeral public key
            ip_address: Optional IP address
            user_agent: Optional user agent
            
        Returns:
            dict: Secure session establishment result
        """
        try:
            # Get user
            user = self.db_manager.get_user_by_id(user_id)
            if not user:
                return {
                    'success': False,
                    'error': 'User not found'
                }
            
            # Generate server ephemeral keypair
            server_private_key, server_public_key = ecdh_handler.generate_ephemeral_keypair()
            
            # Deserialize client public key
            client_public_key = ecc_ops.deserialize_public_key(client_public_key_pem)
            
            # Compute shared secret
            shared_secret = ecdh_handler.compute_shared_secret(server_private_key, client_public_key)
            
            # Derive session key
            session_key, salt = ecdh_handler.derive_session_key(shared_secret)
            
            # Create session token
            session_token = ecdh_handler.create_session_token(session_key, user_id, datetime.utcnow().isoformat())
            
            # Create session in database
            session = self.db_manager.create_session(
                user_id=user.user_id,
                session_token=session_token,
                ip_address=ip_address,
                user_agent=user_agent
            )
            
            # Serialize server public key for transmission
            server_public_key_b64 = ecdh_handler.serialize_public_key_for_transmission(server_public_key)
            
            # Log secure session establishment
            self.db_manager.log_auth_event(
                user_id=user.user_id,
                event_type='secure_session_established',
                success=True,
                ip_address=ip_address,
                user_agent=user_agent,
                details={'session_id': str(session.session_id)}
            )
            
            logger.info(f"Secure session established for user: {user.user_id}")
            
            return {
                'success': True,
                'session_token': session_token,
                'server_public_key': server_public_key_b64,
                'salt': base64.b64encode(salt).decode('utf-8'),
                'expires_at': session.expires_at.isoformat(),
                'message': 'Secure session established'
            }
            
        except Exception as e:
            logger.error(f"Error establishing secure session: {e}")
            return {
                'success': False,
                'error': 'Internal server error'
            }
    
    def _generate_session_token(self, user_id):
        """
        Generate a unique session token
        
        Args:
            user_id: User's UUID
            
        Returns:
            str: Session token
        """
        # Generate a unique token using user_id and timestamp
        timestamp = datetime.utcnow().isoformat()
        token_data = f"{user_id}:{timestamp}:{uuid.uuid4()}"
        
        # For simplicity, we'll use a hash-based approach
        # In production, you might want to use JWT or a more sophisticated token system
        import hashlib
        token_hash = hashlib.sha256(token_data.encode('utf-8')).hexdigest()
        
        return token_hash 