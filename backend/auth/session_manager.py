"""
Session Manager Module
Handles user session management and security operations.
"""

import logging
import redis
import json
from datetime import datetime, timedelta
from database.db_operations import DatabaseManager

logger = logging.getLogger(__name__)

class SessionManager:
    """Manages user sessions and security operations"""
    
    def __init__(self, db_manager, redis_url, session_timeout=3600):
        self.db_manager = db_manager
        self.redis_client = redis.from_url(redis_url)
        self.session_timeout = session_timeout
    
    def create_session(self, user_id, session_data, ip_address=None, user_agent=None):
        """
        Create a new user session
        
        Args:
            user_id: User's UUID
            session_data: Session data dictionary
            ip_address: Optional IP address
            user_agent: Optional user agent
            
        Returns:
            dict: Session creation result
        """
        try:
            # Generate session token
            session_token = self._generate_session_token(user_id)
            
            # Store session in database
            session = self.db_manager.create_session(
                user_id=user_id,
                session_token=session_token,
                ip_address=ip_address,
                user_agent=user_agent
            )
            
            # Store session data in Redis for fast access
            redis_key = f"session:{session_token}"
            session_data['session_id'] = str(session.session_id)
            session_data['created_at'] = datetime.utcnow().isoformat()
            session_data['expires_at'] = session.expires_at.isoformat()
            
            self.redis_client.setex(
                redis_key,
                self.session_timeout,
                json.dumps(session_data)
            )
            
            logger.info(f"Session created for user: {user_id}")
            
            return {
                'success': True,
                'session_token': session_token,
                'session_id': str(session.session_id),
                'expires_at': session.expires_at.isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error creating session: {e}")
            return {
                'success': False,
                'error': 'Internal server error'
            }
    
    def get_session(self, session_token):
        """
        Get session data
        
        Args:
            session_token: Session token
            
        Returns:
            dict: Session data or None if not found
        """
        try:
            # Try Redis first
            redis_key = f"session:{session_token}"
            session_data = self.redis_client.get(redis_key)
            
            if session_data:
                return json.loads(session_data)
            
            # Fallback to database
            session = self.db_manager.get_valid_session(session_token)
            if not session:
                return None
            
            # Get user info
            user = self.db_manager.get_user_by_id(session.user_id)
            if not user:
                return None
            
            # Reconstruct session data
            session_data = {
                'user_id': str(user.user_id),
                'email': user.email,
                'name': user.name,
                'session_id': str(session.session_id),
                'created_at': session.created_at.isoformat(),
                'expires_at': session.expires_at.isoformat(),
                'ip_address': session.ip_address,
                'user_agent': session.user_agent
            }
            
            # Cache in Redis
            self.redis_client.setex(
                redis_key,
                self.session_timeout,
                json.dumps(session_data)
            )
            
            return session_data
            
        except Exception as e:
            logger.error(f"Error getting session: {e}")
            return None
    
    def update_session(self, session_token, session_data):
        """
        Update session data
        
        Args:
            session_token: Session token
            session_data: Updated session data
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # Update Redis
            redis_key = f"session:{session_token}"
            current_data = self.redis_client.get(redis_key)
            
            if current_data:
                current_data = json.loads(current_data)
                current_data.update(session_data)
                
                self.redis_client.setex(
                    redis_key,
                    self.session_timeout,
                    json.dumps(current_data)
                )
                
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Error updating session: {e}")
            return False
    
    def invalidate_session(self, session_token, ip_address=None, user_agent=None):
        """
        Invalidate a session
        
        Args:
            session_token: Session token
            ip_address: Optional IP address
            user_agent: Optional user agent
            
        Returns:
            dict: Invalidation result
        """
        try:
            # Get session info before invalidation
            session = self.db_manager.get_valid_session(session_token)
            if not session:
                return {
                    'success': False,
                    'error': 'Session not found'
                }
            
            # Invalidate in database
            self.db_manager.invalidate_session(session_token)
            
            # Remove from Redis
            redis_key = f"session:{session_token}"
            self.redis_client.delete(redis_key)
            
            # Log logout event
            self.db_manager.log_auth_event(
                user_id=session.user_id,
                event_type='logout',
                success=True,
                ip_address=ip_address,
                user_agent=user_agent
            )
            
            logger.info(f"Session invalidated: {session_token}")
            
            return {
                'success': True,
                'message': 'Session invalidated successfully'
            }
            
        except Exception as e:
            logger.error(f"Error invalidating session: {e}")
            return {
                'success': False,
                'error': 'Internal server error'
            }
    
    def refresh_session(self, session_token):
        """
        Refresh session expiry
        
        Args:
            session_token: Session token
            
        Returns:
            dict: Refresh result
        """
        try:
            session = self.db_manager.get_valid_session(session_token)
            if not session:
                return {
                    'success': False,
                    'error': 'Session not found'
                }
            
            # Update session expiry in database
            new_expires_at = datetime.utcnow() + timedelta(hours=1)
            session.expires_at = new_expires_at
            
            # Update Redis
            redis_key = f"session:{session_token}"
            session_data = self.redis_client.get(redis_key)
            
            if session_data:
                session_data = json.loads(session_data)
                session_data['expires_at'] = new_expires_at.isoformat()
                
                self.redis_client.setex(
                    redis_key,
                    self.session_timeout,
                    json.dumps(session_data)
                )
            
            logger.info(f"Session refreshed: {session_token}")
            
            return {
                'success': True,
                'expires_at': new_expires_at.isoformat(),
                'message': 'Session refreshed successfully'
            }
            
        except Exception as e:
            logger.error(f"Error refreshing session: {e}")
            return {
                'success': False,
                'error': 'Internal server error'
            }
    
    def get_user_sessions(self, user_id):
        """
        Get all active sessions for a user
        
        Args:
            user_id: User's UUID
            
        Returns:
            list: List of active sessions
        """
        try:
            # Get sessions from database
            sessions = self.db_manager.get_user_sessions(user_id)
            
            session_list = []
            for session in sessions:
                session_info = {
                    'session_id': str(session.session_id),
                    'created_at': session.created_at.isoformat(),
                    'expires_at': session.expires_at.isoformat(),
                    'ip_address': session.ip_address,
                    'user_agent': session.user_agent,
                    'is_active': session.is_active
                }
                session_list.append(session_info)
            
            return session_list
            
        except Exception as e:
            logger.error(f"Error getting user sessions: {e}")
            return []
    
    def invalidate_all_user_sessions(self, user_id, except_session_token=None):
        """
        Invalidate all sessions for a user except the specified one
        
        Args:
            user_id: User's UUID
            except_session_token: Session token to exclude from invalidation
            
        Returns:
            dict: Invalidation result
        """
        try:
            sessions = self.db_manager.get_user_sessions(user_id)
            invalidated_count = 0
            
            for session in sessions:
                if except_session_token and session.session_token == except_session_token:
                    continue
                
                # Invalidate session
                self.db_manager.invalidate_session(session.session_token)
                
                # Remove from Redis
                redis_key = f"session:{session.session_token}"
                self.redis_client.delete(redis_key)
                
                invalidated_count += 1
            
            logger.info(f"Invalidated {invalidated_count} sessions for user: {user_id}")
            
            return {
                'success': True,
                'invalidated_count': invalidated_count,
                'message': f'Invalidated {invalidated_count} sessions'
            }
            
        except Exception as e:
            logger.error(f"Error invalidating user sessions: {e}")
            return {
                'success': False,
                'error': 'Internal server error'
            }
    
    def cleanup_expired_sessions(self):
        """Clean up expired sessions from database and Redis"""
        try:
            # Clean up database
            self.db_manager.cleanup_expired_sessions()
            
            # Clean up Redis (Redis handles expiry automatically)
            # But we can scan for expired keys if needed
            expired_keys = []
            for key in self.redis_client.scan_iter("session:*"):
                if not self.redis_client.exists(key):
                    expired_keys.append(key)
            
            if expired_keys:
                self.redis_client.delete(*expired_keys)
                logger.info(f"Cleaned up {len(expired_keys)} expired Redis sessions")
            
            logger.info("Session cleanup completed")
            
        except Exception as e:
            logger.error(f"Error during session cleanup: {e}")
    
    def _generate_session_token(self, user_id):
        """
        Generate a unique session token
        
        Args:
            user_id: User's UUID
            
        Returns:
            str: Session token
        """
        import hashlib
        import uuid
        
        timestamp = datetime.utcnow().isoformat()
        random_uuid = str(uuid.uuid4())
        token_data = f"{user_id}:{timestamp}:{random_uuid}"
        
        token_hash = hashlib.sha256(token_data.encode('utf-8')).hexdigest()
        return token_hash 