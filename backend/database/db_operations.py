"""
Database Operations
Handles all database operations for the ECC MFA system.
"""

import uuid
import json
import logging
from datetime import datetime, timedelta
from sqlalchemy.orm import Session as DBSession
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from .models import User, AuthLog, Session, Challenge, Device, create_database_engine, create_session_factory

logger = logging.getLogger(__name__)

class DatabaseManager:
    """Manages database operations for the ECC MFA system"""
    
    def __init__(self, database_url):
        self.engine = create_database_engine(database_url)
        self.SessionLocal = create_session_factory(self.engine)
    
    def get_session(self):
        """Get a new database session"""
        return self.SessionLocal()
    
    def init_database(self):
        """Initialize database tables"""
        from .models import init_database
        init_database(self.engine)
        logger.info("Database initialized successfully")
    
    # User operations
    def create_user(self, email, public_key_bytes, public_key_pem, name=None):
        """
        Create a new user
        
        Args:
            email: User's email address
            public_key_bytes: Raw public key bytes
            public_key_pem: PEM formatted public key
            name: Optional user name
            
        Returns:
            User: Created user object
        """
        session = self.get_session()
        try:
            user = User(
                email=email,
                public_key=public_key_bytes,
                public_key_pem=public_key_pem,
                name=name
            )
            session.add(user)
            session.commit()
            session.refresh(user)
            logger.info(f"User created successfully: {user.user_id}")
            return user
        except IntegrityError:
            session.rollback()
            logger.error(f"User with email {email} already exists")
            raise ValueError("User with this email already exists")
        except Exception as e:
            session.rollback()
            logger.error(f"Error creating user: {e}")
            raise
        finally:
            session.close()
    
    def get_user_by_email(self, email):
        """
        Get user by email address
        
        Args:
            email: User's email address
            
        Returns:
            User: User object or None if not found
        """
        session = self.get_session()
        try:
            user = session.query(User).filter(User.email == email, User.is_active == True).first()
            return user
        except Exception as e:
            logger.error(f"Error getting user by email: {e}")
            raise
        finally:
            session.close()
    
    def get_user_by_id(self, user_id):
        """
        Get user by user ID
        
        Args:
            user_id: User's UUID
            
        Returns:
            User: User object or None if not found
        """
        session = self.get_session()
        try:
            user = session.query(User).filter(User.user_id == user_id, User.is_active == True).first()
            return user
        except Exception as e:
            logger.error(f"Error getting user by ID: {e}")
            raise
        finally:
            session.close()
    
    def update_last_login(self, user_id):
        """
        Update user's last login timestamp
        
        Args:
            user_id: User's UUID
        """
        session = self.get_session()
        try:
            user = session.query(User).filter(User.user_id == user_id).first()
            if user:
                user.last_login = datetime.utcnow()
                session.commit()
                logger.info(f"Updated last login for user: {user_id}")
        except Exception as e:
            session.rollback()
            logger.error(f"Error updating last login: {e}")
            raise
        finally:
            session.close()
    
    # Challenge operations
    def create_challenge(self, user_id, nonce, ip_address=None):
        """
        Create a new authentication challenge
        
        Args:
            user_id: User's UUID
            nonce: Challenge nonce
            ip_address: Optional IP address
            
        Returns:
            Challenge: Created challenge object
        """
        session = self.get_session()
        try:
            challenge = Challenge(
                user_id=user_id,
                nonce=nonce,
                expires_at=datetime.utcnow() + timedelta(minutes=5),  # 5 minute expiry
                ip_address=ip_address
            )
            session.add(challenge)
            session.commit()
            session.refresh(challenge)
            logger.info(f"Challenge created for user: {user_id}")
            return challenge
        except Exception as e:
            session.rollback()
            logger.error(f"Error creating challenge: {e}")
            raise
        finally:
            session.close()
    
    def get_valid_challenge(self, challenge_id, user_id):
        """
        Get a valid challenge by ID and user
        
        Args:
            challenge_id: Challenge UUID
            user_id: User's UUID
            
        Returns:
            Challenge: Challenge object or None if not found/expired
        """
        session = self.get_session()
        try:
            challenge = session.query(Challenge).filter(
                Challenge.challenge_id == challenge_id,
                Challenge.user_id == user_id,
                Challenge.expires_at > datetime.utcnow(),
                Challenge.is_used == False
            ).first()
            return challenge
        except Exception as e:
            logger.error(f"Error getting challenge: {e}")
            raise
        finally:
            session.close()
    
    def mark_challenge_used(self, challenge_id):
        """
        Mark a challenge as used
        
        Args:
            challenge_id: Challenge UUID
        """
        session = self.get_session()
        try:
            challenge = session.query(Challenge).filter(Challenge.challenge_id == challenge_id).first()
            if challenge:
                challenge.is_used = True
                session.commit()
                logger.info(f"Challenge marked as used: {challenge_id}")
        except Exception as e:
            session.rollback()
            logger.error(f"Error marking challenge as used: {e}")
            raise
        finally:
            session.close()
    
    # Session operations
    def create_session(self, user_id, session_token, ip_address=None, user_agent=None):
        """
        Create a new user session
        
        Args:
            user_id: User's UUID
            session_token: Session token
            ip_address: Optional IP address
            user_agent: Optional user agent
            
        Returns:
            Session: Created session object
        """
        session = self.get_session()
        try:
            db_session = Session(
                user_id=user_id,
                session_token=session_token,
                expires_at=datetime.utcnow() + timedelta(hours=1),  # 1 hour expiry
                ip_address=ip_address,
                user_agent=user_agent
            )
            session.add(db_session)
            session.commit()
            session.refresh(db_session)
            logger.info(f"Session created for user: {user_id}")
            return db_session
        except Exception as e:
            session.rollback()
            logger.error(f"Error creating session: {e}")
            raise
        finally:
            session.close()
    
    def get_valid_session(self, session_token):
        """
        Get a valid session by token
        
        Args:
            session_token: Session token
            
        Returns:
            Session: Session object or None if not found/expired
        """
        session = self.get_session()
        try:
            db_session = session.query(Session).filter(
                Session.session_token == session_token,
                Session.expires_at > datetime.utcnow(),
                Session.is_active == True
            ).first()
            return db_session
        except Exception as e:
            logger.error(f"Error getting session: {e}")
            raise
        finally:
            session.close()
    
    def invalidate_session(self, session_token):
        """
        Invalidate a session
        
        Args:
            session_token: Session token
        """
        session = self.get_session()
        try:
            db_session = session.query(Session).filter(Session.session_token == session_token).first()
            if db_session:
                db_session.is_active = False
                session.commit()
                logger.info(f"Session invalidated: {session_token}")
        except Exception as e:
            session.rollback()
            logger.error(f"Error invalidating session: {e}")
            raise
        finally:
            session.close()
    
    def cleanup_expired_sessions(self):
        """Clean up expired sessions"""
        session = self.get_session()
        try:
            expired_sessions = session.query(Session).filter(
                Session.expires_at < datetime.utcnow()
            ).all()
            
            for db_session in expired_sessions:
                db_session.is_active = False
            
            session.commit()
            logger.info(f"Cleaned up {len(expired_sessions)} expired sessions")
        except Exception as e:
            session.rollback()
            logger.error(f"Error cleaning up expired sessions: {e}")
            raise
        finally:
            session.close()
    
    # Authentication log operations
    def log_auth_event(self, user_id, event_type, success, ip_address=None, user_agent=None, details=None):
        """
        Log an authentication event
        
        Args:
            user_id: User's UUID
            event_type: Type of event ('login', 'logout', 'challenge', 'registration')
            success: Whether the event was successful
            ip_address: Optional IP address
            user_agent: Optional user agent
            details: Optional additional details
        """
        session = self.get_session()
        try:
            auth_log = AuthLog(
                user_id=user_id,
                event_type=event_type,
                success=success,
                ip_address=ip_address,
                user_agent=user_agent,
                details=json.dumps(details) if details else None
            )
            session.add(auth_log)
            session.commit()
            logger.info(f"Auth event logged: {event_type} for user {user_id}")
        except Exception as e:
            session.rollback()
            logger.error(f"Error logging auth event: {e}")
            raise
        finally:
            session.close()
    
    # Device operations
    def register_device(self, user_id, device_name, public_key_bytes, public_key_pem, device_type=None):
        """
        Register a new device for a user
        
        Args:
            user_id: User's UUID
            device_name: Name of the device
            public_key_bytes: Raw public key bytes
            public_key_pem: PEM formatted public key
            device_type: Optional device type
            
        Returns:
            Device: Created device object
        """
        session = self.get_session()
        try:
            device = Device(
                user_id=user_id,
                device_name=device_name,
                device_type=device_type,
                public_key=public_key_bytes,
                public_key_pem=public_key_pem
            )
            session.add(device)
            session.commit()
            session.refresh(device)
            logger.info(f"Device registered for user: {user_id}")
            return device
        except Exception as e:
            session.rollback()
            logger.error(f"Error registering device: {e}")
            raise
        finally:
            session.close()
    
    def get_user_devices(self, user_id):
        """
        Get all devices for a user
        
        Args:
            user_id: User's UUID
            
        Returns:
            list: List of Device objects
        """
        session = self.get_session()
        try:
            devices = session.query(Device).filter(
                Device.user_id == user_id,
                Device.is_active == True
            ).all()
            return devices
        except Exception as e:
            logger.error(f"Error getting user devices: {e}")
            raise
        finally:
            session.close()
    
    def deactivate_device(self, device_id, user_id):
        """
        Deactivate a device
        
        Args:
            device_id: Device UUID
            user_id: User's UUID
        """
        session = self.get_session()
        try:
            device = session.query(Device).filter(
                Device.device_id == device_id,
                Device.user_id == user_id
            ).first()
            if device:
                device.is_active = False
                session.commit()
                logger.info(f"Device deactivated: {device_id}")
        except Exception as e:
            session.rollback()
            logger.error(f"Error deactivating device: {e}")
            raise
        finally:
            session.close() 