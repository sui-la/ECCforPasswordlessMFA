"""
Database Models
Defines the database schema for the ECC MFA system.
"""

import uuid
from datetime import datetime
from sqlalchemy import create_engine, Column, String, DateTime, Boolean, Text, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.dialects.postgresql import UUID, BYTEA
from sqlalchemy.orm import sessionmaker, relationship

Base = declarative_base()

class User(Base):
    """User model for storing user information and public keys"""
    __tablename__ = 'users'
    
    user_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email = Column(String(255), unique=True, nullable=False)
    name = Column(String(255), nullable=True)
    public_key = Column(BYTEA, nullable=False)  # Raw public key bytes
    public_key_pem = Column(Text, nullable=False)  # PEM formatted public key
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    last_login = Column(DateTime, nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)
    
    # Relationships
    auth_logs = relationship("AuthLog", back_populates="user")
    sessions = relationship("Session", back_populates="user")
    
    def __repr__(self):
        return f"<User(user_id={self.user_id}, email='{self.email}')>"

class AuthLog(Base):
    """Authentication log for audit trail"""
    __tablename__ = 'auth_logs'
    
    log_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey('users.user_id'), nullable=False)
    event_type = Column(String(50), nullable=False)  # 'login', 'logout', 'challenge', 'registration'
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    success = Column(Boolean, nullable=False)
    details = Column(Text, nullable=True)  # Additional details in JSON format
    
    # Relationships
    user = relationship("User", back_populates="auth_logs")
    
    def __repr__(self):
        return f"<AuthLog(log_id={self.log_id}, user_id={self.user_id}, event_type='{self.event_type}')>"

class Session(Base):
    """Session management for authenticated users"""
    __tablename__ = 'sessions'
    
    session_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey('users.user_id'), nullable=False)
    session_token = Column(String(255), unique=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(Text, nullable=True)
    
    # Relationships
    user = relationship("User", back_populates="sessions")
    
    def __repr__(self):
        return f"<Session(session_id={self.session_id}, user_id={self.user_id})>"

class Challenge(Base):
    """Challenge storage for authentication flow"""
    __tablename__ = 'challenges'
    
    challenge_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey('users.user_id'), nullable=False)
    nonce = Column(BYTEA, nullable=False)  # Challenge nonce
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    is_used = Column(Boolean, default=False, nullable=False)
    ip_address = Column(String(45), nullable=True)
    
    def __repr__(self):
        return f"<Challenge(challenge_id={self.challenge_id}, user_id={self.user_id})>"

class Device(Base):
    """Device registration for multi-device support"""
    __tablename__ = 'devices'
    
    device_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey('users.user_id'), nullable=False)
    device_name = Column(String(255), nullable=False)
    device_type = Column(String(50), nullable=True)  # 'web', 'mobile', 'desktop'
    public_key = Column(BYTEA, nullable=False)
    public_key_pem = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    last_used = Column(DateTime, nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)
    
    def __repr__(self):
        return f"<Device(device_id={self.device_id}, user_id={self.user_id}, name='{self.device_name}')>"

# Database connection setup
def create_database_engine(database_url):
    """Create SQLAlchemy engine for database connection"""
    return create_engine(database_url, echo=False)

def create_session_factory(engine):
    """Create session factory for database operations"""
    return sessionmaker(bind=engine)

def init_database(engine):
    """Initialize database tables"""
    Base.metadata.create_all(engine) 