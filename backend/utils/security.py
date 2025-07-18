"""
Security Utilities
Additional security functions for the ECC MFA system.
"""

import logging
import hashlib
import secrets
import re
from typing import Optional

logger = logging.getLogger(__name__)

class SecurityUtils:
    """Security utility functions"""
    
    @staticmethod
    def validate_email(email: str) -> bool:
        """
        Validate email format
        
        Args:
            email: Email address to validate
            
        Returns:
            bool: True if valid, False otherwise
        """
        if not email:
            return False
        
        # Basic email validation regex
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email))
    
    @staticmethod
    def generate_secure_token(length: int = 32) -> str:
        """
        Generate a cryptographically secure token
        
        Args:
            length: Length of token in bytes
            
        Returns:
            str: Hex-encoded token
        """
        return secrets.token_hex(length)
    
    @staticmethod
    def hash_data(data: str, salt: Optional[str] = None) -> str:
        """
        Hash data with optional salt
        
        Args:
            data: Data to hash
            salt: Optional salt
            
        Returns:
            str: Hex-encoded hash
        """
        if salt:
            data = salt + data
        
        return hashlib.sha256(data.encode('utf-8')).hexdigest()
    
    @staticmethod
    def validate_public_key_format(public_key_pem: str) -> bool:
        """
        Basic validation of PEM public key format
        
        Args:
            public_key_pem: PEM formatted public key
            
        Returns:
            bool: True if format appears valid, False otherwise
        """
        if not public_key_pem:
            return False
        
        # Check for PEM format indicators
        lines = public_key_pem.strip().split('\n')
        if len(lines) < 3:
            return False
        
        # Check header and footer
        if not lines[0].startswith('-----BEGIN PUBLIC KEY-----'):
            return False
        
        if not lines[-1].startswith('-----END PUBLIC KEY-----'):
            return False
        
        return True
    
    @staticmethod
    def sanitize_input(input_str: str, max_length: int = 255) -> str:
        """
        Sanitize user input
        
        Args:
            input_str: Input string to sanitize
            max_length: Maximum allowed length
            
        Returns:
            str: Sanitized string
        """
        if not input_str:
            return ""
        
        # Remove null bytes and control characters
        sanitized = ''.join(char for char in input_str if ord(char) >= 32)
        
        # Limit length
        if len(sanitized) > max_length:
            sanitized = sanitized[:max_length]
        
        return sanitized.strip()
    
    @staticmethod
    def validate_ip_address(ip_address: str) -> bool:
        """
        Validate IP address format
        
        Args:
            ip_address: IP address to validate
            
        Returns:
            bool: True if valid, False otherwise
        """
        if not ip_address:
            return False
        
        # Basic IPv4 validation
        parts = ip_address.split('.')
        if len(parts) != 4:
            return False
        
        try:
            for part in parts:
                if not 0 <= int(part) <= 255:
                    return False
        except ValueError:
            return False
        
        return True
    
    @staticmethod
    def rate_limit_key(identifier: str, action: str) -> str:
        """
        Generate rate limiting key
        
        Args:
            identifier: User identifier (IP, user_id, etc.)
            action: Action being rate limited
            
        Returns:
            str: Rate limiting key
        """
        return f"rate_limit:{action}:{identifier}"
    
    @staticmethod
    def generate_device_fingerprint(user_agent: str, ip_address: str) -> str:
        """
        Generate device fingerprint for security
        
        Args:
            user_agent: User agent string
            ip_address: IP address
            
        Returns:
            str: Device fingerprint hash
        """
        fingerprint_data = f"{user_agent}:{ip_address}"
        return hashlib.sha256(fingerprint_data.encode('utf-8')).hexdigest()
    
    @staticmethod
    def validate_session_token_format(token: str) -> bool:
        """
        Validate session token format
        
        Args:
            token: Session token to validate
            
        Returns:
            bool: True if format appears valid, False otherwise
        """
        if not token:
            return False
        
        # Check if token is a valid hex string of appropriate length
        if len(token) != 64:  # SHA-256 hash length
            return False
        
        try:
            int(token, 16)
            return True
        except ValueError:
            return False
    
    @staticmethod
    def log_security_event(event_type: str, user_id: str, ip_address: str, 
                          success: bool, details: Optional[dict] = None):
        """
        Log security event
        
        Args:
            event_type: Type of security event
            user_id: User identifier
            ip_address: IP address
            success: Whether the event was successful
            details: Optional additional details
        """
        from datetime import datetime
        
        log_data = {
            'event_type': event_type,
            'user_id': user_id,
            'ip_address': ip_address,
            'success': success,
            'timestamp': datetime.utcnow().isoformat()
        }
        
        if details:
            log_data['details'] = details
        
        if success:
            logger.info(f"Security event: {log_data}")
        else:
            logger.warning(f"Security event: {log_data}")
    
    @staticmethod
    def check_password_strength(password: str) -> dict:
        """
        Check password strength (for any password-based fallback)
        
        Args:
            password: Password to check
            
        Returns:
            dict: Password strength assessment
        """
        if not password:
            return {'strong': False, 'score': 0, 'issues': ['Password is empty']}
        
        score = 0
        issues = []
        
        # Length check
        if len(password) >= 8:
            score += 1
        else:
            issues.append('Password should be at least 8 characters long')
        
        # Character variety checks
        if re.search(r'[a-z]', password):
            score += 1
        else:
            issues.append('Password should contain lowercase letters')
        
        if re.search(r'[A-Z]', password):
            score += 1
        else:
            issues.append('Password should contain uppercase letters')
        
        if re.search(r'\d', password):
            score += 1
        else:
            issues.append('Password should contain numbers')
        
        if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            score += 1
        else:
            issues.append('Password should contain special characters')
        
        # Strength assessment
        if score >= 4:
            strength = 'strong'
        elif score >= 3:
            strength = 'medium'
        else:
            strength = 'weak'
        
        return {
            'strong': score >= 4,
            'score': score,
            'strength': strength,
            'issues': issues
        } 