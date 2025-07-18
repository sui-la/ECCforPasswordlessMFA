"""
Main Flask Application
ECC-based Passwordless MFA System
"""

import logging
import os
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
from config import config
from database.db_operations import DatabaseManager
from auth.registration import RegistrationHandler
from auth.authentication import AuthenticationHandler
from auth.session_manager import SessionManager
from utils.security import SecurityUtils

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def create_app(config_name='default'):
    """Create and configure Flask application"""
    app = Flask(__name__)
    
    # Load configuration
    app.config.from_object(config[config_name])
    
    # Initialize security middleware
    Talisman(app, content_security_policy={
        'default-src': ["'self'"],
        'script-src': ["'self'", "'unsafe-inline'"],
        'style-src': ["'self'", "'unsafe-inline'"],
        'img-src': ["'self'", "data:", "https:"],
    })
    
    # Initialize CORS with permissive configuration for development
    CORS(app, 
         origins=['http://localhost:3000', 'http://127.0.0.1:3000', 'http://frontend:3000', 'http://backend:5000'],
         supports_credentials=True,
         methods=['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
         allow_headers=['Content-Type', 'Authorization', 'X-Requested-With', 'Origin', 'Accept'])
    
    # Initialize rate limiting
    limiter = Limiter(
        app=app,
        key_func=get_remote_address,
        default_limits=[app.config['RATE_LIMIT_DEFAULT']],
        storage_uri=app.config['RATE_LIMIT_STORAGE_URL']
    )
    
    # Initialize database
    db_manager = DatabaseManager(app.config['DATABASE_URL'])
    db_manager.init_database()
    
    # Initialize handlers
    registration_handler = RegistrationHandler(db_manager)
    auth_handler = AuthenticationHandler(db_manager, app.config['JWT_SECRET_KEY'])
    session_manager = SessionManager(db_manager, app.config['REDIS_URL'])
    security_utils = SecurityUtils()
    
    # Health check endpoint
    @app.route('/health', methods=['GET'])
    def health_check():
        """Health check endpoint"""
        return jsonify({
            'status': 'healthy',
            'service': 'ECC MFA Backend',
            'version': '1.0.0'
        })
    
    # Registration endpoints
    @app.route('/api/auth/register', methods=['POST'])
    @limiter.limit("5 per minute")
    def register_user():
        """Register a new user"""
        try:
            data = request.get_json()
            
            if not data:
                return jsonify({'error': 'No data provided'}), 400
            
            email = data.get('email')
            public_key_pem = data.get('public_key')
            name = data.get('name')
            
            if not email or not public_key_pem:
                return jsonify({'error': 'Email and public key are required'}), 400
            
            # Get client information
            ip_address = request.remote_addr
            user_agent = request.headers.get('User-Agent')
            
            result = registration_handler.register_user(
                email=email,
                public_key_pem=public_key_pem,
                name=name,
                ip_address=ip_address,
                user_agent=user_agent
            )
            
            if result['success']:
                return jsonify(result), 201
            else:
                return jsonify(result), 400
                
        except Exception as e:
            logger.error(f"Registration error: {e}")
            return jsonify({'error': 'Internal server error'}), 500
    
    @app.route('/api/auth/register/check-email', methods=['POST', 'OPTIONS'])
    @limiter.limit("10 per minute")
    def check_email_availability():
        """Check if email is available for registration"""
        if request.method == 'OPTIONS':
            return '', 204
        try:
            data = request.get_json()
            
            if not data or 'email' not in data:
                return jsonify({'error': 'Email is required'}), 400
            
            result = registration_handler.check_email_availability(data['email'])
            return jsonify(result)
            
        except Exception as e:
            logger.error(f"Email check error: {e}")
            return jsonify({'error': 'Internal server error'}), 500
    
    @app.route('/api/auth/register/challenge', methods=['POST'])
    @limiter.limit("5 per minute")
    def generate_registration_challenge():
        """Generate challenge for registration verification"""
        try:
            data = request.get_json()
            
            if not data or 'email' not in data:
                return jsonify({'error': 'Email is required'}), 400
            
            ip_address = request.remote_addr
            result = registration_handler.generate_registration_challenge(
                email=data['email'],
                ip_address=ip_address
            )
            
            if result['success']:
                return jsonify(result)
            else:
                return jsonify(result), 400
                
        except Exception as e:
            logger.error(f"Challenge generation error: {e}")
            return jsonify({'error': 'Internal server error'}), 500
    
    @app.route('/api/auth/register/verify', methods=['POST'])
    @limiter.limit("5 per minute")
    def verify_registration():
        """Verify registration with challenge response"""
        try:
            data = request.get_json()
            
            if not data:
                return jsonify({'error': 'No data provided'}), 400
            
            email = data.get('email')
            challenge_nonce = data.get('nonce')
            signature = data.get('signature')
            
            if not all([email, challenge_nonce, signature]):
                return jsonify({'error': 'Email, nonce, and signature are required'}), 400
            
            ip_address = request.remote_addr
            user_agent = request.headers.get('User-Agent')
            
            result = registration_handler.verify_registration(
                email=email,
                challenge_nonce=challenge_nonce,
                signature=signature,
                ip_address=ip_address,
                user_agent=user_agent
            )
            
            if result['success']:
                return jsonify(result)
            else:
                return jsonify(result), 400
                
        except Exception as e:
            logger.error(f"Registration verification error: {e}")
            return jsonify({'error': 'Internal server error'}), 500
    
    # Authentication endpoints
    @app.route('/api/auth/login/initiate', methods=['POST'])
    @limiter.limit("10 per minute")
    def initiate_login():
        """Initiate login process"""
        try:
            data = request.get_json()
            
            if not data or 'email' not in data:
                return jsonify({'error': 'Email is required'}), 400
            
            ip_address = request.remote_addr
            user_agent = request.headers.get('User-Agent')
            
            result = auth_handler.initiate_login(
                email=data['email'],
                ip_address=ip_address,
                user_agent=user_agent
            )
            
            if result['success']:
                return jsonify(result)
            else:
                return jsonify(result), 400
                
        except Exception as e:
            logger.error(f"Login initiation error: {e}")
            return jsonify({'error': 'Internal server error'}), 500
    
    @app.route('/api/auth/login/verify', methods=['POST'])
    @limiter.limit("10 per minute")
    def verify_login():
        """Verify login challenge and create session"""
        try:
            data = request.get_json()
            
            if not data:
                return jsonify({'error': 'No data provided'}), 400
            
            challenge_id = data.get('challenge_id')
            signature = data.get('signature')
            
            if not all([challenge_id, signature]):
                return jsonify({'error': 'Challenge ID and signature are required'}), 400
            
            ip_address = request.remote_addr
            user_agent = request.headers.get('User-Agent')
            
            result = auth_handler.verify_login(
                challenge_id=challenge_id,
                signature=signature,
                ip_address=ip_address,
                user_agent=user_agent
            )
            
            if result['success']:
                return jsonify(result)
            else:
                return jsonify(result), 401
                
        except Exception as e:
            logger.error(f"Login verification error: {e}")
            return jsonify({'error': 'Internal server error'}), 500
    
    @app.route('/api/auth/logout', methods=['POST'])
    def logout():
        """Logout user"""
        try:
            data = request.get_json()
            
            if not data or 'session_token' not in data:
                return jsonify({'error': 'Session token is required'}), 400
            
            ip_address = request.remote_addr
            user_agent = request.headers.get('User-Agent')
            
            result = auth_handler.logout(
                session_token=data['session_token'],
                ip_address=ip_address,
                user_agent=user_agent
            )
            
            if result['success']:
                return jsonify(result)
            else:
                return jsonify(result), 400
                
        except Exception as e:
            logger.error(f"Logout error: {e}")
            return jsonify({'error': 'Internal server error'}), 500
    
    @app.route('/api/auth/session/validate', methods=['POST'])
    def validate_session():
        """Validate session token"""
        try:
            data = request.get_json()
            
            if not data or 'session_token' not in data:
                return jsonify({'error': 'Session token is required'}), 400
            
            result = auth_handler.validate_session(data['session_token'])
            
            if result['success']:
                return jsonify(result)
            else:
                return jsonify(result), 401
                
        except Exception as e:
            logger.error(f"Session validation error: {e}")
            return jsonify({'error': 'Internal server error'}), 500
    
    @app.route('/api/auth/session/refresh', methods=['POST'])
    def refresh_session():
        """Refresh session expiry"""
        try:
            data = request.get_json()
            
            if not data or 'session_token' not in data:
                return jsonify({'error': 'Session token is required'}), 400
            
            result = session_manager.refresh_session(data['session_token'])
            
            if result['success']:
                return jsonify(result)
            else:
                return jsonify(result), 400
                
        except Exception as e:
            logger.error(f"Session refresh error: {e}")
            return jsonify({'error': 'Internal server error'}), 500
    
    # Secure session endpoints
    @app.route('/api/auth/secure-session/establish', methods=['POST'])
    def establish_secure_session():
        """Establish secure session using ECDH"""
        try:
            data = request.get_json()
            
            if not data:
                return jsonify({'error': 'No data provided'}), 400
            
            user_id = data.get('user_id')
            client_public_key = data.get('client_public_key')
            
            if not all([user_id, client_public_key]):
                return jsonify({'error': 'User ID and client public key are required'}), 400
            
            ip_address = request.remote_addr
            user_agent = request.headers.get('User-Agent')
            
            result = auth_handler.establish_secure_session(
                user_id=user_id,
                client_public_key_pem=client_public_key,
                ip_address=ip_address,
                user_agent=user_agent
            )
            
            if result['success']:
                return jsonify(result)
            else:
                return jsonify(result), 400
                
        except Exception as e:
            logger.error(f"Secure session establishment error: {e}")
            return jsonify({'error': 'Internal server error'}), 500
    
    # User management endpoints
    @app.route('/api/user/profile', methods=['GET'])
    def get_user_profile():
        """Get user profile"""
        try:
            session_token = request.headers.get('Authorization', '').replace('Bearer ', '')
            
            if not session_token:
                return jsonify({'error': 'Authorization header required'}), 401
            
            session_data = session_manager.get_session(session_token)
            if not session_data:
                return jsonify({'error': 'Invalid session'}), 401
            
            user = db_manager.get_user_by_id(session_data['user_id'])
            if not user:
                return jsonify({'error': 'User not found'}), 404
            
            return jsonify({
                'user_id': str(user.user_id),
                'email': user.email,
                'name': user.name,
                'created_at': user.created_at.isoformat(),
                'last_login': user.last_login.isoformat() if user.last_login else None
            })
            
        except Exception as e:
            logger.error(f"Get user profile error: {e}")
            return jsonify({'error': 'Internal server error'}), 500
    
    @app.route('/api/user/sessions', methods=['GET'])
    def get_user_sessions():
        """Get user's active sessions"""
        try:
            session_token = request.headers.get('Authorization', '').replace('Bearer ', '')
            
            if not session_token:
                return jsonify({'error': 'Authorization header required'}), 401
            
            session_data = session_manager.get_session(session_token)
            if not session_data:
                return jsonify({'error': 'Invalid session'}), 401
            
            sessions = session_manager.get_user_sessions(session_data['user_id'])
            
            return jsonify({
                'sessions': sessions,
                'count': len(sessions)
            })
            
        except Exception as e:
            logger.error(f"Get user sessions error: {e}")
            return jsonify({'error': 'Internal server error'}), 500
    
    @app.route('/api/user/sessions/invalidate-all', methods=['POST'])
    def invalidate_all_sessions():
        """Invalidate all user sessions except current"""
        try:
            session_token = request.headers.get('Authorization', '').replace('Bearer ', '')
            
            if not session_token:
                return jsonify({'error': 'Authorization header required'}), 401
            
            session_data = session_manager.get_session(session_token)
            if not session_data:
                return jsonify({'error': 'Invalid session'}), 401
            
            result = session_manager.invalidate_all_user_sessions(
                user_id=session_data['user_id'],
                except_session_token=session_token
            )
            
            if result['success']:
                return jsonify(result)
            else:
                return jsonify(result), 400
                
        except Exception as e:
            logger.error(f"Invalidate all sessions error: {e}")
            return jsonify({'error': 'Internal server error'}), 500
    
    # Error handlers
    @app.errorhandler(404)
    def not_found(error):
        return jsonify({'error': 'Not found'}), 404
    
    @app.errorhandler(405)
    def method_not_allowed(error):
        return jsonify({'error': 'Method not allowed'}), 405
    
    @app.errorhandler(500)
    def internal_error(error):
        return jsonify({'error': 'Internal server error'}), 500
    
    return app

if __name__ == '__main__':
    app = create_app()
    app.run(debug=True, host='0.0.0.0', port=5000) 