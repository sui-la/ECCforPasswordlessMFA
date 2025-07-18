# ECC-based Passwordless Multi-Factor Authentication System

A modern, secure authentication system that replaces traditional passwords and OTPs with Elliptic Curve Cryptography (ECC) for enhanced security and user experience.

## 🚀 Features

- **Passwordless Authentication**: No passwords to remember or manage
- **ECC-based Security**: Uses Elliptic Curve Cryptography (P-256 curve)
- **Challenge-Response Protocol**: Prevents replay attacks
- **Session Management**: Secure session handling with Redis
- **Multi-Device Support**: Register multiple devices per user
- **Audit Logging**: Comprehensive authentication event logging
- **Rate Limiting**: Protection against brute force attacks
- **Modern UI**: React-based responsive interface

## 🏗️ Architecture

### Backend (Python/Flask)
- **ECC Operations**: Key generation, signing, verification
- **ECDSA**: Digital signature algorithm for authentication
- **ECDH**: Key exchange for secure sessions
- **PostgreSQL**: User data and session storage
- **Redis**: Session caching and rate limiting
- **Flask**: RESTful API with security middleware

### Frontend (React/TypeScript)
- **Web Crypto API**: Client-side cryptographic operations
- **React Router**: Navigation and protected routes
- **React Hook Form**: Form handling and validation
- **Styled Components**: Modern UI components
- **Toast Notifications**: User feedback

## 📋 Prerequisites

- Python 3.8+
- Node.js 16+
- Docker and Docker Compose
- PostgreSQL 15+
- Redis 6+

## 🛠️ Installation

### 1. Clone the Repository

```bash
git clone <repository-url>
cd ECCforPasswordlessMFA
```

### 2. Start Database Services

```bash
# Start PostgreSQL and Redis using Docker
docker-compose up -d postgres redis

# Or start all services including pgAdmin
docker-compose up -d
```

### 3. Backend Setup

```bash
cd backend

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Set up environment variables
cp .env.example .env
# Edit .env with your configuration

# Initialize database
python init_db.py

# Start the backend server
python app.py
```

### 4. Frontend Setup

```bash
cd frontend

# Install dependencies
npm install

# Start the development server
npm start
```

## 🔧 Configuration

### Backend Environment Variables

Create a `.env` file in the `backend` directory:

```env
# Database
DATABASE_URL=postgresql://hao:your_password_here@localhost/ecc_mfa_db
REDIS_URL=redis://localhost:6379

# Security
SECRET_KEY=your-secret-key-here
JWT_SECRET_KEY=your-jwt-secret-key-here

# CORS
CORS_ORIGINS=http://localhost:3000

# Rate Limiting
RATE_LIMIT_DEFAULT=100 per minute
```

### Frontend Environment Variables

Create a `.env` file in the `frontend` directory:

```env
REACT_APP_API_URL=http://localhost:5000
```

## 🚀 Usage

### 1. Registration

1. Navigate to `http://localhost:3000/register`
2. Enter your email and name
3. The system generates an ECC key pair on your device
4. Only the public key is sent to the server
5. Your private key is stored securely in your browser

### 2. Authentication

1. Navigate to `http://localhost:3000/login`
2. Enter your email address
3. The server sends a cryptographic challenge
4. Your device signs the challenge with your private key
5. The server verifies the signature with your public key
6. If valid, you're authenticated and redirected to the dashboard

### 3. Dashboard

- View account information
- Monitor active sessions
- Manage cryptographic keys
- View authentication logs

## 🔐 Security Features

### ECC Implementation
- **Curve**: SECP256R1 (NIST P-256)
- **Key Size**: 256 bits
- **Algorithm**: ECDSA for signatures, ECDH for key exchange

### Security Measures
- **Private Key Protection**: Never transmitted to servers
- **Challenge-Response**: Prevents replay attacks
- **Session Management**: Secure session tokens with expiry
- **Rate Limiting**: Protection against brute force
- **CORS Protection**: Controlled cross-origin requests
- **Input Validation**: Comprehensive data validation
- **Audit Logging**: All authentication events logged

### Cryptographic Operations

#### Key Generation
```python
# Backend
from crypto.ecc_operations import ecc_ops
private_key, public_key = ecc_ops.generate_keypair()
```

```typescript
// Frontend
const keyPair = await cryptoService.generateKeyPair();
```

#### Challenge Signing
```python
# Backend
from crypto.ecdsa_handler import ecdsa_handler
signature = ecdsa_handler.sign_challenge(private_key, nonce)
```

```typescript
// Frontend
const signature = await cryptoService.signChallenge(privateKeyPem, nonce);
```

#### Signature Verification
```python
# Backend
is_valid = ecdsa_handler.verify_challenge(public_key, nonce, signature)
```

## 📊 API Endpoints

### Authentication
- `POST /api/auth/register` - User registration
- `POST /api/auth/login/initiate` - Start login process
- `POST /api/auth/login/verify` - Verify challenge signature
- `POST /api/auth/logout` - User logout
- `POST /api/auth/session/validate` - Validate session
- `POST /api/auth/session/refresh` - Refresh session

### User Management
- `GET /api/user/profile` - Get user profile
- `GET /api/user/sessions` - Get user sessions
- `POST /api/user/sessions/invalidate-all` - Invalidate all sessions

### Health Check
- `GET /health` - Service health check

## 🧪 Testing

### Backend Tests
```bash
cd backend
pytest
```

### Frontend Tests
```bash
cd frontend
npm test
```

### Manual Testing
1. Register a new user
2. Test login with the registered user
3. Verify session management
4. Test key management features
5. Check audit logs

## 📁 Project Structure

```
ECCforPasswordlessMFA/
├── backend/
│   ├── app.py                 # Main Flask application
│   ├── config.py              # Configuration settings
│   ├── requirements.txt       # Python dependencies
│   ├── init.sql              # Database schema
│   ├── crypto/               # Cryptographic operations
│   │   ├── ecc_operations.py
│   │   ├── ecdsa_handler.py
│   │   └── ecdh_handler.py
│   ├── auth/                 # Authentication logic
│   │   ├── registration.py
│   │   ├── authentication.py
│   │   └── session_manager.py
│   ├── database/             # Database operations
│   │   ├── models.py
│   │   └── db_operations.py
│   └── utils/                # Utility functions
│       └── security.py
├── frontend/
│   ├── package.json          # Node.js dependencies
│   ├── public/               # Static files
│   └── src/
│       ├── components/       # React components
│       │   ├── Registration.tsx
│       │   ├── Authentication.tsx
│       │   ├── Dashboard.tsx
│       │   └── KeyManagement.tsx
│       ├── services/         # API and crypto services
│       │   ├── api.ts
│       │   └── crypto.ts
│       ├── contexts/         # React contexts
│       │   └── AuthContext.tsx
│       └── App.tsx           # Main app component
├── docker-compose.yml        # Docker services
└── README.md                 # This file
```

## 🔧 Development

### Adding New Features
1. Backend: Add new endpoints in `app.py`
2. Frontend: Create new components in `src/components/`
3. Database: Update models in `database/models.py`
4. Tests: Add corresponding test files

### Security Considerations
- Always validate input data
- Use HTTPS in production
- Implement proper error handling
- Regular security audits
- Keep dependencies updated

## 🚀 Deployment

### Production Setup
1. Use HTTPS with valid certificates
2. Configure proper CORS settings
3. Set up production database
4. Use environment variables for secrets
5. Implement monitoring and logging
6. Set up backup procedures

### Docker Deployment
```bash
# Build and run with Docker Compose
docker-compose -f docker-compose.prod.yml up -d
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🆘 Support

For support and questions:
- Create an issue in the repository
- Check the documentation
- Review the code examples

## 🔮 Future Enhancements

- Hardware Security Module (HSM) integration
- Biometric authentication support
- Mobile app development
- Advanced key management features
- Multi-factor authentication options
- Enterprise SSO integration

---

**Note**: This is a demonstration system. For production use, ensure proper security measures, regular audits, and compliance with relevant regulations. 