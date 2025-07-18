# Database Setup Guide for ECC MFA System

This guide will help you set up the PostgreSQL database for your ECC-based Multi-Factor Authentication system.

## Prerequisites

1. **Docker** (recommended) or **PostgreSQL** installed locally
2. **Python** with required packages
3. **Redis** (for session management)

## Option 1: Using Docker (Recommended)

### 1. Start the Database Services

From the project root, run:

```bash
# Start PostgreSQL and Redis
npm run dev:db

# Or use docker-compose directly
docker-compose up -d postgres redis
```

This will start:
- **PostgreSQL** on port 5432
- **Redis** on port 6379
- **pgAdmin** (optional) on port 8080

### 2. Configure Database Connection

Create a `.env` file in the `backend` directory to match your Docker setup:

```env
DATABASE_URL=postgresql://hao:your_password_here@localhost/ecc_mfa_db
REDIS_URL=redis://localhost:6379
SECRET_KEY=your-secret-key-here
JWT_SECRET_KEY=your-jwt-secret-key-here
CORS_ORIGINS=http://localhost:3000
```

### 3. Initialize the Database

```bash
cd backend
python init_db.py
```

This will:
- Create the database if it doesn't exist
- Run the initialization script (`init.sql`)
- Test the connection
- Set up all required tables and indexes

## Option 2: Local PostgreSQL Installation

### 1. Install PostgreSQL

**Windows:**
- Download from https://www.postgresql.org/download/windows/
- Install with default settings

**macOS:**
```bash
brew install postgresql
brew services start postgresql
```

**Linux (Ubuntu/Debian):**
```bash
sudo apt update
sudo apt install postgresql postgresql-contrib
sudo systemctl start postgresql
sudo systemctl enable postgresql
```

### 2. Create Database and User

```bash
# Connect to PostgreSQL as superuser
sudo -u postgres psql

# Create user and database
CREATE USER hao WITH PASSWORD 'your_password_here';
CREATE DATABASE ecc_mfa_db OWNER hao;
GRANT ALL PRIVILEGES ON DATABASE ecc_mfa_db TO hao;
\q
```

### 3. Configure and Initialize

1. Create a `.env` file in the `backend` directory with your credentials
2. Run the initialization script:
```bash
cd backend
python init_db.py
```

## Database Schema

The system creates the following tables:

### `users` Table
- `user_id` (UUID, Primary Key)
- `email` (VARCHAR(255), Unique, Not Null)
- `name` (VARCHAR(255), Not Null)
- `created_at` (TIMESTAMP DEFAULT NOW())
- `last_login` (TIMESTAMP)
- `is_active` (BOOLEAN DEFAULT TRUE)

### `public_keys` Table
- `key_id` (UUID, Primary Key)
- `user_id` (UUID, Foreign Key to users.user_id)
- `public_key` (BYTEA, Not Null)
- `key_name` (VARCHAR(255), Default: 'Primary Key')
- `created_at` (TIMESTAMP DEFAULT NOW())
- `last_used` (TIMESTAMP)
- `is_active` (BOOLEAN DEFAULT TRUE)

### `auth_logs` Table
- `log_id` (UUID, Primary Key)
- `user_id` (UUID, Foreign Key to users.user_id)
- `event_type` (VARCHAR(50), Not Null)
- `ip_address` (VARCHAR(45))
- `user_agent` (TEXT)
- `created_at` (TIMESTAMP DEFAULT NOW())
- `success` (BOOLEAN DEFAULT FALSE)
- `details` (JSONB)

### `sessions` Table
- `session_id` (UUID, Primary Key)
- `user_id` (UUID, Foreign Key to users.user_id)
- `session_token` (VARCHAR(255), Unique, Not Null)
- `created_at` (TIMESTAMP DEFAULT NOW())
- `expires_at` (TIMESTAMP, Not Null)
- `ip_address` (VARCHAR(45))
- `user_agent` (TEXT)
- `is_active` (BOOLEAN DEFAULT TRUE)

### `challenges` Table
- `challenge_id` (UUID, Primary Key)
- `user_id` (UUID, Foreign Key to users.user_id)
- `challenge_nonce` (VARCHAR(255), Unique, Not Null)
- `created_at` (TIMESTAMP DEFAULT NOW())
- `expires_at` (TIMESTAMP, Not Null)
- `is_used` (BOOLEAN DEFAULT FALSE)

## Database Management

### Using the Database Initialization Script

```bash
cd backend

# Initialize database and schema
python init_db.py

# The script will:
# - Create the database if it doesn't exist
# - Create all tables and indexes
# - Test the connection
# - Verify the setup
```

### Using pgAdmin (Docker)

If you're using Docker, you can access pgAdmin at:
- URL: http://localhost:8080
- Email: thenganhao3383@gmail.com
- Password: Suisui$&0322

### Using psql Command Line

```bash
# Connect to database
psql -h localhost -U hao -d ecc_mfa_db

# List tables
\dt

# View table structure
\d users
\d public_keys
\d auth_logs
\d sessions
\d challenges

# Exit
\q
```

## Troubleshooting

### Common Issues

1. **Connection Refused**
   - Ensure PostgreSQL is running
   - Check if the port (5432) is available
   - Verify firewall settings

2. **Authentication Failed**
   - Check username/password in `.env` file
   - Ensure user has proper permissions
   - Try connecting with psql to test credentials

3. **Database Not Found**
   - Run `python init_db.py` to create the database
   - Check if the database name matches in configuration

4. **Tables Not Found**
   - Run `python init_db.py` to create tables
   - Check if `init.sql` file exists and is readable

### Reset Database

To completely reset the database:

```bash
# Stop services
docker-compose down

# Remove volumes (WARNING: This deletes all data!)
docker-compose down -v

# Start fresh
docker-compose up -d postgres redis
cd backend
python init_db.py
```

### Backup and Restore

**Backup:**
```bash
pg_dump -h localhost -U hao ecc_mfa_db > backup.sql
```

**Restore:**
```bash
psql -h localhost -U hao ecc_mfa_db < backup.sql
```

## Security Considerations

1. **Change Default Passwords**
   - Update passwords in `docker-compose.yml` and `config.env`
   - Use strong, unique passwords

2. **Network Security**
   - Don't expose database ports to the internet
   - Use VPN or SSH tunneling for remote access

3. **Regular Backups**
   - Set up automated backups
   - Test restore procedures

4. **Monitoring**
   - Monitor database performance
   - Set up alerts for connection issues

## Next Steps

After setting up the database:

1. **Start the Backend:**
   ```bash
   cd backend
   python app.py
   ```

2. **Start the Frontend:**
   ```bash
   cd frontend
   npm start
   ```

3. **Test the System:**
   - Visit http://localhost:3000
   - Register a new user
   - Test authentication flow
   - Check the dashboard for session management

## Support

If you encounter issues:

1. Check the logs: `docker-compose logs postgres`
2. Verify configuration in `backend/.env`
3. Test connection manually with psql
4. Check the troubleshooting section above
5. Review the main README.md for additional setup instructions 