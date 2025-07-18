-- ECC MFA Database Initialization Script
-- This script creates the database schema for the ECC-based passwordless MFA system

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Users table
CREATE TABLE IF NOT EXISTS users (
    user_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email VARCHAR(255) UNIQUE NOT NULL,
    name VARCHAR(255),
    public_key BYTEA NOT NULL,
    public_key_pem TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    last_login TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE
);

-- Authentication logs table
CREATE TABLE IF NOT EXISTS auth_logs (
    log_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(user_id) ON DELETE CASCADE,
    event_type VARCHAR(50) NOT NULL,
    ip_address VARCHAR(45),
    user_agent TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    success BOOLEAN NOT NULL,
    details TEXT
);

-- Sessions table
CREATE TABLE IF NOT EXISTS sessions (
    session_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(user_id) ON DELETE CASCADE,
    session_token VARCHAR(255) UNIQUE NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMP NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    ip_address VARCHAR(45),
    user_agent TEXT
);

-- Challenges table
CREATE TABLE IF NOT EXISTS challenges (
    challenge_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(user_id) ON DELETE CASCADE,
    nonce BYTEA NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMP NOT NULL,
    is_used BOOLEAN DEFAULT FALSE,
    ip_address VARCHAR(45)
);

-- Devices table
CREATE TABLE IF NOT EXISTS devices (
    device_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(user_id) ON DELETE CASCADE,
    device_name VARCHAR(255) NOT NULL,
    device_type VARCHAR(50),
    public_key BYTEA NOT NULL,
    public_key_pem TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    last_used TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE
);

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_active ON users(is_active);
CREATE INDEX IF NOT EXISTS idx_auth_logs_user_id ON auth_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_auth_logs_event_type ON auth_logs(event_type);
CREATE INDEX IF NOT EXISTS idx_auth_logs_created_at ON auth_logs(created_at);
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(session_token);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_sessions_active ON sessions(is_active);
CREATE INDEX IF NOT EXISTS idx_challenges_user_id ON challenges(user_id);
CREATE INDEX IF NOT EXISTS idx_challenges_expires_at ON challenges(expires_at);
CREATE INDEX IF NOT EXISTS idx_challenges_used ON challenges(is_used);
CREATE INDEX IF NOT EXISTS idx_devices_user_id ON devices(user_id);
CREATE INDEX IF NOT EXISTS idx_devices_active ON devices(is_active);

-- Create a function to clean up expired sessions
CREATE OR REPLACE FUNCTION cleanup_expired_sessions()
RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    UPDATE sessions 
    SET is_active = FALSE 
    WHERE expires_at < NOW() AND is_active = TRUE;
    
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

-- Create a function to clean up expired challenges
CREATE OR REPLACE FUNCTION cleanup_expired_challenges()
RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    DELETE FROM challenges 
    WHERE expires_at < NOW();
    
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

-- Create a function to get user statistics
CREATE OR REPLACE FUNCTION get_user_stats(user_uuid UUID)
RETURNS TABLE(
    total_sessions INTEGER,
    active_sessions INTEGER,
    total_logins INTEGER,
    last_login TIMESTAMP,
    devices_count INTEGER
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        COUNT(s.session_id)::INTEGER as total_sessions,
        COUNT(CASE WHEN s.is_active = TRUE AND s.expires_at > NOW() THEN 1 END)::INTEGER as active_sessions,
        COUNT(CASE WHEN al.event_type = 'login' AND al.success = TRUE THEN 1 END)::INTEGER as total_logins,
        u.last_login,
        COUNT(d.device_id)::INTEGER as devices_count
    FROM users u
    LEFT JOIN sessions s ON u.user_id = s.user_id
    LEFT JOIN auth_logs al ON u.user_id = al.user_id
    LEFT JOIN devices d ON u.user_id = d.user_id AND d.is_active = TRUE
    WHERE u.user_id = user_uuid
    GROUP BY u.user_id, u.last_login;
END;
$$ LANGUAGE plpgsql;

-- Create a view for recent authentication activity
CREATE OR REPLACE VIEW recent_auth_activity AS
SELECT 
    u.email,
    u.name,
    al.event_type,
    al.success,
    al.ip_address,
    al.created_at,
    al.details
FROM auth_logs al
JOIN users u ON al.user_id = u.user_id
WHERE al.created_at > NOW() - INTERVAL '24 hours'
ORDER BY al.created_at DESC;

-- Create a view for active sessions
CREATE OR REPLACE VIEW active_sessions AS
SELECT 
    u.email,
    u.name,
    s.session_id,
    s.session_token,
    s.created_at,
    s.expires_at,
    s.ip_address,
    s.user_agent
FROM sessions s
JOIN users u ON s.user_id = u.user_id
WHERE s.is_active = TRUE AND s.expires_at > NOW()
ORDER BY s.created_at DESC;

-- Grant permissions (adjust as needed for your setup)
-- GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO hao;
-- GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO hao;
-- GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO hao;

-- Insert some sample data for testing (optional)
-- INSERT INTO users (email, name, public_key, public_key_pem) VALUES 
-- ('test@example.com', 'Test User', E'\\x0123456789abcdef', '-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...\n-----END PUBLIC KEY-----');

COMMIT; 