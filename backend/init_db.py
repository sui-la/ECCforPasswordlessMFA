#!/usr/bin/env python3
"""
Database Initialization Script
Sets up the PostgreSQL database for the ECC MFA system.
"""

import os
import sys
import psycopg2
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

def get_database_config():
    """Get database configuration from environment variables"""
    database_url = os.getenv('DATABASE_URL', 'postgresql://hao:your_password_here@localhost/ecc_mfa_db')
    
    # Parse the database URL
    if database_url.startswith('postgresql://'):
        # Remove the protocol
        url = database_url[12:]
        
        # Split into parts
        if '@' in url:
            auth_part, rest = url.split('@', 1)
            if ':' in auth_part:
                username, password = auth_part.split(':', 1)
            else:
                username, password = auth_part, ''
            
            if '/' in rest:
                host_port, database = rest.split('/', 1)
                if ':' in host_port:
                    host, port = host_port.split(':', 1)
                else:
                    host, port = host_port, '5432'
            else:
                host, port = rest, '5432'
                database = 'postgres'
        else:
            # No authentication
            username = password = ''
            if '/' in url:
                host_port, database = url.split('/', 1)
                if ':' in host_port:
                    host, port = host_port.split(':', 1)
                else:
                    host, port = host_port, '5432'
            else:
                host, port = url, '5432'
                database = 'postgres'
    else:
        # Fallback to environment variables
        username = os.getenv('DB_USER', 'hao')
        password = os.getenv('DB_PASSWORD', 'your_password_here')
        host = os.getenv('DB_HOST', 'localhost')
        port = os.getenv('DB_PORT', '5432')
        database = os.getenv('DB_NAME', 'ecc_mfa_db')
    
    return {
        'username': username,
        'password': password,
        'host': host,
        'port': port,
        'database': database
    }

def create_database():
    """Create the database if it doesn't exist"""
    config = get_database_config()
    
    # Connect to PostgreSQL server (not to a specific database)
    conn = psycopg2.connect(
        host=config['host'],
        port=config['port'],
        user=config['username'],
        password=config['password'],
        database='postgres'  # Connect to default postgres database
    )
    conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
    cursor = conn.cursor()
    
    try:
        # Check if database exists
        cursor.execute("SELECT 1 FROM pg_database WHERE datname = %s", (config['database'],))
        exists = cursor.fetchone()
        
        if not exists:
            print(f"Creating database '{config['database']}'...")
            cursor.execute(f"CREATE DATABASE {config['database']}")
            print(f"Database '{config['database']}' created successfully!")
        else:
            print(f"Database '{config['database']}' already exists.")
            
    except Exception as e:
        print(f"Error creating database: {e}")
        return False
    finally:
        cursor.close()
        conn.close()
    
    return True

def init_schema():
    """Initialize the database schema"""
    config = get_database_config()
    
    # Connect to the specific database
    conn = psycopg2.connect(
        host=config['host'],
        port=config['port'],
        user=config['username'],
        password=config['password'],
        database=config['database']
    )
    cursor = conn.cursor()
    
    try:
        # Read and execute the initialization SQL
        with open('init.sql', 'r') as f:
            sql_script = f.read()
        
        print("Executing database schema initialization...")
        cursor.execute(sql_script)
        conn.commit()
        print("Database schema initialized successfully!")
        
    except Exception as e:
        print(f"Error initializing schema: {e}")
        conn.rollback()
        return False
    finally:
        cursor.close()
        conn.close()
    
    return True

def test_connection():
    """Test database connection"""
    config = get_database_config()
    
    try:
        conn = psycopg2.connect(
            host=config['host'],
            port=config['port'],
            user=config['username'],
            password=config['password'],
            database=config['database']
        )
        cursor = conn.cursor()
        
        # Test basic query
        cursor.execute("SELECT version();")
        version = cursor.fetchone()
        print(f"Database connection successful!")
        print(f"PostgreSQL version: {version[0]}")
        
        # Test if tables exist
        cursor.execute("""
            SELECT table_name 
            FROM information_schema.tables 
            WHERE table_schema = 'public' 
            AND table_name IN ('users', 'auth_logs', 'sessions', 'challenges', 'devices')
        """)
        tables = cursor.fetchall()
        
        if tables:
            print(f"Found {len(tables)} tables: {[table[0] for table in tables]}")
        else:
            print("No tables found. Schema may not be initialized.")
        
        cursor.close()
        conn.close()
        return True
        
    except Exception as e:
        print(f"Database connection test failed: {e}")
        return False

def main():
    """Main initialization function"""
    print("ECC MFA Database Initialization")
    print("=" * 40)
    
    # Step 1: Create database
    print("\nStep 1: Creating database...")
    if not create_database():
        print("Failed to create database. Exiting.")
        sys.exit(1)
    
    # Step 2: Initialize schema
    print("\nStep 2: Initializing schema...")
    if not init_schema():
        print("Failed to initialize schema. Exiting.")
        sys.exit(1)
    
    # Step 3: Test connection
    print("\nStep 3: Testing connection...")
    if not test_connection():
        print("Database connection test failed. Exiting.")
        sys.exit(1)
    
    print("\n" + "=" * 40)
    print("Database initialization completed successfully!")
    print("You can now start the application.")

if __name__ == "__main__":
    main() 