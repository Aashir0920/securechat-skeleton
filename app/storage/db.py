import pymysql
import hashlib
from contextlib import contextmanager

# Database configuration
DB_CONFIG = {
    'host': 'localhost',
    'user': 'securechat_user',
    'password': '12345678',
    'database': 'securechat',
    'charset': 'utf8mb4',
    'cursorclass': pymysql.cursors.DictCursor
}

@contextmanager
def get_connection():
    """Context manager for database connections"""
    conn = pymysql.connect(**DB_CONFIG)
    try:
        yield conn
        conn.commit()
    except Exception as e:
        conn.rollback()
        raise e
    finally:
        conn.close()

def init_database():
    """Initialize database tables"""
    with get_connection() as conn:
        cursor = conn.cursor()
        
        # Create users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                email VARCHAR(255) UNIQUE NOT NULL,
                password_hash VARCHAR(64) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP NULL,
                INDEX idx_email (email)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        ''')
        
        # Create sessions table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS sessions (
                id INT AUTO_INCREMENT PRIMARY KEY,
                email VARCHAR(255) NOT NULL,
                session_key VARCHAR(128),
                ip_address VARCHAR(45),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_active TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                is_active BOOLEAN DEFAULT TRUE,
                FOREIGN KEY (email) REFERENCES users(email) ON DELETE CASCADE,
                INDEX idx_email_active (email, is_active)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        ''')
        
        print("[✓] Database tables initialized")

def register_user(email, password):
    """Register a new user"""
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                'INSERT INTO users (email, password_hash) VALUES (%s, %s)',
                (email, password_hash)
            )
            return True
    except pymysql.IntegrityError:
        # User already exists
        return False
    except Exception as e:
        print(f"[✗] Registration error: {e}")
        return False

def verify_user(email, password):
    """Verify user credentials and update last login"""
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                'SELECT password_hash FROM users WHERE email = %s',
                (email,)
            )
            result = cursor.fetchone()
            
            if result and result['password_hash'] == password_hash:
                # Update last login
                cursor.execute(
                    'UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE email = %s',
                    (email,)
                )
                return True
            return False
    except Exception as e:
        print(f"[✗] Verification error: {e}")
        return False

def create_session(email, ip_address=None):
    """Create a new session entry"""
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                'INSERT INTO sessions (email, ip_address) VALUES (%s, %s)',
                (email, ip_address)
            )
            return cursor.lastrowid
    except Exception as e:
        print(f"[✗] Session creation error: {e}")
        return None

def close_session(session_id):
    """Mark a session as inactive"""
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                'UPDATE sessions SET is_active = FALSE WHERE id = %s',
                (session_id,)
            )
            return True
    except Exception as e:
        print(f"[✗] Session close error: {e}")
        return False

def get_active_sessions(email):
    """Get all active sessions for a user"""
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                '''SELECT id, ip_address, created_at, last_active 
                   FROM sessions 
                   WHERE email = %s AND is_active = TRUE
                   ORDER BY last_active DESC''',
                (email,)
            )
            return cursor.fetchall()
    except Exception as e:
        print(f"[✗] Error fetching sessions: {e}")
        return []

def get_user_stats(email):
    """Get user statistics"""
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                '''SELECT 
                    u.email,
                    u.created_at,
                    u.last_login,
                    COUNT(DISTINCT s.id) as total_sessions,
                    COUNT(DISTINCT CASE WHEN s.is_active THEN s.id END) as active_sessions
                   FROM users u
                   LEFT JOIN sessions s ON u.email = s.email
                   WHERE u.email = %s
                   GROUP BY u.email''',
                (email,)
            )
            return cursor.fetchone()
    except Exception as e:
        print(f"[✗] Error fetching user stats: {e}")
        return None

# Initialize database on import
if __name__ != "__main__":
    try:
        init_database()
    except Exception as e:
        print(f"[!] Warning: Could not initialize database: {e}")
