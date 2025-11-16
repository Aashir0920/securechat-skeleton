import pymysql
from datetime import datetime
from .db import get_connection

def init_transcript_table():
    """Initialize transcript table"""
    with get_connection() as conn:
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS messages (
                id INT AUTO_INCREMENT PRIMARY KEY,
                session_id INT,
                email VARCHAR(255) NOT NULL,
                sender VARCHAR(50) NOT NULL,
                seqno INT NOT NULL,
                message TEXT NOT NULL,
                message_hash VARCHAR(64),
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (email) REFERENCES users(email) ON DELETE CASCADE,
                FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE SET NULL,
                INDEX idx_email_seqno (email, seqno),
                INDEX idx_session (session_id),
                INDEX idx_timestamp (timestamp)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        ''')
        
        print("[✓] Transcript table initialized")

def save_message(email, sender, seqno, message, session_id=None):
    """Save a chat message to database"""
    import hashlib
    
    # Create message hash for integrity verification
    message_hash = hashlib.sha256(
        f"{email}{sender}{seqno}{message}".encode()
    ).hexdigest()
    
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                '''INSERT INTO messages 
                   (session_id, email, sender, seqno, message, message_hash) 
                   VALUES (%s, %s, %s, %s, %s, %s)''',
                (session_id, email, sender, seqno, message, message_hash)
            )
            return cursor.lastrowid
    except Exception as e:
        print(f"[✗] Error saving message: {e}")
        return None

def get_conversation(email, limit=50):
    """Retrieve conversation history for a user"""
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                '''SELECT sender, seqno, message, timestamp 
                   FROM messages 
                   WHERE email = %s 
                   ORDER BY timestamp DESC, seqno DESC 
                   LIMIT %s''',
                (email, limit)
            )
            messages = cursor.fetchall()
            # Reverse to show chronological order
            return list(reversed(messages))
    except Exception as e:
        print(f"[✗] Error retrieving conversation: {e}")
        return []

def get_session_transcript(session_id):
    """Get all messages for a specific session"""
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                '''SELECT sender, seqno, message, timestamp 
                   FROM messages 
                   WHERE session_id = %s 
                   ORDER BY timestamp ASC, seqno ASC''',
                (session_id,)
            )
            return cursor.fetchall()
    except Exception as e:
        print(f"[✗] Error retrieving session transcript: {e}")
        return []

def get_message_count(email):
    """Get total message count for a user"""
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                'SELECT COUNT(*) as count FROM messages WHERE email = %s',
                (email,)
            )
            result = cursor.fetchone()
            return result['count'] if result else 0
    except Exception as e:
        print(f"[✗] Error getting message count: {e}")
        return 0

def get_last_sequence_number(email):
    """Get the last sequence number used by a user"""
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                '''SELECT MAX(seqno) as last_seqno 
                   FROM messages 
                   WHERE email = %s AND sender = 'client' ''',
                (email,)
            )
            result = cursor.fetchone()
            return result['last_seqno'] if result and result['last_seqno'] else 0
    except Exception as e:
        print(f"[✗] Error getting last sequence number: {e}")
        return 0

def search_messages(email, search_term, limit=20):
    """Search messages for a specific term"""
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                '''SELECT sender, seqno, message, timestamp 
                   FROM messages 
                   WHERE email = %s AND message LIKE %s
                   ORDER BY timestamp DESC 
                   LIMIT %s''',
                (email, f'%{search_term}%', limit)
            )
            return cursor.fetchall()
    except Exception as e:
        print(f"[✗] Error searching messages: {e}")
        return []

def get_conversation_stats(email):
    """Get statistics about user's conversations"""
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                '''SELECT 
                    COUNT(*) as total_messages,
                    COUNT(DISTINCT session_id) as total_sessions,
                    MIN(timestamp) as first_message,
                    MAX(timestamp) as last_message,
                    COUNT(CASE WHEN sender = 'client' THEN 1 END) as sent_messages,
                    COUNT(CASE WHEN sender = 'server' THEN 1 END) as received_messages
                   FROM messages 
                   WHERE email = %s''',
                (email,)
            )
            return cursor.fetchone()
    except Exception as e:
        print(f"[✗] Error getting conversation stats: {e}")
        return None

def delete_old_messages(days=30):
    """Delete messages older than specified days"""
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                '''DELETE FROM messages 
                   WHERE timestamp < DATE_SUB(NOW(), INTERVAL %s DAY)''',
                (days,)
            )
            deleted_count = cursor.rowcount
            print(f"[✓] Deleted {deleted_count} old messages")
            return deleted_count
    except Exception as e:
        print(f"[✗] Error deleting old messages: {e}")
        return 0

def export_conversation(email, filename=None):
    """Export conversation to a text file"""
    if not filename:
        filename = f"conversation_{email}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    
    try:
        messages = get_conversation(email, limit=10000)
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(f"Conversation Export for {email}\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("="*80 + "\n\n")
            
            for msg in messages:
                f.write(f"[{msg['timestamp']}] {msg['sender']} #{msg['seqno']}: {msg['message']}\n")
        
        print(f"[✓] Conversation exported to {filename}")
        return filename
    except Exception as e:
        print(f"[✗] Error exporting conversation: {e}")
        return None

# Initialize table on import
if __name__ != "__main__":
    try:
        init_transcript_table()
    except Exception as e:
        print(f"[!] Warning: Could not initialize transcript table: {e}")
