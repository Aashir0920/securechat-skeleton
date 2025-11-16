import socket
import struct
import json
import time
from crypto import dh, aes, sign, pki
from cryptography.hazmat.primitives import serialization
from storage import db, transcript

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 9999

# Track session sequence numbers
session_seqno = {}
session_ids = {}

def recv_exact(sock, n):
    """Receive exactly n bytes from socket"""
    buf = b""
    while len(buf) < n:
        try:
            part = sock.recv(n - len(buf))
            if not part:
                raise ConnectionError("Connection closed")
            buf += part
        except socket.timeout:
            raise
    return buf

def print_banner():
    """Print server banner"""
    banner = """
    ╔═══════════════════════════════════════╗
    ║     SECURE CHAT SERVER v1.0          ║
    ║  End-to-End Encrypted Messaging      ║
    ╚═══════════════════════════════════════╝
    """
    print(banner)

def handle_client(client_sock, addr):
    """Handle individual client connection"""
    print(f"\n[+] New connection from {addr[0]}:{addr[1]}")
    session_id = None
    email = None
    
    # Disable Nagle's algorithm for immediate sends
    client_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    
    try:
        # --- Load server certificate and key ---
        SERVER_KEY = pki.load_private_key("server_key.pem")
        SERVER_CERT = pki.load_certificate("server_cert.pem")
        
        # --- Step 1: Authentication ---
        print(f"[{addr[0]}] Waiting for authentication...")
        
        # Set timeout for receiving data
        client_sock.settimeout(30.0)
        
        # Send email prompt and receive response
        client_sock.sendall(b"Email: ")
        time.sleep(0.05)  # Small delay for client to be ready
        
        try:
            email_data = client_sock.recv(1024)
            if not email_data:
                print(f"[{addr[0]}] Client disconnected during email input")
                return
            email = email_data.decode().strip()
            print(f"[{addr[0]}] Received email: {email}")
        except socket.timeout:
            print(f"[{addr[0]}] Timeout waiting for email")
            return
        except Exception as e:
            print(f"[{addr[0]}] Error receiving email: {e}")
            return
        
        # Send password prompt and receive response
        client_sock.sendall(b"Password: ")
        time.sleep(0.05)  # Small delay for client to be ready
        
        try:
            password_data = client_sock.recv(1024)
            if not password_data:
                print(f"[{addr[0]}] Client disconnected during password input")
                return
            password = password_data.decode().strip()
            print(f"[{addr[0]}] Received password (length: {len(password)})")
        except socket.timeout:
            print(f"[{addr[0]}] Timeout waiting for password")
            return
        except Exception as e:
            print(f"[{addr[0]}] Error receiving password: {e}")
            return
        
        # Register or login using database
        if not db.verify_user(email, password):
            # Try to register
            if db.register_user(email, password):
                client_sock.sendall(b"Registration successful!\n")
                print(f"[{addr[0]}] ✓ New user registered: {email}")
            else:
                # User exists but wrong password
                client_sock.sendall(b"Invalid credentials\n")
                print(f"[{addr[0]}] ✗ Invalid login attempt: {email}")
                return
        else:
            client_sock.sendall(b"Login successful!\n")
            print(f"[{addr[0]}] ✓ User logged in: {email}")
        
        # Small delay to ensure client processes auth response before certificate
        time.sleep(0.2)
        
        # Create session in database
        session_id = db.create_session(email, addr[0])
        if session_id:
            session_ids[email] = session_id
            print(f"[{addr[0]}] Session ID: {session_id}")
        
        # --- Step 2: Send server certificate ---
        server_cert_bytes = SERVER_CERT.public_bytes(
            encoding=serialization.Encoding.PEM
        )
        client_sock.sendall(struct.pack("!I", len(server_cert_bytes)))
        client_sock.sendall(server_cert_bytes)
        print(f"[{addr[0]}] ✓ Sent server certificate to {email}")
        
        # --- Step 3: Diffie-Hellman key exchange ---
        # Receive client DH public key
        data_len_bytes = recv_exact(client_sock, 4)
        data_len = struct.unpack("!I", data_len_bytes)[0]
        client_pub_bytes = recv_exact(client_sock, data_len)
        client_pub_key = dh.deserialize_public_key(client_pub_bytes)
        print(f"[{addr[0]}] ✓ Received client DH public key")
        
        # Generate server DH key pair
        private_key = dh.generate_private_key()
        pub_bytes = dh.serialize_public_key(private_key.public_key())
        
        # Send server DH public key
        client_sock.sendall(struct.pack("!I", len(pub_bytes)))
        client_sock.sendall(pub_bytes)
        print(f"[{addr[0]}] ✓ Sent server DH public key")
        
        # Compute shared session key
        session_key = private_key.exchange(client_pub_key)
        if isinstance(session_key, bytes):
            session_key = session_key[:16]  # AES-128 key
        else:
            session_key = session_key.to_bytes(32, byteorder='big')[:16]
        
        print(f"[{addr[0]}] ✓ Session key established")
        
        # --- Step 4: Send signed session receipt ---
        receipt_data = json.dumps({
            "timestamp": time.time(),
            "client": email,
            "status": "session_established",
            "session_id": session_id
        }).encode()
        
        signature = sign.sign_message(SERVER_KEY, receipt_data)
        receipt_json = json.dumps({
            "data": receipt_data.decode(),
            "sig": signature.hex()
        }).encode()
        
        encrypted_receipt = aes.encrypt_message(session_key, receipt_json)
        client_sock.sendall(encrypted_receipt)
        print(f"[{addr[0]}] ✓ Sent session receipt")
        
        # Initialize sequence number for this session
        session_seqno[email] = 1
        
        # --- Step 5: Message exchange loop ---
        print(f"[{addr[0]}] 🔒 Secure session active with {email}")
        print(f"[{addr[0]}] Waiting for messages...")
        
        client_sock.settimeout(300.0)  # 5 minute timeout for messages
        
        while True:
            # Receive encrypted message
            try:
                # Use recv() instead of recv_exact() for variable-length messages
                data = client_sock.recv(4096)
            except socket.timeout:
                print(f"[{addr[0]}] Session timeout")
                break
            except ConnectionError:
                print(f"[{addr[0]}] Client disconnected")
                break
                
            if not data:
                print(f"[{addr[0]}] Client disconnected")
                break
            
            # Decrypt message
            try:
                decrypted = aes.decrypt_message(session_key, data)
                msg_envelope = json.loads(decrypted)
            except Exception as e:
                print(f"[{addr[0]}] ✗ Decryption error: {e}")
                continue
            
            # Verify client signature
            payload_bytes = bytes.fromhex(msg_envelope["payload"])
            sig_bytes = bytes.fromhex(msg_envelope["sig"])
            
            CLIENT_CERT = pki.load_certificate("client_cert.pem")
            CLIENT_PUBKEY = CLIENT_CERT.public_key()
            
            if not sign.verify_signature(CLIENT_PUBKEY, payload_bytes, sig_bytes):
                error_msg = aes.encrypt_message(session_key, b"SIG_FAIL")
                client_sock.sendall(error_msg)
                print(f"[{addr[0]}] ✗ Signature verification failed")
                continue
            
            # Parse message payload
            payload_json = json.loads(payload_bytes)
            client_seqno = payload_json["seqno"]
            client_msg = payload_json["msg"]
            
            # Check for replay attacks
            if client_seqno != session_seqno[email]:
                error_msg = aes.encrypt_message(session_key, b"REPLAY")
                client_sock.sendall(error_msg)
                print(f"[{addr[0]}] ✗ Replay attack detected (expected {session_seqno[email]}, got {client_seqno})")
                continue
            
            print(f"[{addr[0]}] {email} [#{client_seqno}]: {client_msg}")
            
            # Save message to database
            transcript.save_message(
                email=email,
                sender='client',
                seqno=client_seqno,
                message=client_msg,
                session_id=session_id
            )
            
            # Prepare server response
            server_response = f"Echo: {client_msg}"
            response_payload = json.dumps({
                "seqno": session_seqno[email],
                "msg": server_response
            }).encode()
            
            # Sign response
            response_sig = sign.sign_message(SERVER_KEY, response_payload)
            response_envelope = json.dumps({
                "payload": response_payload.hex(),
                "sig": response_sig.hex()
            }).encode()
            
            # Encrypt and send
            encrypted_response = aes.encrypt_message(session_key, response_envelope)
            client_sock.sendall(encrypted_response)
            
            # Save server response to database
            transcript.save_message(
                email=email,
                sender='server',
                seqno=session_seqno[email],
                message=server_response,
                session_id=session_id
            )
            
            session_seqno[email] += 1
            
    except ConnectionError as e:
        print(f"[{addr[0]}] Connection error: {e}")
    except Exception as e:
        print(f"[{addr[0]}] ✗ Error handling client: {e}")
        import traceback
        traceback.print_exc()
    finally:
        # Close session in database
        if session_id:
            db.close_session(session_id)
            print(f"[{addr[0]}] Session {session_id} closed")
        
        client_sock.close()
        
        if email and email in session_seqno:
            del session_seqno[email]
        if email and email in session_ids:
            del session_ids[email]
            
        print(f"[{addr[0]}] Connection closed\n")

def main():
    """Main server loop"""
    print_banner()
    print("=== Starting Secure Chat Server ===\n")
    
    # Initialize database
    print("[1/3] Initializing database...")
    try:
        db.init_database()
        transcript.init_transcript_table()
        print("      [✓] Database initialized\n")
    except Exception as e:
        print(f"      [✗] Database initialization failed: {e}")
        print("      Make sure MariaDB is running and configured correctly")
        return
    
    # Load certificates
    print("[2/3] Loading server certificates...")
    try:
        pki.load_certificate("server_cert.pem")
        pki.load_private_key("server_key.pem")
        print("      [✓] Certificates loaded\n")
    except FileNotFoundError:
        print("      [✗] Server certificates not found!")
        print("      Run: python scripts/gen_cert.py server")
        return
    
    # Create server socket
    print("[3/3] Starting server...")
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server_sock.bind((SERVER_HOST, SERVER_PORT))
        server_sock.listen(5)
        print(f"      [✓] Server listening on {SERVER_HOST}:{SERVER_PORT}\n")
        print("="*60)
        print("🔒 SERVER READY - Waiting for connections...")
        print("="*60)
        print("\nPress Ctrl+C to stop the server\n")
        
        while True:
            client_sock, addr = server_sock.accept()
            # Handle each client (for production, use threading)
            handle_client(client_sock, addr)
            
    except KeyboardInterrupt:
        print("\n\n[!] Server shutting down...")
    except Exception as e:
        print(f"\n[✗] Server error: {e}")
    finally:
        server_sock.close()
        print("[✓] Server stopped\n")

if __name__ == "__main__":
    main()
