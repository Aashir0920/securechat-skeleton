#!/usr/bin/env python3
"""
Simple authentication test to isolate the issue
Run server in one terminal, this in another
"""

import socket
import sys

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 9999

def test_client():
    print("=== Simple Authentication Test ===\n")
    
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(10.0)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    
    try:
        print(f"[1] Connecting to {SERVER_HOST}:{SERVER_PORT}...")
        s.connect((SERVER_HOST, SERVER_PORT))
        print("[✓] Connected\n")
        
        # Receive email prompt
        print("[2] Waiting for email prompt...")
        data = s.recv(1024)
        print(f"[✓] Received: {repr(data)}")
        prompt = data.decode().strip()
        print(f"    Decoded: '{prompt}'")
        
        # Send email
        email = "test@example.com"
        print(f"\n[3] Sending email: {email}")
        s.sendall((email + '\n').encode())
        print("[✓] Email sent\n")
        
        # Receive password prompt
        print("[4] Waiting for password prompt...")
        data = s.recv(1024)
        print(f"[✓] Received: {repr(data)}")
        prompt = data.decode().strip()
        print(f"    Decoded: '{prompt}'")
        
        # Send password
        password = "password123"
        print(f"\n[5] Sending password: {password}")
        s.sendall((password + '\n').encode())
        print("[✓] Password sent\n")
        
        # Receive response
        print("[6] Waiting for auth response...")
        data = s.recv(1024)
        print(f"[✓] Received: {repr(data)}")
        response = data.decode().strip()
        print(f"    Response: '{response}'\n")
        
        print("="*50)
        print("SUCCESS! Authentication flow completed")
        print("="*50)
        
    except socket.timeout as e:
        print(f"\n[✗] TIMEOUT: {e}")
        print("    Server may not be responding")
    except ConnectionRefusedError:
        print(f"\n[✗] Connection refused - is server running?")
    except Exception as e:
        print(f"\n[✗] Error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        s.close()
        print("\n[✓] Connection closed")

if __name__ == "__main__":
    test_client()
