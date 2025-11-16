#!/usr/bin/env python3
"""
Simple debug server to test authentication
"""

import socket
import sys

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 9999

def handle_client(client_sock, addr):
    print(f"\n[+] New connection from {addr[0]}:{addr[1]}")
    
    # Disable Nagle's algorithm
    client_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    client_sock.settimeout(30.0)
    
    try:
        # Send email prompt
        print("\n[1] Sending email prompt...")
        prompt = b"Email: "
        client_sock.sendall(prompt)
        print(f"    Sent: {repr(prompt)}")
        
        # Receive email
        print("\n[2] Waiting for email...")
        email_data = client_sock.recv(1024)
        print(f"    Received raw: {repr(email_data)}")
        email = email_data.decode().strip()
        print(f"    Decoded: '{email}'")
        
        # Send password prompt
        print("\n[3] Sending password prompt...")
        prompt = b"Password: "
        client_sock.sendall(prompt)
        print(f"    Sent: {repr(prompt)}")
        
        # Receive password
        print("\n[4] Waiting for password...")
        password_data = client_sock.recv(1024)
        print(f"    Received raw: {repr(password_data)}")
        password = password_data.decode().strip()
        print(f"    Decoded: '{password}'")
        
        # Send response
        print("\n[5] Sending auth response...")
        response = b"Login successful!\n"
        client_sock.sendall(response)
        print(f"    Sent: {repr(response)}")
        
        print("\n" + "="*50)
        print("SUCCESS! Authentication flow completed")
        print("="*50)
        print(f"\nEmail: {email}")
        print(f"Password: {password}")
        
    except socket.timeout:
        print("\n[✗] TIMEOUT waiting for client data")
    except Exception as e:
        print(f"\n[✗] Error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        client_sock.close()
        print(f"\n[-] Connection closed: {addr[0]}:{addr[1]}\n")

def main():
    print("=== Simple Debug Server ===")
    print(f"Listening on {SERVER_HOST}:{SERVER_PORT}\n")
    
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server_sock.bind((SERVER_HOST, SERVER_PORT))
        server_sock.listen(5)
        print("[✓] Server ready - waiting for connections...\n")
        print("Press Ctrl+C to stop\n")
        print("="*50)
        
        while True:
            client_sock, addr = server_sock.accept()
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
