import socket
import struct
import json
import time
from crypto import dh, aes, sign, pki

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 9999

def recv_exact(sock, n):
    """Receive exactly n bytes from socket"""
    buf = b""
    while len(buf) < n:
        part = sock.recv(n - len(buf))
        if not part:
            raise ConnectionError("Connection closed")
        buf += part
    return buf

def print_banner():
    """Print client banner"""
    banner = """
    ╔═══════════════════════════════════════╗
    ║     SECURE CHAT CLIENT v1.0          ║
    ║  End-to-End Encrypted Messaging      ║
    ╚═══════════════════════════════════════╝
    """
    print(banner)

def main():
    print_banner()
    print("=== Starting Secure Chat Client ===\n")
    
    # --- Load CA and client certs/keys ---
    try:
        print("[1/7] Loading certificates and keys...")
        ROOT_CA_CERT = pki.load_certificate("root_ca_cert.pem")
        CLIENT_KEY = pki.load_private_key("client_key.pem")
        CLIENT_CERT = pki.load_certificate("client_cert.pem")
        print("      [✓] Certificates and keys loaded successfully\n")
    except FileNotFoundError as e:
        print(f"      [✗] Certificate file not found: {e}")
        print("      Run: python scripts/gen_ca.py && python scripts/gen_cert.py client")
        return
    except Exception as e:
        print(f"      [✗] Failed to load certificates/keys: {e}")
        return

    # --- Connect to server ---
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(30.0)
    # Disable Nagle's algorithm for immediate sends
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    
    try:
        print(f"[2/7] Connecting to server...")
        print(f"      Host: {SERVER_HOST}:{SERVER_PORT}")
        s.connect((SERVER_HOST, SERVER_PORT))
        print(f"      [✓] Connected to server\n")
    except socket.timeout:
        print(f"      [✗] Connection timeout")
        return
    except ConnectionRefusedError:
        print(f"      [✗] Connection refused - is server running?")
        return
    except Exception as e:
        print(f"      [✗] Connection failed: {e}")
        return

    try:
        # --- Step 1: Registration/Login ---
        print("[3/7] Authentication...")
        
        # Set reasonable timeout for authentication
        s.settimeout(10.0)
        
        # Receive and respond to email prompt
        prompt1 = s.recv(1024).decode().strip()
        print(f"      {prompt1}", end=" ")
        email = input().strip()
        s.sendall((email + '\n').encode())
        
        # Small delay to ensure server is ready
        time.sleep(0.1)

        # Receive and respond to password prompt
        prompt2 = s.recv(1024).decode().strip()
        print(f"      {prompt2}", end=" ")
        password = input().strip()  # Changed from getpass for debugging
        s.sendall((password + '\n').encode())
        
        # Small delay before receiving response
        time.sleep(0.1)

        # Get authentication response (read line by line to avoid consuming cert data)
        response_data = b""
        while b'\n' not in response_data:
            chunk = s.recv(1)
            if not chunk:
                break
            response_data += chunk
        
        response = response_data.decode().strip()
        print(f"      {response}")

        if "Invalid" in response or "Failed" in response:
            print("      [✗] Authentication failed\n")
            return

        print("      [✓] Authentication successful\n")

        # --- Step 2: Receive server certificate ---
        print("[4/7] Certificate verification...")
        
        # Now we can safely read the certificate
        s.settimeout(10.0)
        data_len_bytes = recv_exact(s, 4)
        data_len = struct.unpack("!I", data_len_bytes)[0]
        
        server_cert_bytes = recv_exact(s, data_len)
        server_cert = pki.load_certificate_bytes(server_cert_bytes)

        # Verify server cert
        if server_cert.issuer != ROOT_CA_CERT.subject:
            print("      [✗] BAD_CERT: Server cert not signed by Root CA")
            print(f"          Server cert issuer: {server_cert.issuer}")
            print(f"          Root CA subject: {ROOT_CA_CERT.subject}")
            return

        current_time = time.time()
        # Use the new UTC methods to avoid deprecation warnings
        try:
            not_before = server_cert.not_valid_before_utc.timestamp()
            not_after = server_cert.not_valid_after_utc.timestamp()
        except AttributeError:
            # Fallback for older versions
            not_before = server_cert.not_valid_before.timestamp()
            not_after = server_cert.not_valid_after.timestamp()
            
        if not_before > current_time:
            print("      [✗] BAD_CERT: Server cert not yet valid")
            return
        if not_after < current_time:
            print("      [✗] BAD_CERT: Server cert expired")
            return

        SERVER_PUBKEY = server_cert.public_key()
        print("      [✓] Server certificate verified\n")

        # --- Step 3: Diffie-Hellman key exchange ---
        print("[5/7] Key exchange (Diffie-Hellman)...")
        private_key = dh.generate_private_key()
        pub_bytes = dh.serialize_public_key(private_key.public_key())

        # Send our DH public key with length prefix
        s.send(struct.pack("!I", len(pub_bytes)) + pub_bytes)

        # Receive server DH public key
        data_len_bytes = recv_exact(s, 4)
        data_len = struct.unpack("!I", data_len_bytes)[0]
        
        server_pub_bytes = recv_exact(s, data_len)
        server_pub_key = dh.deserialize_public_key(server_pub_bytes)

        # Compute shared session key
        session_key = private_key.exchange(server_pub_key)
        
        if isinstance(session_key, bytes):
            session_key = session_key[:16]  # AES-128 key
        else:
            # If it's an int, convert to bytes
            session_key = session_key.to_bytes(32, byteorder='big')[:16]

        print("      [✓] Secure session key established\n")

        # --- Step 4: Receive signed session receipt ---
        print("[6/7] Verifying session receipt...")
        s.settimeout(10.0)
        
        # Receipt is encrypted, so we need to read it properly
        # The receipt can be variable length, so read up to 4096 bytes
        receipt_bytes = s.recv(4096)
        
        if not receipt_bytes:
            print("      [✗] No receipt received from server")
            return
        
        print(f"      Received {len(receipt_bytes)} bytes")
        
        # Decrypt the receipt
        try:
            decrypted_receipt = aes.decrypt_message(session_key, receipt_bytes)
            receipt_json = json.loads(decrypted_receipt)
        except Exception as e:
            print(f"      [✗] Failed to decrypt receipt: {e}")
            return

        receipt_sig = bytes.fromhex(receipt_json["sig"])
        receipt_data = receipt_json["data"].encode()

        if not sign.verify_signature(SERVER_PUBKEY, receipt_data, receipt_sig):
            print("      [✗] Session receipt signature invalid")
            return

        print("      [✓] Session receipt verified\n")
        
        print("[7/7] Connection established!")
        print("\n" + "="*60)
        print("🔒 SECURE CHANNEL ACTIVE")
        print("="*60)
        print("\nCommands:")
        print("  - Type your message and press Enter")
        print("  - Type 'quit' or 'exit' to disconnect")
        print("  - Type 'help' for more commands")
        print("\n" + "="*60 + "\n")
        
        seqno = 1

        # --- Step 5: Send/Receive messages ---
        while True:
            try:
                msg_text = input(f"\n[{email}] You: ").strip()
                
                if not msg_text:
                    continue
                    
                if msg_text.lower() in ['quit', 'exit']:
                    print("\n[✓] Disconnecting...")
                    break
                
                if msg_text.lower() == 'help':
                    print("\nAvailable commands:")
                    print("  quit/exit - Disconnect from server")
                    print("  help      - Show this help message")
                    print("  stats     - Show connection statistics")
                    continue
                
                if msg_text.lower() == 'stats':
                    print(f"\nConnection Statistics:")
                    print(f"  Messages sent: {seqno - 1}")
                    print(f"  Session time: {int(time.time() - current_time)}s")
                    continue

                # Build message payload
                payload = json.dumps({"seqno": seqno, "msg": msg_text}).encode()

                # Sign payload
                signature = sign.sign_message(CLIENT_KEY, payload)
                payload_signed = json.dumps({
                    "payload": payload.hex(),
                    "sig": signature.hex()
                }).encode()

                # Encrypt and send
                enc = aes.encrypt_message(session_key, payload_signed)
                s.sendall(enc)

                # Receive server reply (use recv instead of recv_exact for variable length)
                s.settimeout(10.0)
                data = s.recv(4096)
                if not data:
                    print("\n[✗] Server disconnected")
                    break

                # Decrypt response
                try:
                    decrypted = aes.decrypt_message(session_key, data)
                except Exception as e:
                    print(f"[✗] Failed to decrypt response: {e}")
                    continue
                
                # Check for error messages first
                if decrypted in [b"SIG_FAIL", b"REPLAY"]:
                    print(f"[✗] Error: {decrypted.decode()}")
                    continue

                try:
                    server_msg = json.loads(decrypted)
                except Exception as e:
                    print(f"[✗] Failed to parse server message: {e}")
                    continue

                # Verify server signature
                payload_bytes = bytes.fromhex(server_msg["payload"])
                sig_bytes = bytes.fromhex(server_msg["sig"])
                
                if not sign.verify_signature(SERVER_PUBKEY, payload_bytes, sig_bytes):
                    print("[✗] SIG_FAIL: Server signature verification failed")
                    continue

                # Decode server message
                payload_json = json.loads(payload_bytes)
                server_seq = payload_json["seqno"]
                server_text = payload_json["msg"]

                print(f"[Server #{server_seq}]: {server_text}")
                seqno += 1
                
            except KeyboardInterrupt:
                print("\n\n[!] Interrupted by user")
                break
            except Exception as e:
                print(f"\n[✗] Error: {e}")
                continue

    except socket.timeout:
        print("\n[✗] Connection timeout - server not responding")
    except ConnectionError as e:
        print(f"\n[✗] Connection error: {e}")
    except Exception as e:
        print(f"\n[✗] Unexpected error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        print("\n[✓] Closing connection...")
        s.close()
        print("[✓] Client terminated\n")

if __name__ == "__main__":
    main()
