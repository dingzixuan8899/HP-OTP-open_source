import socket
import ssl
import time
import random
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

# --------------------------
# Constants (Align with Paper)
# --------------------------
TIME_STEP_X = 30  # 30 seconds (TOTP standard)
MAX_TIMESTAMP_DELAY = 60  # Max allowed timestamp skew (60s)
HASH_ALG = hashes.SHA256()
HMAC_ALG = hashes.SHA1()
ECC_CURVE = ec.SECP256R1()  # P-256 (recommended in paper)
OTP_LENGTH = 6  # 6-digit OTP (entropy ~19.93 bits)
RECOMMENDED_HONEYWORDS = 20  # k=20 (paper's recommendation)

class Honeychecker:
    """
    Honeychecker: Auxiliary server to store real password index and verify authenticity.
    Follows paper's design: Separated from main server, uses ECC for index encryption.
    """
    def __init__(self):
        # Generate ECC key pair (ElGamal variant for index encryption)
        self.private_key = ec.generate_private_key(ECC_CURVE, default_backend())
        self.public_key = self.private_key.public_key()
        self.real_index_store = {}  # Maps username -> real index Ic

    def serialize_pub_key(self) -> bytes:
        """Serialize public key for device to use during registration."""
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def decrypt_index(self, encrypted_index: tuple) -> int:
        """
        Decrypt encrypted index EIc = (E, M) using ElGamal variant (paper §IV.B.2):
        - E = g^e (ephemeral public key)
        - M = PK_HC^e XOR Ic (encrypted index)
        - Decryption: Ic = E^sk_HC XOR M
        """
        E_bytes, M_bytes = encrypted_index
        # Deserialize E (ephemeral public key)
        E = ec.EllipticCurvePublicKey.from_public_bytes(E_bytes)
        # Compute E^sk_HC (shared secret)
        shared_secret = self.private_key.exchange(ec.ECDH(), E)
        # XOR to get Ic (convert shared secret to int, then to bytes matching M length)
        shared_secret_int = int.from_bytes(shared_secret, byteorder='big')
        M_int = int.from_bytes(M_bytes, byteorder='big')
        Ic_int = shared_secret_int ^ M_int
        return Ic_int

    def store_real_index(self, username: str, encrypted_index: tuple):
        """Decrypt and store real index Ic for a user."""
        Ic = self.decrypt_index(encrypted_index)
        self.real_index_store[username] = Ic
        print(f"[Honeychecker] Stored real index {Ic} for user {username}")

    def verify_index(self, username: str, matching_indexes: list) -> str:
        """
        Verify if matching indexes from server match the real index Ic:
        - Return "1" if exactly one match (valid login)
        - Return "0" if no match (alert: server breach/guessing)
        - Return "NULL" if multiple matches (OTP collision, re-login)
        """
        if username not in self.real_index_store:
            return "NULL"  # User not registered
        
        real_Ic = self.real_index_store[username]
        matches = [idx for idx in matching_indexes if idx == real_Ic]
        
        if len(matches) == 1:
            return "1"  # Valid login
        elif len(matches) == 0:
            return "0"  # Alert: honeyword used (breach/guessing)
        else:
            return "NULL"  # Collision: re-authenticate

class HTOTPServer:
    def __init__(self, host: str = '0.0.0.0', port: int = 4433):
        self.host = host
        self.port = port
        self.honeychecker = Honeychecker()  # Integrate honeychecker
        # Server storage: username -> (honey_hashes Q, registration_timestamp T1)
        self.user_store = {}
        # TLS context (simulate secure channel per paper §IV.B.2)
        self.ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        self.ssl_context.load_cert_chain(certfile="server_cert.pem", keyfile="server_key.pem")
        # Generate self-signed cert (for testing only; use CA-signed in production)
        self._generate_test_certs()

    def _generate_test_certs(self):
        """Generate self-signed TLS certs (for testing purposes only)."""
        import os
        if not (os.path.exists("server_cert.pem") and os.path.exists("server_key.pem")):
            from cryptography.hazmat.primitives.asymmetric import rsa
            from cryptography import x509
            from cryptography.x509.oid import NameOID
            from datetime import datetime, timedelta

            # Generate RSA key for TLS
            tls_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
            # Write private key
            with open("server_key.pem", "wb") as f:
                f.write(tls_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))

            # Generate self-signed cert
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "CN"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Tianjin"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "Nankai"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "HTOTP Server"),
            ])
            cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(
                tls_key.public_key()
            ).serial_number(x509.random_serial_number()).not_valid_before(
                datetime.utcnow()
            ).not_valid_after(
                datetime.utcnow() + timedelta(days=365)
            ).sign(tls_key, hashes.SHA256(), default_backend())

            # Write cert
            with open("server_cert.pem", "wb") as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))
            print("[Server] Generated test TLS certificates")

    def _hash(self, data: bytes) -> bytes:
        """SHA-256 hash (for salted password hashes Q, paper §IV.B.1)."""
        digest = hashes.Hash(HASH_ALG, default_backend())
        digest.update(data)
        return digest.finalize()

    def _generate_otp(self, seed: bytes, timestamp_step: int) -> str:
        """
        Generate OTP using HMAC-SHA1 + truncation (paper §IV.B.1, RFC 4226):
        OTP = Truncate(HMAC-SHA1(seed, timestamp_step))
        """
        # Convert timestamp_step to 8-byte big-endian (TOTP standard)
        timestamp_bytes = timestamp_step.to_bytes(8, byteorder='big')
        # Compute HMAC-SHA1
        hmac = hashes.Hash(hashes.HMAC(seed, HMAC_ALG, backend=default_backend()))
        hmac.update(timestamp_bytes)
        hmac_result = hmac.finalize()

        # Dynamic truncation (RFC 4226 §5.3)
        offset = hmac_result[-1] & 0x0F  # Last 4 bits as offset
        truncated = hmac_result[offset:offset+4]  # 4-byte chunk
        truncated_int = int.from_bytes(truncated, byteorder='big') & 0x7FFFFFFF  # Remove sign bit
        otp = str(truncated_int % (10 ** OTP_LENGTH)).zfill(OTP_LENGTH)  # 6-digit OTP
        return otp

    def handle_registration(self, conn: ssl.SSLSocket):
        """
        Handle device registration (paper §IV.B.2):
        1. Receive username, encrypted index (EIc), honey_hashes (Q), timestamp (T1)
        2. Verify T1 freshness
        3. Store Q and T1; send EIc to honeychecker
        """
        # Receive registration data: username | EIc (E_bytes|sep|M_bytes) | Q (hash1|sep|hash2|...) | T1
        data = conn.recv(4096).decode('utf-8')
        username, e_bytes_b64, m_bytes_b64, q_list_b64, T1_str = data.split('|')
        
        # Decode base64 data
        import base64
        E_bytes = base64.b64decode(e_bytes_b64)
        M_bytes = base64.b64decode(m_bytes_b64)
        Q = [base64.b64decode(h) for h in q_list_b64.split(',')]
        T1 = int(T1_str)

        # Verify timestamp freshness (|T1' - T1| < MAX_TIMESTAMP_DELAY)
        current_T = int(time.time())
        if abs(current_T - T1) > MAX_TIMESTAMP_DELAY:
            conn.sendall(b"REG_FAIL: Timestamp out of sync")
            return

        # Validate honey_hashes count (must be RECOMMENDED_HONEYWORDS)
        if len(Q) != RECOMMENDED_HONEYWORDS:
            conn.sendall(b"REG_FAIL: Invalid honeywords count")
            return

        # Store user data and send EIc to honeychecker
        self.user_store[username] = (Q, T1)
        self.honeychecker.store_real_index(username, (E_bytes, M_bytes))
        
        conn.sendall(b"REG_SUCCESS: User registered")
        print(f"[Server] Registered user {username} (Q size: {len(Q)}, T1: {T1})")

    def handle_verification(self, conn: ssl.SSLSocket):
        """
        Handle OTP verification (paper §IV.B.3):
        1. Receive username and OTP from device/login terminal
        2. Generate OTP candidates from stored Q
        3. Find matching indexes; verify with honeychecker
        4. Return result (1=login, 0=alert, NULL=retry)
        """
        # Receive verification data: username | OTP
        data = conn.recv(4096).decode('utf-8')
        username, otp = data.split('|')

        # Check if user exists
        if username not in self.user_store:
            conn.sendall(b"VERIFY_FAIL: User not found")
            return

        Q, T1 = self.user_store[username]
        current_T = int(time.time())
        Ts_prime = (current_T - T1) // TIME_STEP_X  # Compute T_s' = (T3 - T1)/X

        # Generate OTP candidates for all hashes in Q
        matching_indexes = []
        for idx, hash_val in enumerate(Q):
            candidate_otp = self._generate_otp(hash_val, Ts_prime)
            if candidate_otp == otp:
                matching_indexes.append(idx)
                print(f"[Server] OTP match at index {idx} (candidate: {candidate_otp})")

        # Verify indexes with honeychecker
        result = self.honeychecker.verify_index(username, matching_indexes)
        
        # Send result to device/login terminal
        if result == "1":
            conn.sendall(b"VERIFY_SUCCESS: Login approved")
        elif result == "0":
            conn.sendall(b"VERIFY_ALERT: Server breach or password guessing detected")
        else:
            conn.sendall(b"VERIFY_RETRY: OTP collision, please re-authenticate")
        print(f"[Server] Verification result for {username}: {result}")

    def run(self):
        """Start TLS server and handle client connections."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            with self.ssl_context.wrap_socket(sock, server_side=True) as secure_sock:
                secure_sock.bind((self.host, self.port))
                secure_sock.listen(5)
                print(f"[Server] HTOTP Server running on {self.host}:{self.port} (TLS enabled)")
                print(f"[Server] Honeychecker Pub Key:\n{self.honeychecker.serialize_pub_key().decode('utf-8')}")

                while True:
                    conn, addr = secure_sock.accept()
                    print(f"\n[Server] New connection from {addr}")
                    try:
                        # Receive command (REGISTER / VERIFY)
                        cmd = conn.recv(16).decode('utf-8').strip()
                        if cmd == "REGISTER":
                            self.handle_registration(conn)
                        elif cmd == "VERIFY":
                            self.handle_verification(conn)
                        else:
                            conn.sendall(b"ERROR: Unknown command")
                    except Exception as e:
                        print(f"[Server] Error handling connection: {str(e)}")
                    finally:
                        conn.close()

if __name__ == "__main__":
    # Run server (use 0.0.0.0 to allow device connections)
    server = HTOTPServer(host='0.0.0.0', port=4433)
    server.run()