from Crypto.PublicKey import ECC
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256, HMAC
from Crypto.Random import get_random_bytes
import base64


class SOSServer:
    def __init__(self, server_domain: str, sms_gateway: MockSMSGateway):
        self.server_domain = server_domain  # e.g., "sms2fa.dev"
        self.sms_gateway = sms_gateway
        self.webID = SHA256.new(self.server_domain.encode()).digest()  # 32-byte server identifier
        self.sessions = {}  # Temp storage for registration/auth sessions
        self.registered_users = {}  # Permanent storage: username → {phone, K}
        self.server_phone = "+1234567890"  # Fixed number for SMS reception

    def _generate_curve25519_key(self) -> ECC.EccKey:
        """Generate ephemeral Curve25519 key pair (per registration session)."""
        return ECC.generate(curve="curve25519")

    def _hkdf_derive_keys(self, shared_secret: bytes, transcript: bytes) -> tuple[bytes, bytes]:
        """Derive K (auth key) and K_kck (key confirmation key) via HKDF."""
        info = b"SOS-AKE:" + transcript  # Domain separation for HKDF
        derived = HKDF(shared_secret, 64, salt=None, hashmod=SHA256, info=info)
        return derived[:32], derived[32:]  # K (32B), K_kck (32B)

    def _generate_t1(self, K_kck: bytes, transcript: bytes) -> bytes:
        """Generate T1: HMAC-SHA256 of transcript (for key confirmation)."""
        hmac = HMAC.new(K_kck, digestmod=SHA256)
        hmac.update(transcript)
        return hmac.digest()

    def _verify_t2(self, K_kck: bytes, transcript: bytes, W: bytes, received_t2: str) -> bool:
        """Verify T2 (6-digit OTP) during registration."""
        data = transcript + W
        hmac = HMAC.new(K_kck, digestmod=SHA256)
        hmac.update(data)
        # Truncate to 20 bits (ceil(log2(1e6))) and mod 1e6 for 6 digits
        truncated = int.from_bytes(hmac.digest()[:3], byteorder="big") & 0xFFFFF
        expected_t2 = str(truncated % 1000000).zfill(6)
        return expected_t2 == received_t2

    # ------------------------------ Registration Phase ------------------------------
    def register_start(self, username: str, phone_number: str, password: str) -> str:
        """Step 1: Start registration (after password verification)."""
        # Simulate password check (replace with real auth in production)
        if password != "test_pass123":
            raise ValueError("Invalid password")

        # Generate server's Curve25519 key pair
        server_dh_key = self._generate_curve25519_key()
        server_dh_pub = server_dh_key.public_key().export_key(format="raw")  # 32B

        # Build KE1 transcript (for later key derivation)
        transcript = b"KE1:" + server_dh_pub + self.webID + username.encode()

        # Build KE1 SMS (header + pub key + webID + username)
        header = b"KE1-"
        username_padded = username.encode().ljust(72, b"\x00")  # Pad to 72B (protocol spec)
        ke1_msg = header + server_dh_pub + self.webID + username_padded
        ke1_msg_b64 = base64.b64encode(ke1_msg).decode()  # Safe for SMS

        # Store session data
        session_key = f"reg:{username}:{phone_number}"
        self.sessions[session_key] = {
            "phase": "ke1_sent",
            "server_dh_priv": server_dh_key,
            "transcript": transcript,
            "username": username,
            "phone": phone_number
        }

        # Send KE1 via SMS
        self.sms_gateway.send_sms(phone_number, ke1_msg_b64)
        print(f"[Server] Registration started for {username} (KE1 sent)")
        return session_key

    def register_process_ke2(self, session_key: str) -> str:
        """Step 2: Process KE2 from device and generate AUTH1 (for QR code)."""
        if session_key not in self.sessions or self.sessions[session_key]["phase"] != "ke1_sent":
            raise ValueError("Invalid session/phase")

        session = self.sessions[session_key]
        server_dh_priv = session["server_dh_priv"]
        transcript_ke1 = session["transcript"]

        # Receive KE2 from device (via SMS)
        ke2_msg_b64 = self.sms_gateway.receive_sms(self.server_phone)
        if not ke2_msg_b64:
            raise ValueError("No KE2 received from device")

        # Decode and parse KE2
        ke2_msg = base64.b64decode(ke2_msg_b64)
        if ke2_msg[:4] != b"KE2-":
            raise ValueError("Invalid KE2 header")
        device_dh_pub_raw = ke2_msg[4:36]  # Extract device's Curve25519 pub key (32B)
        device_dh_pub = ECC.import_key(device_dh_pub_raw, curve_name="curve25519")

        # Update transcript with KE2 data
        transcript = transcript_ke1 + b"|KE2:" + device_dh_pub_raw
        session["transcript"] = transcript

        # Derive shared secret and keys
        shared_secret = server_dh_priv.exchange(device_dh_pub)  # Curve25519 key exchange
        K, K_kck = self._hkdf_derive_keys(shared_secret, transcript)
        session["K"] = K
        session["K_kck"] = K_kck

        # Generate T1 and W (W derived from simulated K_psk)
        T1 = self._generate_t1(K_kck, transcript)
        K_psk = get_random_bytes(32)  # Simulate pre-shared key (from HTTPS)
        W = HMAC.new(K_psk, transcript, SHA256).digest()  # 32B challenge
        session["W"] = W
        session["K_psk"] = K_psk

        # Build AUTH1 string (for QR code: transcript,T1,W)
        auth1_str = ",".join([
            base64.b64encode(transcript).decode(),
            base64.b64encode(T1).decode(),
            base64.b64encode(W).decode()
        ])
        session["phase"] = "auth1_generated"

        print(f"[Server] Processed KE2 → AUTH1 generated (for QR)")
        return auth1_str

    def register_verify_t2(self, session_key: str, received_t2: str) -> bool:
        """Step 3: Verify T2 (OTP) to complete registration."""
        if session_key not in self.sessions or self.sessions[session_key]["phase"] != "auth1_generated":
            raise ValueError("Invalid session/phase")

        session = self.sessions[session_key]
        if self._verify_t2(session["K_kck"], session["transcript"], session["W"], received_t2):
            # Save user's auth key permanently
            self.registered_users[session["username"]] = {
                "phone": session["phone"],
                "K": session["K"]
            }
            del self.sessions[session_key]  # Clean up temp session
            print(f"[Server] Registration completed for {session['username']}")
            return True
        raise ValueError("Invalid T2 → Registration failed")

    # ------------------------------ Authentication Phase ------------------------------
    def auth_start(self, username: str, password: str) -> str:
        """Step 1: Start authentication (after password check) → send W via SMS."""
        # Verify user exists and password is correct
        if username not in self.registered_users or password != "test_pass123":
            raise ValueError("Invalid credentials")

        user = self.registered_users[username]
        W = get_random_bytes(32)  # 256-bit random challenge (protocol spec)

        # Build authentication SMS (header + W + webID + username)
        header = b"AUTH"
        username_padded = username.encode().ljust(72, b"\x00")
        auth_msg = header + W + self.webID + username_padded
        auth_msg_b64 = base64.b64encode(auth_msg).decode()

        # Store auth session
        auth_session_key = f"auth:{username}:{base64.b64encode(W).decode()[:8]}"
        self.sessions[auth_session_key] = {
            "phase": "w_sent",
            "username": username,
            "W": W,
            "K": user["K"]
        }

        # Send W via SMS
        self.sms_gateway.send_sms(user["phone"], auth_msg_b64)
        print(f"[Server] Authentication started for {username} (W sent)")
        return auth_session_key

    def auth_verify_otp(self, auth_session_key: str, received_otp: str) -> bool:
        """Step 2: Verify OTP from user to complete authentication."""
        if auth_session_key not in self.sessions or self.sessions[auth_session_key]["phase"] != "w_sent":
            raise ValueError("Invalid auth session/phase")

        session = self.sessions[auth_session_key]
        # Generate expected OTP (HMAC-SHA256(W) with K, truncated to 6 digits)
        hmac = HMAC.new(session["K"], session["W"], SHA256)
        truncated = int.from_bytes(hmac.digest()[:3], byteorder="big") & 0xFFFFF
        expected_otp = str(truncated % 1000000).zfill(6)

        # Clean up session
        del self.sessions[auth_session_key]

        if expected_otp == received_otp:
            print(f"[Server] Authentication SUCCESS for {session['username']}")
            return True
        print(f"[Server] Authentication FAILED for {session['username']}")
        return False