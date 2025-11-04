import base64
from Crypto.PublicKey import ECC
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256, HMAC


class SOSDevice:
    def __init__(self, phone_number: str, sms_gateway: MockSMSGateway):
        self.phone = phone_number
        self.sms_gateway = sms_gateway
        self.stored_keys = {}  # webID:username → K (auth key)
        self.current_reg_session = None  # Temp storage for registration

    def _generate_curve25519_key(self) -> ECC.EccKey:
        """Generate ephemeral Curve25519 key pair (per registration)."""
        return ECC.generate(curve="curve25519")

    def _hkdf_derive_keys(self, shared_secret: bytes, transcript: bytes) -> tuple[bytes, bytes]:
        """Match server's HKDF key derivation."""
        info = b"SOS-AKE:" + transcript
        derived = HKDF(shared_secret, 64, salt=None, hashmod=SHA256, info=info)
        return derived[:32], derived[32:]

    def _verify_t1(self, K_kck: bytes, transcript: bytes, received_t1: bytes) -> bool:
        """Verify T1 (from QR code) to confirm key agreement."""
        hmac = HMAC.new(K_kck, transcript, SHA256)
        return hmac.digest() == received_t1

    def _generate_t2(self, K_kck: bytes, transcript: bytes, W: bytes) -> str:
        """Generate T2 (6-digit OTP) for registration confirmation."""
        data = transcript + W
        hmac = HMAC.new(K_kck, data, SHA256)
        truncated = int.from_bytes(hmac.digest()[:3], byteorder="big") & 0xFFFFF
        return str(truncated % 1000000).zfill(6)

    # ------------------------------ Registration Phase ------------------------------
    def receive_ke1(self) -> str:
        """Step 1: Receive and parse KE1 from server."""
        ke1_msg_b64 = self.sms_gateway.receive_sms(self.phone)
        if not ke1_msg_b64:
            raise ValueError("No KE1 SMS received")

        # Decode and validate KE1
        ke1_msg = base64.b64decode(ke1_msg_b64)
        if ke1_msg[:4] != b"KE1-":
            raise ValueError("Received SMS is not KE1")

        # Extract components
        server_dh_pub_raw = ke1_msg[4:36]  # 32B pub key
        webID = ke1_msg[36:68]  # 32B server identifier
        username = ke1_msg[68:140].rstrip(b"\x00").decode()  # 72B username (strip padding)

        # Validate server's pub key
        server_dh_pub = ECC.import_key(server_dh_pub_raw, curve_name="curve25519")

        # Generate device's Curve25519 key pair
        device_dh_key = self._generate_curve25519_key()

        # Store session data
        self.current_reg_session = {
            "phase": "ke1_received",
            "server_dh_pub": server_dh_pub,
            "device_dh_priv": device_dh_key,
            "device_dh_pub_raw": device_dh_key.public_key().export_key(format="raw"),
            "webID": webID,
            "username": username,
            "transcript_ke1": b"KE1:" + server_dh_pub_raw + webID + username.encode()
        }

        print(f"[Device] Received KE1 for user: {username}")
        return username

    def send_ke2(self, server_phone: str) -> None:
        """Step 2: Send KE2 (device's pub key) to server."""
        if not self.current_reg_session or self.current_reg_session["phase"] != "ke1_received":
            raise ValueError("KE1 not received yet")

        # Build KE2 SMS
        header = b"KE2-"
        ke2_msg = header + self.current_reg_session["device_dh_pub_raw"]
        ke2_msg_b64 = base64.b64encode(ke2_msg).decode()

        # Send to server's phone number
        self.sms_gateway.send_sms(server_phone, ke2_msg_b64)
        self.current_reg_session["phase"] = "ke2_sent"
        print(f"[Device] Sent KE2 to server")

    def scan_qr_and_generate_t2(self, qr_data: str) -> str:
        """Step 3: Scan QR (AUTH1 data) → verify T1 → generate T2 (OTP)."""
        if not self.current_reg_session or self.current_reg_session["phase"] != "ke2_sent":
            raise ValueError("KE2 not sent yet")

        session = self.current_reg_session
        try:
            # Parse QR data (transcript,T1,W)
            transcript_b64, T1_b64, W_b64 = qr_data.split(",")
            transcript = base64.b64decode(transcript_b64)
            received_t1 = base64.b64decode(T1_b64)
            W = base64.b64decode(W_b64)
        except ValueError:
            raise ValueError("Invalid QR code format")

        # Verify transcript matches local state
        expected_transcript = session["transcript_ke1"] + b"|KE2:" + session["device_dh_pub_raw"]
        if transcript != expected_transcript:
            raise ValueError("Transcript mismatch (tampered QR)")

        # Derive shared secret and keys
        shared_secret = session["device_dh_priv"].exchange(session["server_dh_pub"])
        K, K_kck = self._hkdf_derive_keys(shared_secret, transcript)

        # Verify T1 (key confirmation)
        if not self._verify_t1(K_kck, transcript, received_t1):
            raise ValueError("Invalid T1 (registration tampered)")

        # Generate T2 (OTP) and store auth key
        T2 = self._generate_t2(K_kck, transcript, W)
        key_id = f"{base64.b64encode(session['webID']).decode()}:{session['username']}"
        self.stored_keys[key_id] = K

        session["phase"] = "registration_completed"
        print(f"[Device] QR scanned → T2 (OTP) generated: {T2}")
        return T2

    # ------------------------------ Authentication Phase ------------------------------
    def receive_auth_w_and_generate_otp(self) -> str:
        """Receive W from server → generate OTP using stored K."""
        # Receive authentication SMS
        auth_msg_b64 = self.sms_gateway.receive_sms(self.phone)
        if not auth_msg_b64:
            raise ValueError("No authentication SMS received")

        # Decode and parse
        auth_msg = base64.b64decode(auth_msg_b64)
        if auth_msg[:4] != b"AUTH":
            raise ValueError("Received SMS is not authentication W")

        # Extract components
        W = auth_msg[4:36]  # 32B challenge
        webID = auth_msg[36:68]  # 32B server identifier
        username = auth_msg[68:140].rstrip(b"\x00").decode()  # 72B username

        # Retrieve stored auth key
        key_id = f"{base64.b64encode(webID).decode()}:{username}"
        if key_id not in self.stored_keys:
            raise ValueError("No stored auth key for this user/server")
        K = self.stored_keys[key_id]

        # Generate OTP
        hmac = HMAC.new(K, W, SHA256)
        truncated = int.from_bytes(hmac.digest()[:3], byteorder="big") & 0xFFFFF
        otp = str(truncated % 1000000).zfill(6)

        print(f"[Device] Authentication OTP generated: {otp}")
        return otp
