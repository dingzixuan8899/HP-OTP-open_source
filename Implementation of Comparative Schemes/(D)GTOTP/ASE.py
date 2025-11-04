class ASE:
    """Authenticated Symmetric Encryption (ASE) using AES-GCM-SIV (randomized)."""
    def __init__(self, key: bytes = None):
        """
        Initialize ASE with a random key (if not provided).
        Args:
            key: AES key (16/24/32 bytes, optional)
        """
        self.key = key if key else AESGCM SIV.generate_key(bit_length=256)  # 256-bit key

    def encrypt(self, plaintext: bytes) -> bytes:
        """
        Encrypt plaintext (device ID) with a random nonce.
        Args:
            plaintext: Device ID (bytes)
        Returns:
            Ciphertext (nonce + tag + ciphertext, bytes)
        """
        nonce = os.urandom(12)  # 12-byte nonce (recommended for AES-GCM-SIV)
        ciphertext = AESGCM SIV(self.key).encrypt(nonce, plaintext, None)
        return nonce + ciphertext  # Nonce is needed for decryption

    def decrypt(self, ciphertext: bytes) -> bytes:
        """
        Decrypt ciphertext to recover plaintext (device ID).
        Args:
            ciphertext: Nonce + tag + ciphertext (bytes)
        Returns:
            Plaintext (device ID, bytes)
        Raises:
            InvalidTag exception if ciphertext is tampered with
        """
        nonce = ciphertext[:12]
        ciphertext_data = ciphertext[12:]
        return AESGCM SIV(self.key).decrypt(nonce, ciphertext_data, None)
