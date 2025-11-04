class PRF:
    """Pseudorandom Function (PRF) based on HMAC-SHA256."""
    def __init__(self, key: bytes = None):
        """
        Initialize PRF with a random key (if not provided).
        Args:
            key: PRF secret key (bytes, optional)
        """
        self.key = key if key else os.urandom(32)  # 256-bit key (κ=256)

    def eval(self, msg: bytes) -> bytes:
        """
        Evaluate PRF on a message.
        Args:
            msg: Input message (e.g., "device_id|epoch_idx")
        Returns:
            PRF output (32-byte hash, bytes)
        """
        return hmac.new(self.key, msg, hashlib.sha256).digest()