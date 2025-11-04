class TOTP:
    """Asymmetric TOTP scheme (hash-chain based) for single-device authentication."""
    def __init__(self, delta_e: int, delta_s: int, hash_func=hashlib.sha256):
        """
        Initialize TOTP instance for a single verify epoch.
        Args:
            delta_e: Duration of the verify epoch (seconds)
            delta_s: Password generation interval (seconds)
            hash_func: One-way hash function (default: SHA-256)
        """
        self.delta_e = delta_e
        self.delta_s = delta_s
        self.hash_func = hash_func
        self.N = delta_e // delta_s  # Number of passwords per TOTP instance
        self.hash_chain = []  # hash_chain[z] = password for index z (0 ≤ z < N)
        self.vp = None  # Verify point (tail of the hash chain: hash_chain[N])

    def p_init(self, secret_seed: bytes) -> bytes:
        """
        Generate hash chain from a secret seed and return the verify point (vp).
        Args:
            secret_seed: Random seed for the TOTP instance (from PRF)
        Returns:
            Verify point (vp: tail of the hash chain, bytes)
        """
        # Build hash chain: pw_0 = secret_seed, pw_1 = H(pw_0), ..., pw_N = H(pw_{N-1})
        self.hash_chain = [secret_seed]
        current = secret_seed
        for _ in range(self.N):
            current = self.hash_func(current).digest()
            self.hash_chain.append(current)
        self.vp = self.hash_chain[-1]  # vp = pw_N (tail)
        return self.vp

    def p_gen(self, z: int) -> bytes:
        """
        Generate the z-th one-time password for the current epoch.
        Args:
            z: Password index in the epoch (0 ≤ z < N)
        Returns:
            One-time password (pw = hash_chain[N - z], bytes)
        """
        if not (0 <= z < self.N):
            raise ValueError(f"z must be in [0, {self.N-1}]")
        return self.hash_chain[self.N - z]

    @staticmethod
    def verify(vp: bytes, pw: bytes, z: int, hash_func=hashlib.sha256) -> bool:
        """
        Verify if a password is valid for a given verify point and index z.
        Args:
            vp: Verify point (tail of the hash chain, bytes)
            pw: Candidate password (bytes)
            z: Password index (number of hashes needed to reach vp)
            hash_func: Same hash function used in PInit/PGen
        Returns:
            True if valid, False otherwise
        """
        current = pw
        for _ in range(z):
            current = hash_func(current).digest()
        return current == vp