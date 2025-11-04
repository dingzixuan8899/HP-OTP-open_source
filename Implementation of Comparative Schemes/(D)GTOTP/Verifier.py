class GTOTP_Verifier:
    """Verifier for GTOTP-MT: validates passwords and group membership."""
    def __init__(self, vstG: BloomFilter, pms: dict):
        """
        Initialize Verifier with Group Verification State (GVST) and system parameters.
        Args:
            vstG: Group Verification State (Bloom Filter from RA)
            pms: System parameters from RA
        """
        self.vstG = vstG
        self.pms = pms
        self.h1 = H1(key=pms["h1_key"])  # H₁ instance (uses public h1_key)

    def verify(self, gt otp_pw: tuple[bytes, bytes, list[tuple[bytes, str]]], T: int, pms: dict) -> bool:
        """
        Run GTOTP.Verify: Check if a GTOTP password is valid.
        Args:
            gt otp_pw: GTOTP password tuple (pw, ci, merkle_proof)
            T: Time slot for the password (Unix timestamp)
            pms: System parameters from RA
        Returns:
            True if valid, False otherwise
        """
        # Unpack password components
        totp_pw, ci, merkle_proof = gt otp_pw

        # Step 1: Compute epoch index i and password index z
        Ts = pms["Ts"]
        delta_e = pms["Δe"]
        delta_s = pms["Δs"]
        N = pms["N"]
        
        i = (T - Ts) // delta_e
        if not (0 <= i < pms["E"]):
            return False  # Time outside validity window
        
        epoch_start = Ts + i * delta_e
        z = (T - epoch_start) // delta_s
        if not (0 <= z < N):
            return False  # Invalid password index

        # Step 2: Verify TOTP password (recover vp_i by hashing z times)
        # vp_i = H^z(totp_pw)
        vp_i = totp_pw
        for _ in range(z):
            vp_i = hashlib.sha256(vp_i).digest()
        
        # Step 3: Compute bound verify point ˆvp = H₁(vp_i || Ci || i)
        bound_vp = self.h1.eval(vp=vp_i, ci=ci, epoch_idx=i)

        # Step 4: Verify Merkle proof and check root in Bloom Filter
        # Recompute Merkle root from bound_vp and proof
        computed_root = bound_vp
        for sibling, position in merkle_proof:
            if position == "left":
                computed_root = hashlib.sha256(computed_root + sibling).digest()
            else:
                computed_root = hashlib.sha256(sibling + computed_root).digest()
        
        # Check if computed root is in Bloom Filter
        return self.vstG.check(computed_root)