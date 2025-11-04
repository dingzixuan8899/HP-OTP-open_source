class GTO TP_Device:
    """Device (group member) for GTOTP-MT: generates passwords and interacts with RA."""
    def __init__(self, device_id: str):
        """
        Initialize a GTOTP device.
        Args:
            device_id: Unique identifier of the device (e.g., "user_123")
        """
        self.device_id = device_id.encode()  # Encode to bytes for cryptography
        self.prf = PRF()  # PRF for generating TOTP secret seeds
        self.totp_instances = []  # List of TOTP objects (one per verify epoch)
        self.vp_list = []  # List of TOTP verify points (vp_i for each epoch i)
        self.ci_list = []  # List of encrypted IDs (Ci from RA, one per epoch)
        self.merkle_proofs = []  # List of Merkle proofs (one per epoch)

    def p_init(self, ra_params: dict) -> list[bytes]:
        """
        Run GTOTP.PInit: Initialize TOTP instances and generate verify points.
        Args:
            ra_params: System parameters from RA (E, Δe, Δs, Ts)
        Returns:
            vp_list: List of TOTP verify points (to send to RA)
        """
        E = ra_params["E"]  # Number of verify epochs
        delta_e = ra_params["Δe"]
        delta_s = ra_params["Δs"]
        Ts = ra_params["Ts"]

        self.totp_instances = []
        self.vp_list = []

        # Initialize one TOTP instance per epoch
        for i in range(E):
            # Generate secret seed for epoch i via PRF: sd_i = PRF(device_id || i)
            prf_msg = self.device_id + str(i).encode()
            sd_i = self.prf.eval(prf_msg)
            
            # Initialize TOTP instance and get verify point vp_i
            totp = TOTP(delta_e=delta_e, delta_s=delta_s)
            vp_i = totp.p_init(secret_seed=sd_i)
            
            self.totp_instances.append(totp)
            self.vp_list.append(vp_i)
        
        return self.vp_list

    def receive_ra_data(self, ci_list: list[bytes], merkle_proofs: list[list[tuple[bytes, str]]]) -> None:
        """
        Receive encrypted IDs (Ci) and Merkle proofs from RA.
        Args:
            ci_list: List of Ci (encrypted device ID, one per epoch)
            merkle_proofs: List of Merkle proofs (one per epoch)
        """
        self.ci_list = ci_list
        self.merkle_proofs = merkle_proofs

    def get_sd(self, T: int, ra_params: dict) -> bytes:
        """
        Run GTOTP.GetSD: Retrieve secret seed for time slot T.
        Args:
            T: Current time (Unix timestamp)
            ra_params: System parameters from RA (Ts, Δe)
        Returns:
            sd_i: Secret seed for the epoch containing T
        """
        # Compute epoch index i: i = floor((T - Ts) / Δe)
        i = (T - ra_params["Ts"]) // ra_params["Δe"]
        if not (0 <= i < len(self.totp_instances)):
            raise ValueError(f"Time T={T} is outside the GTOTP validity window")
        
        # Regenerate secret seed (no need to store it persistently)
        prf_msg = self.device_id + str(i).encode()
        return self.prf.eval(prf_msg)

    def pw_gen(self, T: int, ra_params: dict) -> tuple[bytes, bytes, list[tuple[bytes, str]]]:
        """
        Run GTOTP.PwGen: Generate a GTOTP password for time slot T.
        Args:
            T: Current time (Unix timestamp)
            ra_params: System parameters from RA (Ts, Δe, Δs)
        Returns:
            GTOTP password tuple: (TOTP_password, Ci, Merkle_proof)
        """
        # Step 1: Compute epoch index i and password index z
        Ts = ra_params["Ts"]
        delta_e = ra_params["Δe"]
        delta_s = ra_params["Δs"]
        
        i = (T - Ts) // delta_e
        if not (0 <= i < len(self.totp_instances)):
            raise ValueError(f"Time T={T} is outside the GTOTP validity window")
        
        # z = floor((T - (Ts + i*Δe)) / Δs)
        epoch_start = Ts + i * delta_e
        z = (T - epoch_start) // delta_s
        if not (0 <= z < self.totp_instances[i].N):
            raise ValueError(f"Invalid password index z={z} for epoch i={i}")

        # Step 2: Generate TOTP password
        totp_password = self.totp_instances[i].p_gen(z)

        # Step 3: Retrieve Ci and Merkle proof for epoch i
        ci = self.ci_list[i]
        merkle_proof = self.merkle_proofs[i]

        return (totp_password, ci, merkle_proof)