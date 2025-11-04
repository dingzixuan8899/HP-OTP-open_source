class GTOTP_RA:
    """Registration Authority (RA) for GTOTP-MT: setup, GVST generation, and identity tracing."""
    def __init__(self, kappa: int = 256):
        """
        Initialize RA with security parameter κ.
        Args:
            kappa: Security parameter (bits, default: 256)
        """
        self.kappa = kappa
        self.ase = ASE()  # ASE for encrypting device IDs (k_RA = ase.key)
        self.kp = os.urandom(kappa // 8)  # Permutation key (unpredictable permutation)
        self.h1 = None  # H₁ instance (initialized in Setup)
        self.pms = None  # System parameters (initialized in Setup)

    def setup(self, Ts: int, Te: int, delta_e: int, delta_s: int, false_positive_rate: float = 0.001, phi: int = 8) -> dict:
        """
        Run GTOTP.Setup: Generate system parameters (pms).
        Args:
            Ts: Start time of GTOTP validity (Unix timestamp)
            Te: End time of GTOTP validity (Unix timestamp)
            delta_e: Duration of each verify epoch (seconds)
            delta_s: Password generation interval (seconds)
            false_positive_rate: Bloom Filter ε (default: 0.001)
            phi: Number of Merkle Trees (default: 8, paper uses 8192)
        Returns:
            pms: Public system parameters (shared with devices/verifier)
        """
        # Calculate core parameters
        E = (Te - Ts) // delta_e  # Number of verify epochs
        N = delta_e // delta_s    # Number of passwords per TOTP instance
        
        # Initialize H₁ (collision-resistant hash)
        h1_key = os.urandom(self.kappa // 8)
        self.h1 = H1(key=h1_key)

        # Store system parameters (pms)
        self.pms = {
            "κ": self.kappa,
            "Ts": Ts,
            "Te": Te,
            "Δe": delta_e,
            "Δs": delta_s,
            "E": E,
            "N": N,
            "ϕ": phi,
            "h1_key": h1_key,  # Public (used by Verifier)
            "false_positive_rate": false_positive_rate
        }

        return self.pms

    def gvst_gen(self, device_vp_dict: dict[str, list[bytes]]) -> tuple[BloomFilter, dict[str, tuple[list[bytes], list[list[tuple[bytes, str]]]]]]:
        """
        Run GTOTP.GVSTGen: Generate Group Verification State (GVST) and device-specific data.
        Args:
            device_vp_dict: {device_id: vp_list} (vp_list from each device's PInit)
        Returns:
            tuple: (vstG: Bloom Filter, device_data: {device_id: (ci_list, merkle_proofs)})
        """
        if not self.pms:
            raise ValueError("RA must run Setup() before GVSTGen()")
        
        E = self.pms["E"]
        phi = self.pms["ϕ"]
        false_positive_rate = self.pms["false_positive_rate"]

        # Step 1: Collect and bind all verify points (ˆvp = H₁(vp_i || Ci || i))
        all_bound_vps = []
        device_bound_vps = {}  # {device_id: [ˆvp_i for i in 0..E-1]}
        device_ci = {}         # {device_id: [Ci for i in 0..E-1]}

        for device_id, vp_list in device_vp_dict.items():
            device_bytes = device_id.encode()
            bound_vps = []
            ci_list = []

            for i in range(E):
                vp_i = vp_list[i]
                # Encrypt device ID to get Ci (randomized due to AES-GCM-SIV)
                ci = self.ase.encrypt(device_bytes)
                # Bind vp_i, Ci, and i with H₁
                bound_vp = self.h1.eval(vp=vp_i, ci=ci, epoch_idx=i)
                
                bound_vps.append(bound_vp)
                ci_list.append(ci)
            
            all_bound_vps.extend(bound_vps)
            device_bound_vps[device_id] = bound_vps
            device_ci[device_id] = ci_list

        # Step 2: Shuffle bound verify points (unpredictable permutation)
        shuffled_bound_vps = unpredictable_permutation(all_bound_vps, self.kp)

        # Step 3: Split into ϕ subsets and build Merkle Trees
        subset_size = max(1, len(shuffled_bound_vps) // phi)
        subsets = [
            shuffled_bound_vps[i*subset_size : (i+1)*subset_size]
            for i in range(phi)
        ]
        # Pad last subset with dummy (if needed) to avoid empty trees
        if len(subsets[-1]) == 0 and len(subsets) > 1:
            subsets[-1] = subsets[-2][:1]

        # Build Merkle Tree for each subset
        merkle_trees = [MerkleTree(leaves=subset) for subset in subsets]
        merkle_roots = [tree.root for tree in merkle_trees]

        # Step 4: Create Bloom Filter (vstG) from Merkle roots
        vstG = BloomFilter(
            false_positive_rate=false_positive_rate,
            num_elements=len(merkle_roots)
        )
        for root in merkle_roots:
            vstG.insert(root)

        # Step 5: Generate Merkle proofs for each device's bound verify points
        device_data = {}
        for device_id in device_vp_dict.keys():
            bound_vps = device_bound_vps[device_id]
            ci_list = device_ci[device_id]
            merkle_proofs = []

            for bound_vp in bound_vps:
                # Find which Merkle Tree contains the bound_vp
                tree_idx = None
                for idx, tree in enumerate(merkle_trees):
                    if bound_vp in tree.leaves:
                        tree_idx = idx
                        break
                if tree_idx is None:
                    raise ValueError(f"Bound VP not found in any Merkle Tree (device: {device_id})")
                
                # Get proof from the tree
                proof = merkle_trees[tree_idx].get_proof(bound_vp)
                merkle_proofs.append(proof)
            
            device_data[device_id] = (ci_list, merkle_proofs)

        return (vstG, device_data)

    def open(self, gt otp_pw: tuple[bytes, bytes, list[tuple[bytes, str]]], T: int, vstG: BloomFilter, verifier: "GTOTP_Verifier") -> str:
        """
        Run GTOTP.Open: Trace the identity of the password owner.
        Args:
            gt otp_pw: GTOTP password tuple (pw, ci, merkle_proof)
            T: Time slot for the password (Unix timestamp)
            vstG: Group Verification State (Bloom Filter)
            verifier: GTOTP Verifier instance (to validate the password first)
        Returns:
            device_id: Decrypted device ID (str) or "⊥" if invalid
        """
        # Step 1: First verify if the password is valid
        if not verifier.verify(gt otp_pw, T, self.pms):
            return "⊥"
        
        # Step 2: Extract Ci from the password and decrypt it
        ci = gt otp_pw[1]
        try:
            device_id_bytes = self.ase.decrypt(ci)
            return device_id_bytes.decode()
        except Exception:
            return "⊥"