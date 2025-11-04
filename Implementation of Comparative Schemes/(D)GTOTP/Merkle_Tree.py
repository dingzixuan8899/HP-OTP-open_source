class MerkleTree:
    """Merkle Tree for verifying membership of verify points (uses SHA-256)."""
    def __init__(self, leaves: list[bytes]):
        """
        Build a Merkle Tree from a list of leaves (bound verify points).
        Args:
            leaves: List of ˆvp (bound verify points, bytes)
        """
        self.leaves = leaves
        self.hash_func = hashlib.sha256
        self.tree = self._build_tree()
        self.root = self.tree[-1][0] if self.tree else None

    def _build_tree(self) -> list[list[bytes]]:
        """Build the Merkle Tree (list of levels, from leaves to root)."""
        if not self.leaves:
            return []
        
        # Initialize tree with leaves (level 0)
        tree = [self.leaves.copy()]
        current_level = self.leaves.copy()

        # Build upper levels until root is reached
        while len(current_level) > 1:
            next_level = []
            # Process pairs of nodes (pad with last node if odd count)
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                right = current_level[i+1] if (i+1 < len(current_level)) else left
                parent = self.hash_func(left + right).digest()
                next_level.append(parent)
            current_level = next_level
            tree.append(current_level)
        
        return tree

    def get_proof(self, leaf: bytes) -> list[tuple[bytes, str]]:
        """
        Get a Merkle proof for a leaf (siblings + left/right position).
        Args:
            leaf: Target leaf (ˆvp, bytes)
        Returns:
            Proof: List of (sibling_node, position), where position is "left" or "right"
        Raises:
            ValueError if leaf is not in the tree
        """
        if leaf not in self.leaves:
            raise ValueError("Leaf not found in Merkle Tree")
        
        proof = []
        current_index = self.leaves.index(leaf)
        current_level = 0

        # Traverse up to the root
        while current_level < len(self.tree) - 1:
            level_nodes = self.tree[current_level]
            # Find sibling index (even: sibling is right; odd: sibling is left)
            if current_index % 2 == 0:
                sibling_index = current_index + 1
                position = "left"  # Current node is left of sibling
            else:
                sibling_index = current_index - 1
                position = "right"  # Current node is right of sibling
            
            # If sibling index is out of bounds, use current node as sibling (padding)
            sibling = level_nodes[sibling_index] if (sibling_index < len(level_nodes)) else level_nodes[current_index]
            proof.append((sibling, position))
            
            # Move to next level (parent index = current_index // 2)
            current_index = current_index // 2
            current_level += 1
        
        return proof

    @staticmethod
    def verify_proof(leaf: bytes, proof: list[tuple[bytes, str]], root: bytes, hash_func=hashlib.sha256) -> bool:
        """
        Verify if a leaf belongs to the Merkle Tree with the given root.
        Args:
            leaf: Target leaf (ˆvp, bytes)
            proof: Merkle proof (from get_proof)
            root: Expected root of the Merkle Tree (bytes)
            hash_func: Hash function used to build the tree
        Returns:
            True if valid, False otherwise
        """
        current = leaf
        for sibling, position in proof:
            if position == "left":
                # Current node is left; parent = H(current + sibling)
                current = hash_func(current + sibling).digest()
            else:
                # Current node is right; parent = H(sibling + current)
                current = hash_func(sibling + current).digest()
        return current == root