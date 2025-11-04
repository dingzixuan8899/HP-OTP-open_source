class BloomFilter:
    """Bloom Filter for membership testing of Merkle roots (negligible false positives)."""
    def __init__(self, false_positive_rate: float, num_elements: int):
        """
        Initialize Bloom Filter with target false positive rate and element count.
        Args:
            false_positive_rate: Target ε (e.g., 0.001)
            num_elements: Expected number of elements (ϕ, number of Merkle Trees)
        """
        # Calculate optimal bit array size (m) and number of hash functions (k)
        self.m = int(-num_elements * math.log(false_positive_rate) / (math.log(2) ** 2))
        self.k = int((self.m / num_elements) * math.log(2))
        self.bit_array = bitarray(self.m)
        self.bit_array.setall(0)
        self.hash_funcs = [lambda x, i=i: hashlib.sha256(x + str(i).encode()).digest() for i in range(self.k)]

    def _get_bit_positions(self, element: bytes) -> list[int]:
        """Compute bit positions for an element using k hash functions."""
        positions = []
        for h in self.hash_funcs:
            hash_val = h(element)
            pos = int.from_bytes(hash_val, byteorder="big") % self.m
            positions.append(pos)
        return positions

    def insert(self, element: bytes) -> None:
        """Insert an element (Merkle root) into the Bloom Filter."""
        for pos in self._get_bit_positions(element):
            self.bit_array[pos] = 1

    def check(self, element: bytes) -> bool:
        """
        Check if an element is in the Bloom Filter (no false negatives).
        Returns:
            True if element is likely present, False otherwise
        """
        for pos in self._get_bit_positions(element):
            if not self.bit_array[pos]:
                return False
        return True