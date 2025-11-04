def unpredictable_permutation(data: list[bytes], key: bytes) -> list[bytes]:
    """
    Shuffle a list of elements using an unpredictable permutation (seeded by key).
    Args:
        data: List of ˆvp (bound verify points)
        key: RA's permutation key (kp)
    Returns:
        Shuffled list
    """
    # Generate a deterministic seed from the key
    seed = hmac.new(key, b"gtotp_permutation_seed", hashlib.sha256).digest()
    seed_int = int.from_bytes(seed, byteorder="big")
    
    # Shuffle with the seed (reproducible)
    random.seed(seed_int)
    shuffled = data.copy()
    random.shuffle(shuffled)
    return shuffled