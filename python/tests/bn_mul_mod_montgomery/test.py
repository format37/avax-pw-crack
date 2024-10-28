def montgomery_multiplication(a, b, n):
    """
    Perform Montgomery multiplication of a and b modulo n.
    
    Parameters:
    a (int): First operand.
    b (int): Second operand.
    n (int): Modulus.

    Returns:
    int: The result of (a * b) mod n using Montgomery multiplication.
    """
    import math

    # Step 1: Calculate R = 2^k where k is the number of bits in n
    k = n.bit_length()
    R = 1 << k  # R = 2^k

    # Ensure R and n are coprime
    assert math.gcd(R, n) == 1, "R and n must be coprime."

    # Step 2: Compute n' = -n^{-1} mod R
    n_inv = pow(-n, -1, R)
    n_prime = n_inv % R

    # Step 3: Convert operands to Montgomery form
    a_bar = (a * R) % n
    b_bar = (b * R) % n

    # Step 4: Montgomery multiplication in Montgomery form
    t = a_bar * b_bar
    m = (t * n_prime) % R
    u = (t + m * n) // R
    if u >= n:
        u -= n

    # Step 5: Convert result back from Montgomery form
    t = u
    m = (t * n_prime) % R
    u = (t + m * n) // R
    if u >= n:
        u -= n

    return u

# Example usage
if __name__ == "__main__":
    n = 101  # Modulus
    a = 45   # First operand
    b = 76   # Second operand

    result = montgomery_multiplication(a, b, n)
    expected = (a * b) % n

    print(f"Montgomery multiplication result: {result}")
    print(f"Expected result: {expected}")
    print(f"Computation is {'correct' if result == expected else 'incorrect'}.")
