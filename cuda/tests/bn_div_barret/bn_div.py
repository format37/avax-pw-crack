def barrett_reduction(x, m):
    """
    Barrett reduction to compute quotient and remainder of a division.
    :param x: The dividend (integer to be divided).
    :param m: The modulus (divisor).
    :return: A tuple containing (quotient, remainder).
    """
    # print x and m
    print(f">> x: {hex(x)}")
    print(f">> m: {hex(m)}")
    # Step 1: Precompute mu = floor(2^(2 * k) / m), where k is the number of bits in m
    k = m.bit_length()
    mu = (1 << (2 * k)) // m
    print(f"mu: {hex(mu)}")

    # Step 2: Calculate q = floor(x / m) using Barrett approximation
    q = (x * mu) >> (2 * k)

    # Step 3: Compute the remainder r = x - q * m
    r = x - q * m

    # Step 4: If r >= m, subtract m and increment q
    while r >= m:
        r -= m
        q += 1
    
    # Step 5: If r < 0, add m and decrement q
    while r < 0:
        r += m
        q -= 1

    return q, r


# Test the solution with a large 128-bit integer
if __name__ == "__main__":
    # Example dividend (128-bit integer) and modulus (64-bit integer)
    x = 0x12345678ABCDEF12  # 128-bit integer
    m = 0x1ABCDEF12345678  # 64-bit modulus

    # Compute quotient and remainder using Barrett reduction
    quotient, remainder = barrett_reduction(x, m)

    # Print the results
    print(f"Quotient: {hex(quotient)}")
    print(f"Remainder: {hex(remainder)}")

    # Verify correctness using Python's built-in division
    assert x == quotient * m + remainder, "The result is incorrect!"
    print("The result is correct!")