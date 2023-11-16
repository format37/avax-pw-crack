# Constants for secp256k1
p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
a = 0
b = 7
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8


class Bignum:
    def __init__(self, value=0):
        if isinstance(value, list):
            self.d = value
            self.neg = 0  # Assuming the list represents a non-negative number
        else:
            self.d = self._int_to_words(value)
            self.neg = int(value < 0)
        self.top = len(self.d)
        self.dmax = len(self.d)

    @staticmethod
    def _int_to_words(value):
        words = []
        abs_value = abs(value)
        while abs_value:
            words.append(abs_value & 0xFFFFFFFF)
            abs_value >>= 32
        return words

    def to_int(self):
        value = 0
        for i, word in enumerate(self.d):
            value += word << (32 * i)
        return -value if self.neg else value

    def __str__(self):
        return f"{'-' if self.neg else ''}{''.join(f'{x:08x}' for x in reversed(self.d))}"

    def __add__(self, other):
        # Basic addition of two Bignum numbers
        max_len = max(len(self.d), len(other.d))
        result = []
        carry = 0
        for i in range(max_len):
            a = self.d[i] if i < len(self.d) else 0
            b = other.d[i] if i < len(other.d) else 0
            sum_val = a + b + carry
            result.append(sum_val & 0xFFFFFFFF)
            carry = sum_val >> 32
        if carry:
            result.append(carry)
        return Bignum(result)

    def __sub__(self, other):
        # Basic subtraction of two Bignum numbers
        result = []
        borrow = 0
        for i in range(len(self.d)):
            a = self.d[i]
            b = other.d[i] if i < len(other.d) else 0
            diff = a - b - borrow
            if diff < 0:
                diff += 0x100000000
                borrow = 1
            else:
                borrow = 0
            result.append(diff)
        return Bignum(result)

    def __mod__(self, other):
        # Basic modulo operation for Bignum
        # For simplicity, assuming non-negative values and other is non-zero
        if self < other:
            return self
        elif self == other:
            return Bignum(0)
        else:
            # Implementing a simple subtraction-based modulo for demonstration purposes
            temp = Bignum(self.d)
            while temp >= other:
                temp -= other
            return temp

    def __floordiv__(self, other):
        # Basic floor division operation for Bignum
        # For simplicity, assuming non-negative values and other is non-zero
        quotient = Bignum(0)
        remainder = Bignum(self.d)
        while remainder >= other:
            remainder -= other
            quotient += Bignum(1)
        return quotient
    

def mod_inverse(a, m):
    """
    Compute the modular inverse of a modulo m using the Extended Euclidean Algorithm.
    a and m are Bignum objects.
    """
    if m == Bignum(0):
        return None

    lm, hm = Bignum(1), Bignum(0)
    low, high = a % m, m
    while low.to_int() > 1:
        ratio = high // low
        nm, new = hm - lm * ratio, high - low * ratio
        hm, high, lm, low = lm, low, nm, new

    return lm % m


class Point:
    def __init__(self, x, y, a, b):
        # Ensuring that x, y, a, and b are Bignum instances
        self.x = x if isinstance(x, Bignum) else Bignum(x)
        self.y = y if isinstance(y, Bignum) else Bignum(y)
        self.a = a if isinstance(a, Bignum) else Bignum(a)
        self.b = b if isinstance(b, Bignum) else Bignum(b)

    def __str__(self):
        return f"Point({self.x}, {self.y})"

    def __add__(self, other):
        # Point addition using Bignum arithmetic
        if self.a != other.a or self.b != other.b:
            raise ValueError("Points are not on the same curve")

        # Handle special cases (point at infinity)
        if self.x.to_int() is None:
            return other
        if other.x.to_int() is None:
            return self

        # Point addition formula
        if self.x == other.x and self.y != other.y:
            # Result is point at infinity
            return Point(None, None, self.a, self.b)

        """if self.x != other.x:
            # General case: point addition formula
            s = (other.y - self.y) / (other.x - self.x)  # Will need to implement division for Bignum
            x3 = s * s - self.x - other.x
            y3 = s * (self.x - x3) - self.y
            return Point(x3, y3, self.a, self.b)

        # Case: self.x == other.x (and self.y == other.y)
        # Point doubling formula
        s = (3 * self.x * self.x + self.a) / (2 * self.y)  # Will need to implement division for Bignum
        x3 = s * s - 2 * self.x
        y3 = s * (self.x - x3) - self.y
        return Point(x3, y3, self.a, self.b)"""
        # Point addition formula
        if self.x != other.x:
            # Use modular inverse for division
            s = (other.y - self.y) * mod_inverse(other.x - self.x, p)
            x3 = (s * s - self.x - other.x) % p
            y3 = (s * (self.x - x3) - self.y) % p
            return Point(x3, y3, self.a, self.b)

        # Point doubling formula
        # Use modular inverse for division
        s = (3 * self.x * self.x + self.a) * mod_inverse(2 * self.y, p)
        x3 = (s * s - 2 * self.x) % p
        y3 = (s * (self.x - x3) - self.y) % p
        return Point(x3, y3, self.a, self.b)
    

    def __rmul__(self, coefficient):
        # Scalar multiplication using the double-and-add method
        coef = coefficient
        current = self
        result = Point(None, None, self.a, self.b)  # Starting with the point at infinity
        while coef > 0:
            if coef & 1:
                result += current
            current += current
            coef >>= 1
        return result


# Test the modified Point class with Bignum
point1 = Point(Gx, Gy, a, b)
point2 = Point(Gx, Gy, a, b)
sum_point = point1 + point2  # Point addition
print(sum_point)

# Retesting the arithmetic operations
num1 = Bignum(12345)
num2 = Bignum(6789)

add_result = num1 + num2
sub_result = num1 - num2
mul_result = num1 * num2
div_result = num1 // num2
mod_result = num1 % num2

print(
    add_result.to_int(), 
    sub_result.to_int(), 
    mul_result.to_int(), 
    div_result.to_int(), 
    mod_result.to_int()
    )