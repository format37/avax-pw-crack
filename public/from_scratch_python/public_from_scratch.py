# Implementing elliptic curve operations for secp256k1

# Constants for secp256k1
p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
a = 0
b = 7
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

# Define a point class
class Point:
    def __init__(self, x, y, a, b):
        self.x = x
        self.y = y
        self.a = a
        self.b = b

    # Point addition
    def __add__(self, other):
        if self.a != other.a or self.b != other.b:
            print(f'Points are not on the same curve: {self}, {other}')
            raise TypeError("Points {}, {} are not on the same curve".format(self, other))
        
        # Case 0.0: self is the point at infinity, return other
        if self.x is None:
            print('self is the point at infinity')
            return other
        
        # Case 0.1: other is the point at infinity, return self
        if other.x is None:
            print('other is the point at infinity')
            return self

        # Case 1: self.x == other.x, self.y != other.y
        # Result is point at infinity
        if self.x == other.x and self.y != other.y:
            print('self.x == other.x, self.y != other.y')
            return self.__class__(None, None, self.a, self.b)
        
        # Case 2: self.x != other.x
        if self.x != other.x:
            print('self.x != other.x')
            # Formula (x3, y3) = (x1, y1) + (x2, y2)
            s = (other.y - self.y) * pow(other.x - self.x, -1, p)
            x3 = (s ** 2 - self.x - other.x) % p
            y3 = (s * (self.x - x3) - self.y) % p
            return self.__class__(x3, y3, self.a, self.b)

        # Case 3: self.x == other.x
        else:
            print('self.x == other.x')
            # Formula (x3, y3) = (x1, y1) + (x1, y1)
            print('self.x:', hex(self.x))
            print('self.y:', hex(self.y))
            print('self.a:', hex(self.a))
            print('p:', hex(p))
            s = (3 * self.x ** 2 + self.a) * pow(2 * self.y, -1, p)
            print('s:', hex(s))
            x3 = (s ** 2 - 2 * self.x) % p
            y3 = (s * (self.x - x3) - self.y) % p
            return self.__class__(x3, y3, self.a, self.b)

    # Point multiplication
    def __rmul__(self, coefficient):
        debug_counter = 0
        coef = coefficient
        current = self
        result = self.__class__(None, None, self.a, self.b)  # point at infinity
        print('coef hex:', hex(coef))
        while coef:
            print('0 x:', hex(current.x))
            print('0 y:', hex(current.y))
            if coef & 1:  # if coef is odd
                result += current
                print('1 x:', hex(result.x))
                print('1 y:', hex(result.y))
            # Double current point
            current += current
            print('2 x:', hex(current.x))
            print('2 y:', hex(current.y))

            # Halve coef and continue
            coef >>= 1

            debug_counter += 1
            if debug_counter > 0:
                print('3 x:', hex(result.x))
                print('3 y:', hex(result.y))

            exit()
        
        print('3 x:', hex(result.x))
        print('3 y:', hex(result.y))

        return result

# Initialize G
G = Point(Gx, Gy, a, b)

# Function to derive public key from a private key
def derive_public_key(private_key):
    return private_key * G

# Function to compress a public key
def compress_public_key(public_key):
    prefix = '02' if public_key.y % 2 == 0 else '03'
    return prefix + hex(public_key.x)[2:].zfill(64)


# Test with a sample private key (hex format)
private_key_hex = "2e09165b257a4c3e52c9f4faa6322c66cede807b7d6b4ec3960820795ee5447f"
private_key = int(private_key_hex, 16)

print("Private Key (hex):", private_key_hex)

# Derive public key
public_key = derive_public_key(private_key)

# Print public key coordinates in hexadecimal format
print(f"Public Key (x, y) in hex: ({hex(public_key.x)}, {hex(public_key.y)})")

# Compress the derived public key

compressed_public_key = compress_public_key(public_key)
print('compressed_public_key:', compressed_public_key)
