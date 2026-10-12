"""
Elliptic Curve Cryptography (ECC) Implementation
- Asymmetric encryption algorithm
- Uses elliptic curve math and public key for encryption
- Uses corresponding private key for decryption
- Reversible: encryption and decryption both supported
- Based on ECDH and ECIES (Elliptic Curve Integrated Encryption Scheme)
"""

from math import gcd
from random import randint


class Point:
    """Represents a point on an elliptic curve"""
    
    def __init__(self, x, y, curve):
        self.x = x
        self.y = y
        self.curve = curve
    
    def __add__(self, other):
        """Add two points on the elliptic curve"""
        if not isinstance(other, Point):
            raise TypeError("Can only add Point objects")
        
        if self.curve != other.curve:
            raise ValueError("Points must be on the same curve")
        
        # Point at infinity
        if self.x is None or other.x is None:
            if self.x is None:
                return other
            return self
        
        # If points have same x but different y
        if self.x == other.x:
            if self.y == -other.y % self.curve.p:
                return Point(None, None, self.curve)
            # Same point - point doubling
            return self._double()
        
        # Different x coordinates
        m = ((other.y - self.y) * pow(other.x - self.x, -1, self.curve.p)) % self.curve.p
        x3 = (m * m - self.x - other.x) % self.curve.p
        y3 = (m * (self.x - x3) - self.y) % self.curve.p
        
        return Point(x3, y3, self.curve)
    
    def _double(self):
        """Double a point on the elliptic curve"""
        if self.x is None:
            return self
        
        # m = (3x^2 + a) / (2y)
        m = ((3 * self.x * self.x + self.curve.a) * pow(2 * self.y, -1, self.curve.p)) % self.curve.p
        x3 = (m * m - 2 * self.x) % self.curve.p
        y3 = (m * (self.x - x3) - self.y) % self.curve.p
        
        return Point(x3, y3, self.curve)
    
    def __mul__(self, scalar):
        """Scalar multiplication using binary method (double-and-add)"""
        if not isinstance(scalar, int):
            raise TypeError("Scalar must be an integer")
        
        if scalar == 0:
            return Point(None, None, self.curve)
        
        if scalar < 0:
            raise ValueError("Scalar must be non-negative")
        
        result = Point(None, None, self.curve)  # Point at infinity
        addend = self
        
        while scalar:
            if scalar & 1:
                result = result + addend
            addend = addend._double()
            scalar >>= 1
        
        return result
    
    def __rmul__(self, scalar):
        """Scalar multiplication (reverse)"""
        return self.__mul__(scalar)
    
    def __eq__(self, other):
        if not isinstance(other, Point):
            return False
        return self.x == other.x and self.y == other.y and self.curve == other.curve
    
    def __repr__(self):
        if self.x is None:
            return "Point at infinity"
        return f"({self.x}, {self.y})"


class EllipticCurve:
    """Represents an elliptic curve: y^2 = x^3 + ax + b (mod p)"""
    
    def __init__(self, a, b, p):
        """
        Initialize elliptic curve
        
        Args:
            a, b: Coefficients of the curve equation
            p: Prime modulus
        """
        self.a = a
        self.b = b
        self.p = p
        
        # Verify discriminant (4a^3 + 27b^2 ≠ 0 mod p)
        discriminant = (4 * a * a * a + 27 * b * b) % p
        if discriminant == 0:
            raise ValueError("Invalid curve: discriminant must be non-zero")
    
    def __eq__(self, other):
        if not isinstance(other, EllipticCurve):
            return False
        return self.a == other.a and self.b == other.b and self.p == other.p
    
    def __repr__(self):
        return f"y^2 = x^3 + {self.a}x + {self.b} (mod {self.p})"


class ECC:
    """Elliptic Curve Cryptography using ECIES scheme"""
    
    def __init__(self, curve, G, n):
        """
        Initialize ECC
        
        Args:
            curve: EllipticCurve object
            G: Generator point
            n: Order of generator point (number of points in subgroup)
        """
        self.curve = curve
        self.G = G  # Generator point (public)
        self.n = n  # Order of subgroup
        
        # Generate random private key
        self.private_key = randint(1, n - 1)
        
        # Calculate public key
        self.public_key = self.private_key * self.G
    
    def set_private_key(self, d):
        """Set private key and calculate corresponding public key"""
        if not (0 < d < self.n):
            raise ValueError(f"Private key must be between 1 and {self.n - 1}")
        self.private_key = d
        self.public_key = d * self.G
    
    def encrypt(self, plaintext, public_key=None):
        """
        Encrypt plaintext using ECIES
        
        Args:
            plaintext: Integer to encrypt
            public_key: Public key point (uses recipient's public key)
        
        Returns:
            (C1, C2) tuple where:
                C1: Ephemeral public key point
                C2: Encrypted message
        """
        if public_key is None:
            public_key = self.public_key
        
        if not isinstance(plaintext, int) or plaintext < 0:
            raise ValueError("Plaintext must be non-negative integer")
        
        # Generate random ephemeral key
        k = randint(1, self.n - 1)
        
        # C1 = k * G (ephemeral public key)
        C1 = k * self.G
        
        # Shared secret = k * public_key
        shared_secret = k * public_key
        
        # Use x-coordinate of shared secret as encryption key
        if shared_secret.x is None:
            raise ValueError("Invalid shared secret")
        
        # Simple encryption: XOR plaintext with derived key
        encryption_key = shared_secret.x
        C2 = plaintext ^ encryption_key
        
        return (C1, C2)
    
    def decrypt(self, ciphertext_tuple, private_key=None):
        """
        Decrypt ciphertext using ECIES
        
        Args:
            ciphertext_tuple: (C1, C2) tuple from encryption
            private_key: Private key scalar (uses own private key if not provided)
        
        Returns:
            Plaintext: decrypted integer
        """
        if private_key is None:
            private_key = self.private_key
        
        C1, C2 = ciphertext_tuple
        
        # Shared secret = private_key * C1
        shared_secret = private_key * C1
        
        # Use x-coordinate of shared secret as decryption key
        if shared_secret.x is None:
            raise ValueError("Invalid shared secret")
        
        # Simple decryption: XOR encrypted message with derived key
        decryption_key = shared_secret.x
        plaintext = C2 ^ decryption_key
        
        return plaintext
    
    @staticmethod
    def create_secp192k1():
        """
        Create ECC using secp192k1 parameters (Bitcoin curve, simplified)
        """
        # Parameters for secp192k1 (simplified for smaller numbers)
        p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD
        a = 0
        b = 3
        
        curve = EllipticCurve(a, b, p)
        
        # Generator point G
        Gx = 0x188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012
        Gy = 0x07192B95FFC8DA78631011ED6B24CDD573F977A11E794811
        G = Point(Gx, Gy, curve)
        
        # Order of subgroup
        n = 0xFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831
        
        return ECC(curve, G, n)


# Example usage
if __name__ == "__main__":
    print("Elliptic Curve Cryptography (ECC) Implementation\n")
    
    # Create a simple elliptic curve for demonstration
    # Using small parameters for easy computation
    p = 23  # Prime modulus
    a = 1   # Curve parameter
    b = 1   # Curve parameter
    
    curve = EllipticCurve(a, b, p)
    print(f"Elliptic Curve: {curve}\n")
    
    # Find points on the curve (generator point)
    # For y^2 = x^3 + x + 1 (mod 23)
    G = Point(3, 10, curve)
    n = 28  # Order of the generator
    
    print(f"Generator Point G: {G}")
    print(f"Order n: {n}\n")
    
    # Alice's ECC
    alice = ECC(curve, G, n)
    print(f"Alice's private key: {alice.private_key}")
    print(f"Alice's public key: {alice.public_key}")
    
    # Bob's ECC
    bob = ECC(curve, G, n)
    print(f"\nBob's private key: {bob.private_key}")
    print(f"Bob's public key: {bob.public_key}")
    
    # Bob encrypts a message for Alice
    plaintext = 15
    ciphertext = bob.encrypt(plaintext, alice.public_key)
    print(f"\nBob encrypts message: {plaintext}")
    print(f"  C1 (ephemeral public key): {ciphertext[0]}")
    print(f"  C2 (encrypted message): {ciphertext[1]}")
    
    # Alice decrypts
    decrypted = alice.decrypt(ciphertext, alice.private_key)
    print(f"\nAlice decrypts and gets: {decrypted}")
    
    print(f"\nReversibility check: {plaintext == decrypted} ✓" if plaintext == decrypted else f"\nReversibility check: FAILED ✗")
