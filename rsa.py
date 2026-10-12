"""
RSA (Rivest–Shamir–Adleman) Encryption Implementation
- Asymmetric encryption algorithm
- Uses public key for encryption, private key for decryption
- Reversible: encryption and decryption both supported
- Educational implementation with key generation from prime numbers
"""

from math import gcd
from random import randint


class RSA:
    """RSA Encryption/Decryption"""
    
    def __init__(self, p=None, q=None, e=None):
        """
        Initialize RSA with prime numbers
        
        Args:
            p: First prime number (default: 61)
            q: Second prime number (default: 53)
            e: Public exponent (default: 17, must be coprime with φ(n))
        """
        self.p = p or 61
        self.q = q or 53
        self.e = e or 17
        
        # Calculate n = p * q
        self.n = self.p * self.q
        
        # Calculate φ(n) = (p-1) * (q-1)
        phi_n = (self.p - 1) * (self.q - 1)
        
        # Verify e is valid
        if gcd(self.e, phi_n) != 1:
            raise ValueError("e must be coprime with φ(n)")
        
        # Calculate d (private exponent)
        self.d = self._mod_inverse(self.e, phi_n)
        
        # Public key: (e, n)
        # Private key: (d, n)
    
    def _mod_inverse(self, a, m):
        """Calculate modular multiplicative inverse using Extended Euclidean Algorithm"""
        if gcd(a, m) != 1:
            raise ValueError("Modular inverse does not exist")
        
        # Extended Euclidean Algorithm
        def extended_gcd(a, b):
            if a == 0:
                return b, 0, 1
            gcd_val, x1, y1 = extended_gcd(b % a, a)
            x = y1 - (b // a) * x1
            y = x1
            return gcd_val, x, y
        
        _, x, _ = extended_gcd(a % m, m)
        return (x % m + m) % m
    
    def encrypt(self, plaintext):
        """
        Encrypt plaintext using public key (e, n)
        
        Args:
            plaintext: Integer to encrypt (must be < n)
        
        Returns:
            Ciphertext: encrypted integer
        """
        if plaintext >= self.n or plaintext < 0:
            raise ValueError(f"Plaintext must be between 0 and {self.n - 1}")
        
        # Ciphertext = plaintext^e mod n
        ciphertext = pow(plaintext, self.e, self.n)
        return ciphertext
    
    def decrypt(self, ciphertext):
        """
        Decrypt ciphertext using private key (d, n)
        
        Args:
            ciphertext: Integer to decrypt
        
        Returns:
            Plaintext: decrypted integer
        """
        if ciphertext >= self.n or ciphertext < 0:
            raise ValueError(f"Ciphertext must be between 0 and {self.n - 1}")
        
        # Plaintext = ciphertext^d mod n
        plaintext = pow(ciphertext, self.d, self.n)
        return plaintext
    
    def get_public_key(self):
        """Return public key (e, n)"""
        return (self.e, self.n)
    
    def get_private_key(self):
        """Return private key (d, n)"""
        return (self.d, self.n)
    
    def get_key_info(self):
        """Return detailed key information"""
        return {
            'p': self.p,
            'q': self.q,
            'n': self.n,
            'phi_n': (self.p - 1) * (self.q - 1),
            'e': self.e,
            'd': self.d,
            'public_key': (self.e, self.n),
            'private_key': (self.d, self.n)
        }


class RSAKeyGenerator:
    """Generate RSA keys from scratch"""
    
    @staticmethod
    def is_prime(n, k=5):
        """Miller-Rabin primality test"""
        if n < 2:
            return False
        if n == 2 or n == 3:
            return True
        if n % 2 == 0:
            return False
        
        # Write n-1 as 2^r * d
        r, d = 0, n - 1
        while d % 2 == 0:
            r += 1
            d //= 2
        
        # Witness loop
        for _ in range(k):
            a = randint(2, n - 2)
            x = pow(a, d, n)
            
            if x == 1 or x == n - 1:
                continue
            
            for _ in range(r - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False
        
        return True
    
    @staticmethod
    def get_prime(bits=16):
        """Generate a random prime number with specified bits"""
        while True:
            num = randint(2 ** (bits - 1), 2 ** bits - 1)
            if RSAKeyGenerator.is_prime(num):
                return num
    
    @staticmethod
    def generate_rsa_keys(p_bits=16, q_bits=16, e=65537):
        """
        Generate RSA key pair
        
        Args:
            p_bits: Bit length of prime p
            q_bits: Bit length of prime q
            e: Public exponent (default: 65537)
        
        Returns:
            RSA object with generated keys
        """
        p = RSAKeyGenerator.get_prime(p_bits)
        q = RSAKeyGenerator.get_prime(q_bits)
        
        # Ensure p != q
        while p == q:
            q = RSAKeyGenerator.get_prime(q_bits)
        
        return RSA(p, q, e)


# Example usage
if __name__ == "__main__":
    print("RSA Implementation\n")
    
    # Create RSA instance with small primes (for demonstration)
    rsa = RSA(p=61, q=53, e=17)
    
    print(f"Key Generation:")
    key_info = rsa.get_key_info()
    print(f"  Prime p: {key_info['p']}")
    print(f"  Prime q: {key_info['q']}")
    print(f"  n = p*q: {key_info['n']}")
    print(f"  φ(n): {key_info['phi_n']}")
    print(f"  Public exponent e: {key_info['e']}")
    print(f"  Private exponent d: {key_info['d']}")
    
    print(f"\nPublic Key (e, n): {key_info['public_key']}")
    print(f"Private Key (d, n): {key_info['private_key']}")
    
    # Encrypt
    plaintext = 42
    ciphertext = rsa.encrypt(plaintext)
    print(f"\nEncryption:")
    print(f"  Plaintext: {plaintext}")
    print(f"  Ciphertext: {ciphertext}")
    
    # Decrypt
    decrypted = rsa.decrypt(ciphertext)
    print(f"\nDecryption:")
    print(f"  Ciphertext: {ciphertext}")
    print(f"  Decrypted: {decrypted}")
    
    print(f"\nReversibility check: {plaintext == decrypted} ✓" if plaintext == decrypted else f"\nReversibility check: FAILED ✗")
