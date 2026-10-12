# Cryptographic Algorithms Implementation

A comprehensive educational implementation of symmetric encryption (S-DES), asymmetric encryption (RSA, ECC), and hashing algorithms demonstrating encryption/decryption reversibility and hash functions' one-way properties.

## Project Structure

```
Encryption_Algs/
├── sdes.py              # Simple DES Implementation (Symmetric)
├── rsa.py               # RSA Implementation (Asymmetric)
├── ecc.py               # Elliptic Curve Cryptography (Asymmetric)
├── hashing.py           # SHA-256, MD5, Simple Hash
├── main.py              # Comprehensive Demo & Comparison
├── README.md            # This file
└── requirements.txt     # Python dependencies (none - pure Python)
```

## Algorithms Overview

### 1. S-DES (Simple Data Encryption Standard) - SYMMETRIC

**Type:** Symmetric Encryption  
**Reversible:** ✓ YES

#### Features:
- **Key Size:** 10 bits
- **Block Size:** 8 bits
- **Process:** Uses same key for encryption and decryption
- **Forward:** Plaintext → Ciphertext (encryption)
- **Backward:** Ciphertext → Plaintext (decryption)

#### Key Components:
- Initial Permutation (IP)
- 2 Rounds of Feistel function
- S-box substitution
- Subkey generation

#### Usage:
```python
from sdes import SDES

# Create cipher with 10-bit key
key = 0b1010000010  # 10 bits
cipher = SDES(key)

# Encrypt 8-bit plaintext
plaintext = 0b10101010  # 8 bits
ciphertext = cipher.encrypt(plaintext)

# Decrypt
decrypted = cipher.decrypt(ciphertext)
assert plaintext == decrypted  # ✓ Reversible
```

---

### 2. RSA (Rivest–Shamir–Adleman) - ASYMMETRIC

**Type:** Asymmetric Encryption  
**Reversible:** ✓ YES

#### Features:
- **Key Pair:** Public key (e, n) & Private key (d, n)
- **Security:** Based on difficulty of factoring large primes
- **Forward:** Plaintext → Ciphertext (public key encryption)
- **Backward:** Ciphertext → Plaintext (private key decryption)

#### Key Generation:
1. Select two large prime numbers p and q
2. Calculate n = p × q
3. Calculate φ(n) = (p-1) × (q-1)
4. Choose e coprime with φ(n)
5. Calculate d ≡ e⁻¹ (mod φ(n))

#### Usage:
```python
from rsa import RSA

# Create RSA with primes p=61, q=53, e=17
rsa = RSA(p=61, q=53, e=17)

# Encryption (public key: e=17, n=3233)
plaintext = 42
ciphertext = rsa.encrypt(plaintext)

# Decryption (private key: d=2753, n=3233)
decrypted = rsa.decrypt(ciphertext)
assert plaintext == decrypted  # ✓ Reversible
```

#### Mathematical Operations:
- Encryption: C ≡ P^e (mod n)
- Decryption: P ≡ C^d (mod n)

---

### 3. ECC (Elliptic Curve Cryptography) - ASYMMETRIC

**Type:** Asymmetric Encryption (Elliptic Curve)  
**Reversible:** ✓ YES

#### Features:
- **Curve:** y² = x³ + ax + b (mod p)
- **Scheme:** ECIES (Elliptic Curve Integrated Encryption Scheme)
- **Efficiency:** Smaller key sizes than RSA for equivalent security
- **Forward:** Plaintext → Ciphertext (using ephemeral key pair)
- **Backward:** Ciphertext → Plaintext (using private key)

#### Key Components:
1. **Elliptic Curve:** Defined by equation y² = x³ + ax + b (mod p)
2. **Generator Point G:** Base point with order n
3. **Private Key d:** Random integer [1, n-1]
4. **Public Key Q:** Q = d × G

#### ECIES Process:
```
Encryption:
  1. Generate ephemeral key pair (k, C1=k×G)
  2. Calculate shared secret S = k × Public_Key
  3. Derive encryption key from S.x
  4. C2 = Plaintext XOR encryption_key
  5. Send (C1, C2)

Decryption:
  1. Receive (C1, C2)
  2. Calculate shared secret S = private_key × C1
  3. Derive encryption key from S.x
  4. Plaintext = C2 XOR decryption_key
```

#### Usage:
```python
from ecc import EllipticCurve, Point, ECC

# Create elliptic curve
curve = EllipticCurve(a=1, b=1, p=23)
G = Point(3, 10, curve)
n = 28  # Order

# Alice's ECC
alice = ECC(curve, G, n)

# Bob encrypts for Alice
plaintext = 15
C1, C2 = bob.encrypt(plaintext, alice.public_key)

# Alice decrypts
decrypted = alice.decrypt((C1, C2), alice.private_key)
assert plaintext == decrypted  # ✓ Reversible
```

---

### 4. HASHING (One-Way Functions) - NOT REVERSIBLE

**Type:** Cryptographic Hash Functions  
**Reversible:** ✗ NO

#### Implementations:

##### SHA-256 (Secure Hash Algorithm 256-bit)
- **Output:** 256 bits (32 bytes)
- **Security:** Still secure (as of 2024)
- **Applications:** Blockchain, digital signatures, password hashing

##### MD5 (Message-Digest Algorithm 5)
- **Output:** 128 bits (16 bytes)
- **Security:** DEPRECATED - cryptographically broken
- **Status:** Legacy only - DO NOT USE FOR SECURITY

#### Properties of Hash Functions:
1. **Deterministic:** Same input → Same output
2. **One-Way:** Computationally infeasible to reverse
3. **Pre-image Resistance:** Given hash H, can't find input M
4. **Collision Resistance:** Hard to find M1 ≠ M2 where Hash(M1) = Hash(M2)
5. **Avalanche Effect:** Small input change = completely different hash

#### Usage:
```python
from hashing import SHA256, MD5

# SHA-256 (recommended)
sha256 = SHA256("Hello, World!")
print(sha256.hexdigest())
# Output: dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f

# MD5 (deprecated - for reference only)
md5 = MD5("Hello, World!")
print(md5.hexdigest())
# Output: 65a8e27d8d55e25c3d666491b6fac4b9
```

#### Why Hashing is NOT Reversible:
1. **Information Loss:** Fixed-size output from variable-size input
2. **No Inverse:** Mathematical property - no inverse function exists
3. **Computational Infeasibility:** Would require billions of years to reverse
4. **Intentional Design:** One-way property is required for security

---

## Algorithm Comparison Table

| Algorithm | Type | Forward Process | Backward Process | Reversible? | Key Type | Output |
|-----------|------|-----------------|------------------|-------------|----------|---------|
| S-DES | Symmetric | Encrypt plaintext | Decrypt ciphertext | **YES** | Shared (10-bit) | 8-bit block |
| RSA | Asymmetric | Encrypt (public key) | Decrypt (private key) | **YES** | Pub/Priv | Variable |
| ECC | Asymmetric | Encrypt (ECIES) | Decrypt (private key) | **YES** | Pub/Priv | Variable |
| SHA-256 | One-Way Hash | Data → Hash | IMPOSSIBLE | **NO** | N/A | 256-bit |
| MD5 | One-Way Hash | Data → Hash | IMPOSSIBLE | **NO** | N/A | 128-bit |

---

## Running the Program

### Run All Demonstrations:
```bash
python main.py
```

This will display:
- S-DES encryption/decryption with reversibility check
- RSA key generation and encryption/decryption
- ECC key exchange and encryption/decryption
- Hash function outputs and properties
- Comprehensive algorithm comparison

### Run Individual Algorithms:
```bash
# S-DES
python sdes.py

# RSA
python rsa.py

# ECC
python ecc.py

# Hashing
python hashing.py
```

---

## Key Concepts

### Reversible Encryption
- **Symmetric (S-DES):** Same key for encryption and decryption
  - Advantage: Fast and simple
  - Disadvantage: Key distribution problem
  
- **Asymmetric (RSA, ECC):** Different keys for encryption and decryption
  - Public key: Known to everyone, used for encryption
  - Private key: Secret, used for decryption
  - Advantage: Solves key distribution problem
  - Disadvantage: Slower than symmetric

### One-Way Functions (Hashing)
- **Purpose:** Data integrity, authentication, password storage
- **Property:** Easy to compute forward, impossible to reverse
- **Applications:**
  - Password hashing (store hash, not password)
  - Digital signatures (hash of document)
  - Blockchain (chain of hashes)
  - Verification (detect tampering)

---

## Security Properties

### For Encryption Algorithms:
- **Confidentiality:** Only intended recipient can read message
- **Authentication:** Receiver can verify sender's identity
- **Non-repudiation:** Sender cannot deny sending message

### For Hash Functions:
- **Integrity:** Detect if data has been modified
- **Authentication:** Verify data comes from authentic source
- **Non-repudiation:** Prove who created/signed data

---

## Mathematical Foundations

### S-DES:
- Feistel Network structure
- XOR operations for combining
- S-box substitution for confusion
- Permutations for diffusion

### RSA:
- Modular exponentiation
- Euler's theorem: a^φ(n) ≡ 1 (mod n)
- Extended Euclidean Algorithm for key generation

### ECC:
- Elliptic curve arithmetic over finite fields
- Point addition and scalar multiplication
- Discrete logarithm problem (hard to solve)

### Hashing:
- Bitwise operations (rotate, XOR, AND, OR)
- Modular arithmetic
- Cryptographic compression functions

---

## Educational Notes

This implementation prioritizes clarity over production-level security:

1. **S-DES:** Uses small blocks (8-bit) - for educational purposes only
2. **RSA:** Small key sizes (typically 16-bits) - demonstration only
3. **ECC:** Small curve parameters - demonstration only
4. **Hashing:** Educational implementations of SHA-256 and MD5

**For real-world use:**
- Use TLS/SSL for encryption
- Use bcrypt/Argon2 for password hashing
- Use ECDSA/RSA 2048+ for digital signatures
- Use SHA-256 or SHA-3 for hashing

---

## References

1. **S-DES:** 
   - Edward Schaefer, "A Simplified DES Algorithm"
   - Educational resource for teaching cryptography

2. **RSA:**
   - Rivest, R., Shamir, A., & Adleman, L. (1978)
   - RFC 3447: PKCS #1: RSA Cryptography Specifications

3. **ECC:**
   - FIPS 186-4: Digital Signature Standard (DSS)
   - SEC 2: Recommended Elliptic Curve Domain Parameters

4. **Hashing:**
   - FIPS 180-4: Secure Hash Standard (SHS)
   - RFC 1321: The MD5 Message-Digest Algorithm

---

## Author

ICS341 - Cryptography Course Assignment  
Winston Project - Encryption Algorithms

---

## License

Educational Use Only

---

## Summary

This project demonstrates four fundamental cryptographic algorithms:

✓ **Reversible Algorithms:**
- S-DES: Simple symmetric encryption
- RSA: Public-key encryption
- ECC: Elliptic curve encryption

✗ **One-Way Functions:**
- Hashing: SHA-256, MD5, and educational implementations

All reversible algorithms include both encryption and decryption implementations to verify the mathematical property of reversibility. Hash functions intentionally lack reversibility as a security feature.
