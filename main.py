"""
Comprehensive Cryptographic Algorithms Demo
Demonstrates S-DES, RSA, ECC, and Hashing algorithms
Shows encryption/decryption reversibility and hash one-way properties
"""

from sdes import SDES
from rsa import RSA
from ecc import EllipticCurve, Point, ECC
from hashing import SHA256, MD5, SimpleHash


def print_section(title):
    """Print a formatted section header"""
    print("\n" + "=" * 80)
    print(f" {title}")
    print("=" * 80)


def print_subsection(title):
    """Print a formatted subsection header"""
    print(f"\n{title}")
    print("-" * 80)


def demo_sdes():
    """Demonstrate S-DES encryption and decryption"""
    print_section("1. S-DES (Symmetric Encryption) - REVERSIBLE")
    
    # Key and plaintext setup
    key = 0b1010000010  # 10-bit key
    plaintext = 0b10101010  # 8-bit plaintext
    
    print_subsection("S-DES Configuration:")
    print(f"  Algorithm Type:    Symmetric Encryption")
    print(f"  Key Length:        10 bits")
    print(f"  Block Size:        8 bits")
    print(f"  Reversible:        YES (encryption ⇔ decryption)")
    
    print_subsection("Encryption Process:")
    print(f"  Shared Key:        {format(key, '010b')} (binary) = {key} (decimal)")
    print(f"  Plaintext:         {format(plaintext, '08b')} (binary) = {plaintext} (decimal)")
    
    # Encrypt
    cipher = SDES(key)
    ciphertext = cipher.encrypt(plaintext)
    print(f"  Ciphertext:        {format(ciphertext, '08b')} (binary) = {ciphertext} (decimal)")
    
    print_subsection("Decryption Process (Reversibility Check):")
    decrypted = cipher.decrypt(ciphertext)
    print(f"  Ciphertext:        {format(ciphertext, '08b')} (binary)")
    print(f"  Decrypted Text:    {format(decrypted, '08b')} (binary) = {decrypted} (decimal)")
    print(f"  ✓ REVERSIBLE:      {plaintext == decrypted} (Plaintext == Decrypted: {plaintext == decrypted})")


def demo_rsa():
    """Demonstrate RSA encryption and decryption"""
    print_section("2. RSA (Asymmetric Encryption) - REVERSIBLE")
    
    print_subsection("RSA Configuration:")
    print(f"  Algorithm Type:    Asymmetric Encryption")
    print(f"  Key Type:          Public/Private Key Pair")
    print(f"  Reversible:        YES (encryption ⇔ decryption)")
    
    # Create RSA instance
    rsa = RSA(p=61, q=53, e=17)
    key_info = rsa.get_key_info()
    
    print_subsection("Key Generation:")
    print(f"  Prime p:           {key_info['p']}")
    print(f"  Prime q:           {key_info['q']}")
    print(f"  n = p × q:         {key_info['n']}")
    print(f"  φ(n):              {key_info['phi_n']}")
    print(f"  Public exponent e: {key_info['e']}")
    print(f"  Private exponent d:{key_info['d']}")
    
    print_subsection("Public and Private Keys:")
    print(f"  Public Key (e, n): ({key_info['e']}, {key_info['n']})")
    print(f"  Private Key (d, n):({key_info['d']}, {key_info['n']})")
    
    print_subsection("Encryption Process (Using Public Key):")
    plaintext = 42
    ciphertext = rsa.encrypt(plaintext)
    print(f"  Plaintext:         {plaintext}")
    print(f"  Encryption:        plaintext^e mod n = {plaintext}^{key_info['e']} mod {key_info['n']}")
    print(f"  Ciphertext:        {ciphertext}")
    
    print_subsection("Decryption Process (Using Private Key - Reversibility Check):")
    decrypted = rsa.decrypt(ciphertext)
    print(f"  Ciphertext:        {ciphertext}")
    print(f"  Decryption:        ciphertext^d mod n = {ciphertext}^{key_info['d']} mod {key_info['n']}")
    print(f"  Plaintext:         {decrypted}")
    print(f"  ✓ REVERSIBLE:      {plaintext == decrypted} (Plaintext == Decrypted: {plaintext == decrypted})")


def demo_ecc():
    """Demonstrate ECC encryption and decryption"""
    print_section("3. ECC (Elliptic Curve Cryptography) - REVERSIBLE")
    
    print_subsection("ECC Configuration:")
    print(f"  Algorithm Type:    Asymmetric Encryption (Elliptic Curve)")
    print(f"  Curve Equation:    y² = x³ + ax + b (mod p)")
    print(f"  Scheme:            ECIES (Elliptic Curve Integrated Encryption Scheme)")
    print(f"  Reversible:        YES (encryption ⇔ decryption)")
    
    # Create simple elliptic curve
    p = 23  # Prime modulus
    a = 1   # Curve parameter
    b = 1   # Curve parameter
    
    curve = EllipticCurve(a, b, p)
    G = Point(3, 10, curve)  # Generator point
    n = 28  # Order of generator
    
    print_subsection("Curve Parameters:")
    print(f"  Prime p:           {p}")
    print(f"  Curve Parameters:  a={a}, b={b}")
    print(f"  Curve Equation:    y² = x³ + {a}x + {b} (mod {p})")
    print(f"  Generator Point G: {G}")
    print(f"  Order n:           {n}")
    
    # Create Alice's and Bob's ECC instances
    alice = ECC(curve, G, n)
    bob = ECC(curve, G, n)
    
    print_subsection("Key Pairs:")
    print(f"  Alice's Private Key: {alice.private_key}")
    print(f"  Alice's Public Key:  {alice.public_key}")
    print(f"  Bob's Private Key:   {bob.private_key}")
    print(f"  Bob's Public Key:    {bob.public_key}")
    
    print_subsection("Encryption Process (Bob encrypts for Alice):")
    plaintext = 15
    ciphertext = bob.encrypt(plaintext, alice.public_key)
    C1, C2 = ciphertext
    print(f"  Plaintext Message:   {plaintext}")
    print(f"  C1 (Ephemeral PK):   {C1}")
    print(f"  C2 (Encrypted Msg):  {C2}")
    
    print_subsection("Decryption Process (Alice decrypts - Reversibility Check):")
    decrypted = alice.decrypt(ciphertext, alice.private_key)
    print(f"  C1 (Ephemeral PK):   {C1}")
    print(f"  C2 (Encrypted Msg):  {C2}")
    print(f"  Decrypted Message:   {decrypted}")
    print(f"  ✓ REVERSIBLE:        {plaintext == decrypted} (Plaintext == Decrypted: {plaintext == decrypted})")


def demo_hashing():
    """Demonstrate hashing algorithms"""
    print_section("4. HASHING (One-Way Functions) - NOT REVERSIBLE")
    
    print_subsection("Hashing Configuration:")
    print(f"  Algorithm Type:    One-Way Hash Function")
    print(f"  Output Format:     Fixed-size digest")
    print(f"  Reversible:        NO (hash is NOT reversible)")
    print(f"  Property:          Preimage resistance (mathematically infeasible to reverse)")
    
    test_data = [
        ("Hello, World!", "Greeting"),
        ("The quick brown fox", "Phrase"),
        ("12345", "Number"),
        ("", "Empty string")
    ]
    
    print_subsection("SHA-256 Hash Examples (256-bit output):")
    for data, description in test_data:
        sha256 = SHA256(data)
        print(f"  Input ({description:15}): '{data}'")
        print(f"  SHA-256:                  {sha256.hexdigest()}")
        print()
    
    print_subsection("MD5 Hash Examples (128-bit output - deprecated):")
    for data, description in test_data[:2]:  # Show just first two
        md5 = MD5(data)
        print(f"  Input ({description:15}): '{data}'")
        print(f"  MD5:                      {md5.hexdigest()}")
        print()
    
    print_subsection("Important Properties of Hashing:")
    print(f"  1. Deterministic:         Same input always produces same hash")
    print(f"  2. One-Way:               Impossible to reverse hash to original input")
    print(f"  3. Pre-image Resistance:  Given hash H, infeasible to find input M")
    print(f"  4. Collision Resistance:  Hard to find two inputs with same hash")
    print(f"  5. Avalanche Effect:      Small input change = completely different hash")
    
    print_subsection("Avalanche Effect Demonstration:")
    msg1 = "password"
    msg2 = "password"  # One character different
    
    sha1 = SHA256(msg1)
    sha2 = SHA256(msg2)
    
    print(f"  Input 1: '{msg1}'")
    print(f"  Hash 1:  {sha1.hexdigest()}")
    print(f"  Input 2: '{msg2}'  (one character different)")
    print(f"  Hash 2:  {sha2.hexdigest()}")
    print(f"  → Completely different hashes despite similar inputs ✓")
    
    print_subsection("Why Hashing is NOT Reversible:")
    print(f"  • Loss of Information: Hash is fixed-size, input is variable")
    print(f"  • Mathematical Property: No inverse function exists")
    print(f"  • Practical Impossibility: Would require billions of years to reverse")
    print(f"  • Design Goal: Hashing is intentionally irreversible for security")


def demo_comparison():
    """Compare all algorithms"""
    print_section("5. ALGORITHM COMPARISON")
    
    print_subsection("Cryptographic Properties:")
    
    comparison_data = [
        ("S-DES", "Symmetric", "Yes", "Encryption/Decryption", "10-bit", "8-bit"),
        ("RSA", "Asymmetric", "Yes", "Encryption/Decryption", "Public/Private", "Variable"),
        ("ECC", "Asymmetric", "Yes", "Encryption/Decryption", "Public/Private", "Variable"),
        ("SHA-256", "One-Way Hash", "No", "Hash only", "N/A", "256-bit"),
        ("MD5", "One-Way Hash", "No", "Hash only", "N/A", "128-bit"),
    ]
    
    print(f"{'Algorithm':<12} {'Type':<15} {'Reversible?':<12} {'Use':<25} {'Key Type':<15} {'Output':<12}")
    print("-" * 95)
    
    for algo, algo_type, reversible, use, key_type, output in comparison_data:
        print(f"{algo:<12} {algo_type:<15} {reversible:<12} {use:<25} {key_type:<15} {output:<12}")
    
    print_subsection("Forward vs Backward Processes:")
    
    forward_backward = [
        ("S-DES", "Plaintext → Ciphertext (encryption)", "Ciphertext → Plaintext (decryption)"),
        ("RSA", "Plaintext → Ciphertext (pub key)", "Ciphertext → Plaintext (priv key)"),
        ("ECC", "Plaintext → Ciphertext (ECIES)", "Ciphertext → Plaintext (private key)"),
        ("Hashing", "Data → Hash (fixed-size digest)", "IMPOSSIBLE (one-way function)"),
    ]
    
    print(f"{'Algorithm':<12} {'Forward Process':<40} {'Backward Process':<40}")
    print("-" * 95)
    
    for algo, forward, backward in forward_backward:
        print(f"{algo:<12} {forward:<40} {backward:<40}")


def main():
    """Run all demonstrations"""
    print("\n")
    print("╔" + "=" * 78 + "╗")
    print("║" + " " * 15 + "CRYPTOGRAPHIC ALGORITHMS IMPLEMENTATION" + " " * 25 + "║")
    print("║" + " " * 12 + "S-DES | RSA | ECC | SHA-256 | MD5 | Hashing" + " " * 23 + "║")
    print("╚" + "=" * 78 + "╝")
    
    # Run all demonstrations
    demo_sdes()
    demo_rsa()
    demo_ecc()
    demo_hashing()
    demo_comparison()
    
    print_section("SUMMARY")
    print_subsection("Reversible Algorithms (Encryption):")
    print(f"  ✓ S-DES (Symmetric):      Plaintext ⇄ Ciphertext using shared key")
    print(f"  ✓ RSA (Asymmetric):       Plaintext ⇄ Ciphertext using pub/priv keys")
    print(f"  ✓ ECC (Asymmetric):       Plaintext ⇄ Ciphertext using elliptic curves")
    
    print_subsection("NOT Reversible (Hashing):")
    print(f"  ✗ Hashing:                Data → Hash (one-way function, mathematically irreversible)")
    
    print_subsection("Key Differences:")
    print(f"  • Symmetric vs Asymmetric: Symmetric uses one key, Asymmetric uses key pair")
    print(f"  • Encryption vs Hashing:   Encryption is reversible, Hashing is not")
    print(f"  • Security Properties:     Hash functions provide integrity, not confidentiality")
    
    print("\n" + "=" * 80 + "\n")


if __name__ == "__main__":
    main()
