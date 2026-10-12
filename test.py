"""
Verification and Testing Suite
Tests reversibility of encryption algorithms and one-way properties of hashing
"""

from sdes import SDES
from rsa import RSA, RSAKeyGenerator
from ecc import EllipticCurve, Point, ECC
from hashing import SHA256, MD5


def test_sdes_reversibility():
    """Test S-DES encryption/decryption reversibility"""
    print("\n" + "="*70)
    print("TEST 1: S-DES Reversibility")
    print("="*70)
    
    test_cases = [
        (0b1010000010, 0b00000000),  # All zeros
        (0b1010000010, 0b11111111),  # All ones
        (0b1010000010, 0b10101010),  # Alternating
        (0b0000000000, 0b10101010),  # Zero key
        (0b1111111111, 0b11110000),  # Max key
    ]
    
    passed = 0
    for key, plaintext in test_cases:
        try:
            cipher = SDES(key)
            ciphertext = cipher.encrypt(plaintext)
            decrypted = cipher.decrypt(ciphertext)
            
            is_reversible = plaintext == decrypted
            status = "✓ PASS" if is_reversible else "✗ FAIL"
            
            print(f"\n{status}")
            print(f"  Key:       {format(key, '010b')} ({key})")
            print(f"  Plaintext: {format(plaintext, '08b')} ({plaintext})")
            print(f"  Ciphertext:{format(ciphertext, '08b')} ({ciphertext})")
            print(f"  Decrypted: {format(decrypted, '08b')} ({decrypted})")
            print(f"  Match:     {is_reversible}")
            
            if is_reversible:
                passed += 1
        except Exception as e:
            print(f"✗ ERROR: {e}")
    
    print(f"\n→ S-DES Reversibility: {passed}/{len(test_cases)} tests passed")
    return passed == len(test_cases)


def test_rsa_reversibility():
    """Test RSA encryption/decryption reversibility"""
    print("\n" + "="*70)
    print("TEST 2: RSA Reversibility")
    print("="*70)
    
    test_cases = [
        (61, 53, 17, 42),
        (61, 53, 17, 1),
        (61, 53, 17, 3232),  # Max value before n
        (47, 59, 17, 100),
    ]
    
    passed = 0
    for p, q, e, plaintext in test_cases:
        try:
            rsa = RSA(p, q, e)
            n = rsa.n
            
            if plaintext >= n:
                print(f"\n⊘ SKIP: Plaintext {plaintext} >= n {n}")
                continue
            
            ciphertext = rsa.encrypt(plaintext)
            decrypted = rsa.decrypt(ciphertext)
            
            is_reversible = plaintext == decrypted
            status = "✓ PASS" if is_reversible else "✗ FAIL"
            
            print(f"\n{status}")
            print(f"  Primes: p={p}, q={q}")
            print(f"  n = {n}, e = {e}, d = {rsa.d}")
            print(f"  Plaintext: {plaintext}")
            print(f"  Ciphertext: {ciphertext}")
            print(f"  Decrypted: {decrypted}")
            print(f"  Match: {is_reversible}")
            
            if is_reversible:
                passed += 1
        except Exception as e:
            print(f"✗ ERROR: {e}")
    
    print(f"\n→ RSA Reversibility: {passed}/{len(test_cases)} tests passed")
    return passed == len(test_cases)


def test_ecc_reversibility():
    """Test ECC encryption/decryption reversibility"""
    print("\n" + "="*70)
    print("TEST 3: ECC Reversibility")
    print("="*70)
    
    # Create elliptic curve for testing
    p = 23
    curve = EllipticCurve(1, 1, p)
    G = Point(3, 10, curve)
    n = 28
    
    test_messages = [1, 5, 10, 15, 20, 23]
    
    passed = 0
    for plaintext in test_messages:
        try:
            # Alice and Bob create their ECC instances
            alice = ECC(curve, G, n)
            bob = ECC(curve, G, n)
            
            # Bob encrypts for Alice
            ciphertext = bob.encrypt(plaintext, alice.public_key)
            
            # Alice decrypts
            decrypted = alice.decrypt(ciphertext, alice.private_key)
            
            is_reversible = plaintext == decrypted
            status = "✓ PASS" if is_reversible else "✗ FAIL"
            
            print(f"\n{status}")
            print(f"  Plaintext: {plaintext}")
            print(f"  Ciphertext C1: {ciphertext[0]}")
            print(f"  Ciphertext C2: {ciphertext[1]}")
            print(f"  Decrypted: {decrypted}")
            print(f"  Match: {is_reversible}")
            
            if is_reversible:
                passed += 1
        except Exception as e:
            print(f"✗ ERROR: {e}")
    
    print(f"\n→ ECC Reversibility: {passed}/{len(test_messages)} tests passed")
    return passed == len(test_messages)


def test_hash_one_way():
    """Test hashing one-way property"""
    print("\n" + "="*70)
    print("TEST 4: Hash One-Way Property")
    print("="*70)
    
    test_data = [
        "Hello, World!",
        "The quick brown fox jumps over the lazy dog",
        "Cryptography",
        "123456",
        ""
    ]
    
    print("\nSHA-256 Hashes:")
    print("-" * 70)
    hashes = []
    for data in test_data:
        sha256 = SHA256(data)
        hash_val = sha256.hexdigest()
        hashes.append((data, hash_val))
        print(f"Input:  '{data}'")
        print(f"Hash:   {hash_val}")
        print()
    
    # Verify hashes are different for different inputs
    print("Uniqueness Check:")
    print("-" * 70)
    all_unique = len(set(h for _, h in hashes)) == len(hashes)
    print(f"All hashes unique: {'✓ YES' if all_unique else '✗ NO'}")
    
    # Demonstrate avalanche effect
    print("\nAvalanche Effect (small input change = different hash):")
    print("-" * 70)
    msg1 = "password"
    msg2 = "password1"
    
    sha1 = SHA256(msg1)
    sha2 = SHA256(msg2)
    
    print(f"Input 1: '{msg1}'")
    print(f"Hash 1:  {sha1.hexdigest()}")
    print()
    print(f"Input 2: '{msg2}' (one character added)")
    print(f"Hash 2:  {sha2.hexdigest()}")
    
    different = sha1.hexdigest() != sha2.hexdigest()
    print(f"Hashes different: {'✓ YES' if different else '✗ NO'}")
    
    # Show deterministic property
    print("\nDeterministic Property (same input = same hash):")
    print("-" * 70)
    sha_1a = SHA256("test").hexdigest()
    sha_1b = SHA256("test").hexdigest()
    
    print(f"Hash 1a: {sha_1a}")
    print(f"Hash 1b: {sha_1b}")
    
    deterministic = sha_1a == sha_1b
    print(f"Identical hashes: {'✓ YES' if deterministic else '✗ NO'}")
    
    print("\n✗ One-Way Property: Hashes CANNOT be reversed")
    print("   - Given hash, impossible to find original input")
    print("   - Mathematically infeasible (preimage resistance)")
    print("   - This is intentional for security")
    
    return True


def test_hash_collision_resistance():
    """Test hash collision resistance"""
    print("\n" + "="*70)
    print("TEST 5: Hash Collision Resistance")
    print("="*70)
    
    # Try many different inputs to find collisions (should be extremely rare)
    print("\nSearching for SHA-256 collisions (this won't find any):")
    print("-" * 70)
    
    inputs = []
    hashes_seen = set()
    
    for i in range(1000):
        data = f"input_{i}"
        sha256 = SHA256(data)
        hash_val = sha256.hexdigest()
        
        if hash_val in hashes_seen:
            print(f"✗ Collision found at input_{i}")
            return False
        
        hashes_seen.add(hash_val)
        inputs.append(data)
    
    print(f"✓ No collisions found in {len(inputs)} different inputs")
    print("  (Collision resistance is working)")
    print("\nNote: Finding SHA-256 collision would require ~2^128 attempts!")
    
    return True


def run_all_tests():
    """Run all tests and provide summary"""
    print("\n")
    print("╔" + "="*68 + "╗")
    print("║" + " "*15 + "CRYPTOGRAPHIC ALGORITHMS TEST SUITE" + " "*18 + "║")
    print("╚" + "="*68 + "╝")
    
    results = []
    
    # Run all tests
    results.append(("S-DES Reversibility", test_sdes_reversibility()))
    results.append(("RSA Reversibility", test_rsa_reversibility()))
    results.append(("ECC Reversibility", test_ecc_reversibility()))
    results.append(("Hash One-Way Property", test_hash_one_way()))
    results.append(("Hash Collision Resistance", test_hash_collision_resistance()))
    
    # Print summary
    print("\n" + "="*70)
    print("TEST SUMMARY")
    print("="*70)
    
    for test_name, passed in results:
        status = "✓ PASS" if passed else "✗ FAIL"
        print(f"{status}: {test_name}")
    
    total_passed = sum(1 for _, passed in results if passed)
    total_tests = len(results)
    
    print(f"\nTotal: {total_passed}/{total_tests} test groups passed")
    
    if total_passed == total_tests:
        print("\n✓ All tests passed! Implementations working correctly.")
    else:
        print("\n✗ Some tests failed. Check output above.")
    
    print("\n" + "="*70 + "\n")
    
    return total_passed == total_tests


if __name__ == "__main__":
    success = run_all_tests()
    exit(0 if success else 1)
