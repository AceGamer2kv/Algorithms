"""
Hashing Algorithms Implementation
- One-way functions (NOT reversible)
- Convert input data into fixed-size string
- Mathematically infeasible to reverse due to pre-image resistance
- Implementations: SHA-256, MD5, SHA-1
"""

import struct


class HashAlgorithm:
    """Base class for hash algorithms"""
    
    def update(self, data):
        """Update hash with new data"""
        raise NotImplementedError
    
    def digest(self):
        """Return hash digest as bytes"""
        raise NotImplementedError
    
    def hexdigest(self):
        """Return hash digest as hexadecimal string"""
        return self.digest().hex()


class SHA256(HashAlgorithm):
    """SHA-256 (Secure Hash Algorithm 256-bit) Implementation"""
    
    # SHA-256 constants
    K = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
        0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
        0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
        0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
        0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ]
    
    # Initial hash values
    H = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    ]
    
    def __init__(self, data=b''):
        """Initialize SHA-256"""
        self.h = self.H[:]
        self.buffer = b''
        self.length = 0
        if data:
            self.update(data)
    
    def update(self, data):
        """Update hash with new data"""
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        self.buffer += data
        self.length += len(data)
    
    def digest(self):
        """Return SHA-256 hash digest"""
        h = self.h[:]
        buffer = self.buffer
        length = self.length
        
        # Pre-processing
        msg = bytearray(buffer)
        msg_len = len(msg)
        msg.append(0x80)
        
        while (len(msg) % 64) != 56:
            msg.append(0x00)
        
        # Append original length in bits as 64-bit big-endian
        msg += struct.pack('>Q', length * 8)
        
        # Process message in 512-bit chunks
        for offset in range(0, len(msg), 64):
            self._process_chunk(msg[offset:offset + 64], h)
        
        # Produce the final hash value
        return struct.pack('>8I', *h)
    
    @staticmethod
    def _process_chunk(chunk, h):
        """Process a 512-bit chunk"""
        # Create message schedule array
        w = list(struct.unpack('>16I', chunk))
        
        for i in range(16, 64):
            s0 = SHA256._rightrotate(w[i-15], 7) ^ SHA256._rightrotate(w[i-15], 18) ^ (w[i-15] >> 3)
            s1 = SHA256._rightrotate(w[i-2], 17) ^ SHA256._rightrotate(w[i-2], 19) ^ (w[i-2] >> 10)
            w.append((w[i-16] + s0 + w[i-7] + s1) & 0xffffffff)
        
        # Initialize working variables
        a, b, c, d, e, f, g, h_var = h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]
        
        # Main loop
        for i in range(64):
            S1 = SHA256._rightrotate(e, 6) ^ SHA256._rightrotate(e, 11) ^ SHA256._rightrotate(e, 25)
            ch = (e & f) ^ ((~e) & g)
            temp1 = (h_var + S1 + ch + SHA256.K[i] + w[i]) & 0xffffffff
            S0 = SHA256._rightrotate(a, 2) ^ SHA256._rightrotate(a, 13) ^ SHA256._rightrotate(a, 22)
            maj = (a & b) ^ (a & c) ^ (b & c)
            temp2 = (S0 + maj) & 0xffffffff
            
            h_var = g
            g = f
            f = e
            e = (d + temp1) & 0xffffffff
            d = c
            c = b
            b = a
            a = (temp1 + temp2) & 0xffffffff
        
        # Add compressed chunk to current hash value
        h[0] = (h[0] + a) & 0xffffffff
        h[1] = (h[1] + b) & 0xffffffff
        h[2] = (h[2] + c) & 0xffffffff
        h[3] = (h[3] + d) & 0xffffffff
        h[4] = (h[4] + e) & 0xffffffff
        h[5] = (h[5] + f) & 0xffffffff
        h[6] = (h[6] + g) & 0xffffffff
        h[7] = (h[7] + h_var) & 0xffffffff
    
    @staticmethod
    def _rightrotate(n, d):
        """Rotate right"""
        return ((n >> d) | (n << (32 - d))) & 0xffffffff


class MD5(HashAlgorithm):
    """MD5 (Message-Digest Algorithm 5) Implementation"""
    
    # MD5 constants
    S = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
        5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
        4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
        6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
    ]
    
    K = [int(abs((1 << 32) * __import__('math').sin(i + 1))) & 0xffffffff for i in range(64)]
    
    # Initial hash values
    H = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]
    
    def __init__(self, data=b''):
        """Initialize MD5"""
        self.h = self.H[:]
        self.buffer = b''
        self.length = 0
        if data:
            self.update(data)
    
    def update(self, data):
        """Update hash with new data"""
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        self.buffer += data
        self.length += len(data)
    
    def digest(self):
        """Return MD5 hash digest"""
        h = self.h[:]
        buffer = self.buffer
        length = self.length
        
        # Pre-processing
        msg = bytearray(buffer)
        msg_len = len(msg)
        msg.append(0x80)
        
        while (len(msg) % 64) != 56:
            msg.append(0x00)
        
        # Append original length in bits as 64-bit little-endian
        msg += struct.pack('<Q', length * 8)
        
        # Process message in 512-bit chunks
        for offset in range(0, len(msg), 64):
            self._process_chunk(msg[offset:offset + 64], h)
        
        # Produce the final hash value (little-endian)
        return struct.pack('<4I', *h)
    
    @classmethod
    def _process_chunk(cls, chunk, h):
        """Process a 512-bit chunk"""
        x = list(struct.unpack('<16I', chunk))
        
        a, b, c, d = h[0], h[1], h[2], h[3]
        
        for i in range(64):
            if i < 16:
                f = (b & c) | ((~b) & d)
                g = i
            elif i < 32:
                f = (d & b) | ((~d) & c)
                g = (5 * i + 1) % 16
            elif i < 48:
                f = b ^ c ^ d
                g = (3 * i + 5) % 16
            else:
                f = c ^ (b | (~d))
                g = (7 * i) % 16
            
            f = (f + a + cls.K[i] + x[g]) & 0xffffffff
            a = d
            d = c
            c = b
            b = (b + cls._leftrotate(f, cls.S[i])) & 0xffffffff
        
        h[0] = (h[0] + a) & 0xffffffff
        h[1] = (h[1] + b) & 0xffffffff
        h[2] = (h[2] + c) & 0xffffffff
        h[3] = (h[3] + d) & 0xffffffff
    
    @staticmethod
    def _leftrotate(n, d):
        """Rotate left"""
        return ((n << d) | (n >> (32 - d))) & 0xffffffff


class SimpleHash(HashAlgorithm):
    """Simple hash function for demonstration"""
    
    def __init__(self, data=b'', output_length=32):
        """Initialize simple hash"""
        self.output_length = output_length
        self.buffer = b''
        if data:
            self.update(data)
    
    def update(self, data):
        """Update hash with new data"""
        if isinstance(data, str):
            data = data.encode('utf-8')
        self.buffer += data
    
    def digest(self):
        """Return simple hash digest"""
        hash_value = 5381  # Initial hash value (FNV-1a inspired)
        
        for byte in self.buffer:
            hash_value = ((hash_value << 5) + hash_value) ^ byte
            hash_value &= 0xffffffff  # Keep it 32-bit
        
        # Convert to bytes of specified length
        result = bytearray()
        for i in range(self.output_length):
            result.append((hash_value >> (i % 32)) & 0xff)
        
        return bytes(result)


# Example usage
if __name__ == "__main__":
    print("Hashing Algorithms Implementation\n")
    print("=" * 70)
    
    # Test data
    test_strings = [
        "Hello, World!",
        "The quick brown fox jumps over the lazy dog",
        "Cryptography",
        ""
    ]
    
    print("\nSHA-256 (256-bit hash, one-way function):")
    print("-" * 70)
    for test_str in test_strings:
        sha256 = SHA256(test_str)
        print(f"Input:  '{test_str}'")
        print(f"Output: {sha256.hexdigest()}")
        print()
    
    print("\nMD5 (128-bit hash, one-way function - deprecated for security)")
    print("-" * 70)
    for test_str in test_strings:
        md5 = MD5(test_str)
        print(f"Input:  '{test_str}'")
        print(f"Output: {md5.hexdigest()}")
        print()
    
    print("\nSimple Hash Function (demonstration):")
    print("-" * 70)
    for test_str in test_strings:
        simple = SimpleHash(test_str)
        print(f"Input:  '{test_str}'")
        print(f"Output: {simple.hexdigest()}")
        print()
    
    print("\n" + "=" * 70)
    print("IMPORTANT PROPERTY - ONE-WAY FUNCTION:")
    print("=" * 70)
    print("\nHashing is NOT reversible:")
    print("  - Given a hash value, it's mathematically infeasible to")
    print("    find the original input (preimage resistance)")
    print("  - This is a fundamental property of cryptographic hash functions")
    print("  - Unlike encryption, hashing is intentionally irreversible")
