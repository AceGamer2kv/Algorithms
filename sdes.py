"""
Simple Data Encryption Standard (S-DES) Implementation
- Symmetric encryption algorithm
- Uses 10-bit key
- Processes 8-bit blocks
- Reversible: encryption and decryption both supported
"""


class SDES:
    """Simple DES Encryption/Decryption"""
    
    # Initial Permutation Table
    IP = [1, 5, 2, 0, 3, 7, 4, 6]
    
    # Inverse Initial Permutation
    IP_INV = [3, 0, 2, 4, 6, 1, 7, 5]
    
    # Expansion Permutation
    E = [3, 0, 1, 2, 1, 2, 3, 0]
    
    # P-box Permutation
    P_BOX = [1, 3, 2, 0]
    
    # S-boxes (4x4 substitution boxes)
    S0 = [
        [1, 0, 3, 2],
        [3, 2, 1, 0],
        [0, 2, 1, 3],
        [3, 1, 3, 2]
    ]
    
    S1 = [
        [0, 1, 2, 3],
        [2, 0, 1, 3],
        [3, 0, 1, 2],
        [2, 1, 0, 3]
    ]
    
    # Permutation Choice 1 (for key generation)
    PC1 = [2, 4, 1, 6, 3, 9, 0, 8, 7, 5]
    
    # Permutation Choice 2 (for key generation)
    PC2 = [5, 2, 6, 3, 7, 4, 9, 8, 0, 1]
    
    def __init__(self, key):
        """
        Initialize with a 10-bit key
        Args:
            key: 10-bit integer or string of '0' and '1' characters
        """
        if isinstance(key, str):
            key = int(key, 2)
        
        if not (0 <= key < 1024):  # 2^10 = 1024
            raise ValueError("Key must be 10 bits (0-1023)")
        
        self.key = key
        self.k1, self.k2 = self._generate_subkeys()
    
    def _generate_subkeys(self):
        """Generate two 8-bit subkeys from 10-bit key"""
        # Convert key to binary
        key_bits = self._to_bits(self.key, 10)
        
        # Apply PC1
        permuted = [key_bits[i] for i in self.PC1]
        
        # Split into two 5-bit halves and left shift by 1
        left = permuted[:5]
        right = permuted[5:]
        
        # First subkey after left shift by 1
        left_rotated_1 = left[1:] + [left[0]]
        right_rotated_1 = right[1:] + [right[0]]
        k1_bits = left_rotated_1 + right_rotated_1
        k1 = self._bits_to_int([k1_bits[i] for i in self.PC2])
        
        # Second subkey after left shift by 2 total
        left_rotated_2 = left_rotated_1[1:] + [left_rotated_1[0]]
        right_rotated_2 = right_rotated_1[1:] + [right_rotated_1[0]]
        k2_bits = left_rotated_2 + right_rotated_2
        k2 = self._bits_to_int([k2_bits[i] for i in self.PC2])
        
        return k1, k2
    
    def encrypt(self, plaintext):
        """
        Encrypt 8-bit plaintext
        Args:
            plaintext: 8-bit integer or binary string
        Returns:
            8-bit ciphertext integer
        """
        if isinstance(plaintext, str):
            plaintext = int(plaintext, 2)
        
        if not (0 <= plaintext < 256):  # 2^8 = 256
            raise ValueError("Plaintext must be 8 bits (0-255)")
        
        # Apply initial permutation
        bits = self._to_bits(plaintext, 8)
        bits = [bits[i] for i in self.IP]
        
        # Split into left and right halves
        left, right = bits[:4], bits[4:]
        
        # First round
        right = self._feistel_function(right, self.k1)
        left = [left[i] ^ right[i] for i in range(4)]
        
        # Second round (swap)
        right, left = left, right
        
        right = self._feistel_function(right, self.k2)
        left = [left[i] ^ right[i] for i in range(4)]
        
        # Combine and apply inverse permutation
        combined = left + right
        ciphertext_bits = [combined[i] for i in self.IP_INV]
        
        return self._bits_to_int(ciphertext_bits)
    
    def decrypt(self, ciphertext):
        """
        Decrypt 8-bit ciphertext
        Args:
            ciphertext: 8-bit integer or binary string
        Returns:
            8-bit plaintext integer
        """
        if isinstance(ciphertext, str):
            ciphertext = int(ciphertext, 2)
        
        if not (0 <= ciphertext < 256):
            raise ValueError("Ciphertext must be 8 bits (0-255)")
        
        # Apply initial permutation
        bits = self._to_bits(ciphertext, 8)
        bits = [bits[i] for i in self.IP]
        
        # Split into left and right halves
        left, right = bits[:4], bits[4:]
        
        # First round (with k2)
        right = self._feistel_function(right, self.k2)
        left = [left[i] ^ right[i] for i in range(4)]
        
        # Second round (swap)
        right, left = left, right
        
        right = self._feistel_function(right, self.k1)
        left = [left[i] ^ right[i] for i in range(4)]
        
        # Combine and apply inverse permutation
        combined = left + right
        plaintext_bits = [combined[i] for i in self.IP_INV]
        
        return self._bits_to_int(plaintext_bits)
    
    def _feistel_function(self, right_bits, subkey):
        """Apply Feistel function"""
        # Expand right half to 8 bits
        expanded = [right_bits[i] for i in self.E]
        
        # XOR with subkey
        subkey_bits = self._to_bits(subkey, 8)
        xored = [expanded[i] ^ subkey_bits[i] for i in range(8)]
        
        # S-box substitution
        s0_input = [xored[0], xored[1], xored[2], xored[3]]
        s0_row = (s0_input[0] << 1) | s0_input[3]
        s0_col = (s0_input[1] << 1) | s0_input[2]
        s0_output = self._to_bits(self.S0[s0_row][s0_col], 2)
        
        s1_input = [xored[4], xored[5], xored[6], xored[7]]
        s1_row = (s1_input[0] << 1) | s1_input[3]
        s1_col = (s1_input[1] << 1) | s1_input[2]
        s1_output = self._to_bits(self.S1[s1_row][s1_col], 2)
        
        sbox_output = s0_output + s1_output
        
        # P-box permutation
        result = [sbox_output[i] for i in self.P_BOX]
        
        return result
    
    @staticmethod
    def _to_bits(n, width):
        """Convert integer to list of bits"""
        return [(n >> (width - 1 - i)) & 1 for i in range(width)]
    
    @staticmethod
    def _bits_to_int(bits):
        """Convert list of bits to integer"""
        result = 0
        for bit in bits:
            result = (result << 1) | bit
        return result
    
    def to_binary_string(self, value, width):
        """Convert integer to binary string"""
        return format(value, f'0{width}b')


# Example usage
if __name__ == "__main__":
    # 10-bit key
    key = 0b1010000010  # 642 in decimal
    
    sdes = SDES(key)
    
    # 8-bit plaintext
    plaintext = 0b10101010  # 170 in decimal
    
    print(f"S-DES Implementation")
    print(f"Key (10-bit): {sdes.to_binary_string(key, 10)}")
    print(f"Plaintext (8-bit): {sdes.to_binary_string(plaintext, 8)}")
    
    ciphertext = sdes.encrypt(plaintext)
    print(f"Ciphertext (8-bit): {sdes.to_binary_string(ciphertext, 8)}")
    
    decrypted = sdes.decrypt(ciphertext)
    print(f"Decrypted (8-bit): {sdes.to_binary_string(decrypted, 8)}")
    
    print(f"\nReversibility check: {plaintext == decrypted} ✓" if plaintext == decrypted else f"\nReversibility check: FAILED ✗")
