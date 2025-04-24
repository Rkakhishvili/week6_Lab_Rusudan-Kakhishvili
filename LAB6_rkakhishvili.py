from binascii import unhexlify
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

BLOCK_SIZE = 16  # AES block size (16 bytes)
KEY = b"this_is_16_bytes"  # AES key (must be 16 bytes for AES)

def padding_oracle(ciphertext: bytes) -> bool:
    """Returns True if the ciphertext decrypts with valid padding, False otherwise."""
    try:
        iv = ciphertext[:BLOCK_SIZE]  # Extract the IV (first 16 bytes)
        ct = ciphertext[BLOCK_SIZE:]  # The rest is the ciphertext

        # Initialize AES cipher for decryption
        cipher = Cipher(algorithms.AES(KEY), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(ct) + decryptor.finalize()

        # Check for valid PKCS#7 padding (no unpadding step yet)
        if len(decrypted) % BLOCK_SIZE != 0:
            return False

        padding_value = decrypted[-1]
        if padding_value < 1 or padding_value > BLOCK_SIZE:
            return False

        if decrypted[-padding_value:] != bytes([padding_value] * padding_value):
            return False

        return True  # Padding is valid
    except (ValueError, TypeError):
        return False  # Padding is invalid

# Provided ciphertext in hex format (combining all parts)
CIPHERTEXT_HEX = (
    "746869735f69735f31365f6279746573"  # "this_is_16_bytes"
    "9404628dcdf3f003482b3b0648bd920b"
    "3f60e13e89fa6950d3340adbbbb41c12"
    "b3d1d97ef97860e9df7ec0d31d13839a"
    "e17b3be8f69921a07627021af16430e1"
)

# Convert the provided ciphertext from hex to bytes
ciphertext = unhexlify(CIPHERTEXT_HEX)

# Test the padding oracle with the known ciphertext
padding_valid = padding_oracle(ciphertext)
print("Padding valid for known ciphertext:", padding_valid)  # Expected output: True







def split_blocks(data: bytes, block_size: int = BLOCK_SIZE) -> list[bytes]:
    """Split data into blocks of the specified size."""
    blocks = []  # Initialize an empty list to store blocks
    for i in range(0, len(data), block_size):  # Step through the data in increments of block_size
        block = data[i:i + block_size]  # Slice out a block of the specified size
        blocks.append(block)  # Add the block to the list
    return blocks

# Sample data (this would be your ciphertext in actual usage)
data = unhexlify(
    "746869735f69735f31365f62797465739404628dcdf3f003482b3b0648bd920b3f60e13e89fa6950d3340adbbbb41c12b3d1d97ef97860e9df7ec0d31d13839ae17b3be8f69921a07627021af16430e1"
)

# Split the data into 16-byte blocks
blocks = split_blocks(data)

# Print the resulting blocks
for block in blocks:
    print(block)









from binascii import unhexlify
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

BLOCK_SIZE = 16
KEY = b"this_is_16_bytes"

CIPHERTEXT_HEX = (
    "746869735f69735f31365f6279746573"
    "9404628dcdf3f003482b3b0648bd920b"
    "3f60e13e89fa6950d3340adbbbb41c12"
    "b3d1d97ef97860e9df7ec0d31d13839a"
    "e17b3be8f69921a07627021af16430e1"
)

def padding_oracle(ciphertext: bytes) -> bool:
    try:
        iv = ciphertext[:BLOCK_SIZE]
        ct = ciphertext[BLOCK_SIZE:]
        cipher = Cipher(algorithms.AES(KEY), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(ct) + decryptor.finalize()
        padder = padding.PKCS7(BLOCK_SIZE * 8).unpadder()
        padder.update(decrypted)
        padder.finalize()
        return True
    except (ValueError, TypeError):
        return False

def split_blocks(data: bytes, block_size: int = BLOCK_SIZE) -> list[bytes]:
    blocks = [data[i:i + block_size] for i in range(0, len(data), block_size)]
    print(f"[+] Split into {len(blocks)} blocks.")
    return blocks

def decrypt_block(prev_block: bytes, target_block: bytes) -> bytes:
    intermediate = bytearray(BLOCK_SIZE)
    recovered = bytearray(BLOCK_SIZE)

    for byte_index in range(BLOCK_SIZE - 1, -1, -1):
        pad_value = BLOCK_SIZE - byte_index
        for guess in range(256):
            modified_block = bytearray(BLOCK_SIZE)
            for i in range(BLOCK_SIZE - 1, byte_index, -1):
                modified_block[i] = intermediate[i] ^ pad_value
            modified_block[byte_index] = guess
            crafted_block = bytes(modified_block[:byte_index] + bytes([guess]) + modified_block[byte_index+1:])
            if padding_oracle(crafted_block + target_block):
                intermediate[byte_index] = guess ^ pad_value
                recovered[byte_index] = intermediate[byte_index] ^ prev_block[byte_index]
                break

    print(f"[+] Decrypted block: {recovered}")
    return bytes(recovered)

def padding_oracle_attack(ciphertext: bytes) -> bytes:
    blocks = split_blocks(ciphertext)
    plaintext = bytearray()

    for i in range(1, len(blocks)):
        prev = blocks[i - 1]
        curr = blocks[i]
        print(f"[*] Decrypting block {i}...")
        decrypted = decrypt_block(prev, curr)
        plaintext.extend(decrypted)

    print(f"[+] Recovered full plaintext (raw): {plaintext}")
    return bytes(plaintext)

if __name__ == "__main__":
    try:
        ciphertext = unhexlify(CIPHERTEXT_HEX)
        print(f"[*] Ciphertext length: {len(ciphertext)} bytes")
        print(f"[*] IV: {ciphertext[:BLOCK_SIZE].hex()}")

        recovered = padding_oracle_attack(ciphertext)

        print("\n[+] Decryption complete!")
        print(f"Recovered plaintext (raw bytes): {recovered}")
        print(f"Hex: {recovered.hex()}")

    except Exception as e:
        print(f"\n[!] Error occurred: {e}")

from cryptography.hazmat.primitives import padding

BLOCK_SIZE = 16  # AES block size in bytes













from cryptography.hazmat.primitives import padding

BLOCK_SIZE = 16  # AES block size (16 bytes)

# Task 5: Unpad and decode recovered plaintext
def unpad_and_decode(plaintext: bytes) -> str:
    try:
        unpadder = padding.PKCS7(BLOCK_SIZE * 8).unpadder()
        unpadded = unpadder.update(plaintext) + unpadder.finalize()
        return unpadded.decode("utf-8")
    except Exception as e:
        return f"[!] Failed to decode: {e}"

if __name__ == "__main__":
    try:
        # Example recovered plaintext from Task 4 (with padding)
        recovered = b'This is a top secret message. Decrypt me if you can!\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c'

        decoded = unpad_and_decode(recovered)
        print("\nFinal plaintext:")
        print(decoded)

    except Exception as e:
        print(f"\n[!] Error occurred: {e}")
