import numpy as np
import os

class AAES:
    def __init__(self, key_size=512, block_size=512):
        self.key_size = key_size // 8  
        self.block_size = block_size // 8
        self.rounds = self.get_rounds(key_size)

    def get_rounds(self, key_size):
        if key_size == 512:
            return 18
        elif key_size == 768:
            return 22
        elif key_size == 1024:
            return 26
        else:
            raise ValueError("Unsupported key size")

    def pad(self, data):
        pad_len = self.block_size - (len(data) % self.block_size)
        return data + bytes([pad_len] * pad_len)

    def unpad(self, data):
        pad_len = data[-1]
        if pad_len > self.block_size:  
            raise ValueError("Invalid padding detected")
        return data[:-pad_len]

    def add_round_key(self, state, round_key):
        return state ^ round_key

    def key_schedule(self, key):
        keys = [key.copy()]
        for i in range(1, self.rounds):
            keys.append(np.roll(keys[-1], i).reshape(8, 8))  
        return keys

    def encrypt_block(self, plaintext, round_keys):
        state = np.array(list(plaintext), dtype=np.uint8).reshape(8, 8)
        state = self.add_round_key(state, round_keys[0])
        for i in range(1, self.rounds):
            state = state  
            state = self.add_round_key(state, round_keys[i])
        state = self.add_round_key(state, round_keys[-1])  
        return state.flatten()

    def decrypt_block(self, ciphertext, round_keys):
        state = np.array(list(ciphertext), dtype=np.uint8).reshape(8, 8)
        state = self.add_round_key(state, round_keys[-1])
        for i in range(self.rounds - 1, 0, -1):
            state = self.add_round_key(state, round_keys[i])
        state = self.add_round_key(state, round_keys[0]) 
        return state.flatten()

    def encrypt(self, plaintext, key):
        plaintext = self.pad(plaintext)
        ciphertext = b""
        round_keys = self.key_schedule(np.array(list(key), dtype=np.uint8).reshape(8, 8))
        for i in range(0, len(plaintext), self.block_size):
            block = plaintext[i:i + self.block_size]
            ciphertext += self.encrypt_block(block, round_keys).tobytes()
        return ciphertext

    def decrypt(self, ciphertext, key):
        plaintext = b""
        round_keys = self.key_schedule(np.array(list(key), dtype=np.uint8).reshape(8, 8))
        for i in range(0, len(ciphertext), self.block_size):
            block = ciphertext[i:i + self.block_size]
            plaintext += self.decrypt_block(block, round_keys).tobytes()
        return self.unpad(plaintext)


def read_file(file_path):
    with open(file_path, "rb") as f:
        return f.read()


def write_file(file_path, data):
    with open(file_path, "wb") as f:
        f.write(data)

def file():
    file_path = input("Enter the full path of the PDF file to encrypt: ").strip()
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"The file '{file_path}' does not exist.")
    return file_path

if __name__ == "__main__":
    input_pdf = file()
    encrypted_pdf = "encrypted_file.pdf"
    decrypted_pdf = "decrypted_file.pdf"

    key = b"A" * 64 

    plaintext = read_file(input_pdf)
    print(f"Original Plaintext Size: {len(plaintext)}")

    aaes = AAES()
    ciphertext = aaes.encrypt(plaintext, key)
    print(f"Ciphertext Size: {len(ciphertext)}")
    write_file(encrypted_pdf, ciphertext)
    print(f"Encrypted PDF saved as: {encrypted_pdf}")

    decrypted_plaintext = aaes.decrypt(ciphertext, key)
    print(f"Decrypted Plaintext Size: {len(decrypted_plaintext)}")
    write_file(decrypted_pdf, decrypted_plaintext)
    print(f"Decrypted PDF saved as: {decrypted_pdf}")
