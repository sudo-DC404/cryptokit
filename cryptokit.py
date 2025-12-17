#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════════════╗
║              CryptoKit - Multi-Method Encryption Tool         ║
║          Symmetric | Asymmetric | Classic Ciphers             ║
╚═══════════════════════════════════════════════════════════════╝

⚠️  FOR EDUCATIONAL AND AUTHORIZED TESTING ONLY ⚠️

Features:
- Symmetric: AES, DES, 3DES, Blowfish, ChaCha20
- Asymmetric: RSA, ECC
- Classic: Caesar, Vigenere, ROT13
- File & Text encryption
- Key management system
"""

import os
import sys
import json
import base64
import hashlib
import zlib
from pathlib import Path
from datetime import datetime
from typing import Optional, Tuple, Dict

# Check and import required libraries
try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False

try:
    from Crypto.Cipher import DES, DES3, Blowfish as BF
    from Crypto.Util.Padding import pad, unpad
    HAS_PYCRYPTODOME = True
except ImportError:
    HAS_PYCRYPTODOME = False

# Configuration
VERSION = "2.0.0"
BASE_DIR = Path.home() / ".cryptokit"
KEYS_DIR = BASE_DIR / "keys"
METADATA_FILE = KEYS_DIR / "metadata.json"


class Colors:
    """ANSI color codes for terminal output"""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    UNDERLINE = '\033[4m'


class CryptoKit:
    """Main encryption/decryption tool class"""

    def __init__(self):
        """Initialize CryptoKit and setup directories"""
        self.setup_directories()
        self.metadata = self.load_metadata()
        self.backend = default_backend() if HAS_CRYPTOGRAPHY else None

    def setup_directories(self):
        """Create necessary directories"""
        KEYS_DIR.mkdir(parents=True, exist_ok=True)

    def load_metadata(self) -> Dict:
        """Load key metadata from JSON file"""
        if METADATA_FILE.exists():
            try:
                with open(METADATA_FILE, 'r') as f:
                    return json.load(f)
            except:
                return {"keys": []}
        return {"keys": []}

    def save_metadata(self):
        """Save key metadata to JSON file"""
        with open(METADATA_FILE, 'w') as f:
            json.dump(self.metadata, f, indent=2)

    def print_header(self, text: str):
        """Print colored header"""
        print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*70}{Colors.END}")
        print(f"{Colors.BOLD}{Colors.CYAN}{text.center(70)}{Colors.END}")
        print(f"{Colors.BOLD}{Colors.CYAN}{'='*70}{Colors.END}\n")

    def print_success(self, text: str):
        """Print success message"""
        print(f"{Colors.GREEN}✓ {text}{Colors.END}")

    def print_error(self, text: str):
        """Print error message"""
        print(f"{Colors.RED}✗ {text}{Colors.END}")

    def print_warning(self, text: str):
        """Print warning message"""
        print(f"{Colors.YELLOW}⚠ {text}{Colors.END}")

    def print_info(self, text: str):
        """Print info message"""
        print(f"{Colors.BLUE}ℹ {text}{Colors.END}")

    # ===================================================================
    # SYMMETRIC ENCRYPTION - AES
    # ===================================================================

    def aes_encrypt(self, data: bytes, key: bytes = None) -> Tuple[bytes, bytes, bytes]:
        """
        Encrypt data using AES-256-GCM
        Returns: (ciphertext, nonce, tag)
        """
        if key is None:
            key = os.urandom(32)  # 256-bit key

        nonce = os.urandom(12)  # 96-bit nonce for GCM
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(nonce),
            backend=self.backend
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data) + encryptor.finalize()

        return ciphertext, nonce, encryptor.tag, key

    def aes_decrypt(self, ciphertext: bytes, key: bytes, nonce: bytes, tag: bytes) -> bytes:
        """Decrypt data using AES-256-GCM"""
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(nonce, tag),
            backend=self.backend
        )
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()

    # ===================================================================
    # SYMMETRIC ENCRYPTION - ChaCha20
    # ===================================================================

    def chacha20_encrypt(self, data: bytes, key: bytes = None) -> Tuple[bytes, bytes, bytes]:
        """
        Encrypt data using ChaCha20
        Returns: (ciphertext, nonce, key)
        """
        if key is None:
            key = os.urandom(32)  # 256-bit key

        nonce = os.urandom(16)  # 128-bit nonce
        cipher = Cipher(
            algorithms.ChaCha20(key, nonce),
            mode=None,
            backend=self.backend
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data) + encryptor.finalize()

        return ciphertext, nonce, key

    def chacha20_decrypt(self, ciphertext: bytes, key: bytes, nonce: bytes) -> bytes:
        """Decrypt data using ChaCha20"""
        cipher = Cipher(
            algorithms.ChaCha20(key, nonce),
            mode=None,
            backend=self.backend
        )
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()

    # ===================================================================
    # SYMMETRIC ENCRYPTION - DES/3DES/Blowfish (PyCryptodome)
    # ===================================================================

    def des_encrypt(self, data: bytes, key: bytes = None) -> Tuple[bytes, bytes, bytes]:
        """Encrypt using DES (insecure - educational only)"""
        if key is None:
            key = os.urandom(8)  # 64-bit key

        cipher = DES.new(key, DES.MODE_CBC)
        padded_data = pad(data, DES.block_size)
        ciphertext = cipher.encrypt(padded_data)

        return ciphertext, cipher.iv, key

    def des_decrypt(self, ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
        """Decrypt using DES"""
        cipher = DES.new(key, DES.MODE_CBC, iv=iv)
        padded_data = cipher.decrypt(ciphertext)
        return unpad(padded_data, DES.block_size)

    def des3_encrypt(self, data: bytes, key: bytes = None) -> Tuple[bytes, bytes, bytes]:
        """Encrypt using 3DES"""
        if key is None:
            key = DES3.adjust_key_parity(os.urandom(24))  # 192-bit key

        cipher = DES3.new(key, DES3.MODE_CBC)
        padded_data = pad(data, DES3.block_size)
        ciphertext = cipher.encrypt(padded_data)

        return ciphertext, cipher.iv, key

    def des3_decrypt(self, ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
        """Decrypt using 3DES"""
        cipher = DES3.new(key, DES3.MODE_CBC, iv=iv)
        padded_data = cipher.decrypt(ciphertext)
        return unpad(padded_data, DES3.block_size)

    def blowfish_encrypt(self, data: bytes, key: bytes = None) -> Tuple[bytes, bytes, bytes]:
        """Encrypt using Blowfish"""
        if key is None:
            key = os.urandom(16)  # 128-bit key

        cipher = BF.new(key, BF.MODE_CBC)
        padded_data = pad(data, BF.block_size)
        ciphertext = cipher.encrypt(padded_data)

        return ciphertext, cipher.iv, key

    def blowfish_decrypt(self, ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
        """Decrypt using Blowfish"""
        cipher = BF.new(key, BF.MODE_CBC, iv=iv)
        padded_data = cipher.decrypt(ciphertext)
        return unpad(padded_data, BF.block_size)

    # ===================================================================
    # ASYMMETRIC ENCRYPTION - RSA
    # ===================================================================

    def rsa_generate_keypair(self, key_size: int = 2048) -> Tuple[bytes, bytes]:
        """Generate RSA key pair"""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=self.backend
        )

        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        public_key = private_key.public_key()
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        return private_pem, public_pem

    def rsa_encrypt(self, data: bytes, public_key_pem: bytes) -> bytes:
        """Encrypt data using RSA public key"""
        public_key = serialization.load_pem_public_key(
            public_key_pem,
            backend=self.backend
        )

        ciphertext = public_key.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return ciphertext

    def rsa_decrypt(self, ciphertext: bytes, private_key_pem: bytes) -> bytes:
        """Decrypt data using RSA private key"""
        private_key = serialization.load_pem_private_key(
            private_key_pem,
            password=None,
            backend=self.backend
        )

        plaintext = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return plaintext

    # ===================================================================
    # ASYMMETRIC ENCRYPTION - ECC
    # ===================================================================

    def ecc_generate_keypair(self, curve: str = "secp256r1") -> Tuple[bytes, bytes]:
        """Generate ECC key pair"""
        curve_map = {
            "secp256r1": ec.SECP256R1(),
            "secp384r1": ec.SECP384R1(),
        }

        private_key = ec.generate_private_key(
            curve_map.get(curve, ec.SECP256R1()),
            self.backend
        )

        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        public_key = private_key.public_key()
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        return private_pem, public_pem

    # ===================================================================
    # CLASSIC CIPHERS
    # ===================================================================

    def caesar_cipher(self, text: str, shift: int, decrypt: bool = False) -> str:
        """Caesar cipher encryption/decryption"""
        if decrypt:
            shift = -shift

        result = []
        for char in text:
            if char.isalpha():
                ascii_offset = 65 if char.isupper() else 97
                shifted = (ord(char) - ascii_offset + shift) % 26
                result.append(chr(shifted + ascii_offset))
            else:
                result.append(char)

        return ''.join(result)

    def vigenere_cipher(self, text: str, key: str, decrypt: bool = False) -> str:
        """Vigenere cipher encryption/decryption"""
        result = []
        key = key.upper()
        key_index = 0

        for char in text:
            if char.isalpha():
                ascii_offset = 65 if char.isupper() else 97
                key_char = key[key_index % len(key)]
                shift = ord(key_char) - 65

                if decrypt:
                    shift = -shift

                shifted = (ord(char) - ascii_offset + shift) % 26
                result.append(chr(shifted + ascii_offset))
                key_index += 1
            else:
                result.append(char)

        return ''.join(result)

    def rot13(self, text: str) -> str:
        """ROT13 cipher (Caesar with shift 13)"""
        return self.caesar_cipher(text, 13)

    # ===================================================================
    # HASHING FUNCTIONS
    # ===================================================================

    def hash_data(self, data: bytes, algorithm: str) -> str:
        """Hash data using specified algorithm"""
        if algorithm == "md5":
            return hashlib.md5(data).hexdigest()
        elif algorithm == "sha1":
            return hashlib.sha1(data).hexdigest()
        elif algorithm == "sha256":
            return hashlib.sha256(data).hexdigest()
        elif algorithm == "sha512":
            return hashlib.sha512(data).hexdigest()
        elif algorithm == "sha3-256":
            return hashlib.sha3_256(data).hexdigest()
        elif algorithm == "sha3-512":
            return hashlib.sha3_512(data).hexdigest()
        elif algorithm == "blake2b":
            return hashlib.blake2b(data).hexdigest()
        elif algorithm == "blake2s":
            return hashlib.blake2s(data).hexdigest()
        else:
            raise ValueError(f"Unsupported hash algorithm: {algorithm}")

    def hash_file(self, file_path: str, algorithm: str) -> str:
        """Hash a file using specified algorithm"""
        hash_obj = None
        if algorithm == "md5":
            hash_obj = hashlib.md5()
        elif algorithm == "sha1":
            hash_obj = hashlib.sha1()
        elif algorithm == "sha256":
            hash_obj = hashlib.sha256()
        elif algorithm == "sha512":
            hash_obj = hashlib.sha512()
        elif algorithm == "sha3-256":
            hash_obj = hashlib.sha3_256()
        elif algorithm == "sha3-512":
            hash_obj = hashlib.sha3_512()
        elif algorithm == "blake2b":
            hash_obj = hashlib.blake2b()
        elif algorithm == "blake2s":
            hash_obj = hashlib.blake2s()
        else:
            raise ValueError(f"Unsupported hash algorithm: {algorithm}")

        with open(file_path, 'rb') as f:
            while chunk := f.read(8192):
                hash_obj.update(chunk)

        return hash_obj.hexdigest()

    def verify_hash(self, data: bytes, expected_hash: str, algorithm: str) -> bool:
        """Verify data against expected hash"""
        computed_hash = self.hash_data(data, algorithm)
        return computed_hash.lower() == expected_hash.lower()

    # ===================================================================
    # PASSWORD-BASED ENCRYPTION
    # ===================================================================

    def derive_key_from_password(self, password: str, salt: bytes = None,
                                 key_length: int = 32) -> Tuple[bytes, bytes]:
        """Derive encryption key from password using PBKDF2"""
        if salt is None:
            salt = os.urandom(16)

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=key_length,
            salt=salt,
            iterations=600000,  # OWASP recommended
            backend=self.backend
        )

        key = kdf.derive(password.encode())
        return key, salt

    def password_encrypt(self, data: bytes, password: str) -> Tuple[bytes, bytes]:
        """Encrypt data using password-derived key (AES-256-GCM)"""
        key, salt = self.derive_key_from_password(password)
        ciphertext, nonce, tag, _ = self.aes_encrypt(data, key)
        # Return: salt + nonce + tag + ciphertext
        return salt + nonce + tag + ciphertext, salt

    def password_decrypt(self, encrypted_data: bytes, password: str) -> bytes:
        """Decrypt data using password-derived key"""
        salt = encrypted_data[:16]
        nonce = encrypted_data[16:28]
        tag = encrypted_data[28:44]
        ciphertext = encrypted_data[44:]

        key, _ = self.derive_key_from_password(password, salt)
        return self.aes_decrypt(ciphertext, key, nonce, tag)

    # ===================================================================
    # FILE UTILITIES
    # ===================================================================

    def compress_data(self, data: bytes) -> bytes:
        """Compress data using zlib"""
        return zlib.compress(data, level=9)

    def decompress_data(self, data: bytes) -> bytes:
        """Decompress data using zlib"""
        return zlib.decompress(data)

    def get_file_hash(self, file_path: str) -> str:
        """Get SHA-256 hash of file for integrity verification"""
        return self.hash_file(file_path, "sha256")

    # ===================================================================
    # KEY MANAGEMENT
    # ===================================================================

    def save_key(self, key_data: bytes, key_name: str, algorithm: str, key_type: str,
                 additional_info: Dict = None):
        """Save key to file with metadata"""
        key_file = KEYS_DIR / f"{key_name}.key"

        # Save key file
        with open(key_file, 'wb') as f:
            f.write(key_data)

        # Update metadata
        key_info = {
            "name": key_name,
            "algorithm": algorithm,
            "type": key_type,
            "file": str(key_file),
            "created": datetime.now().isoformat(),
            "size": len(key_data)
        }

        if additional_info:
            key_info.update(additional_info)

        # Remove old entry if exists
        self.metadata["keys"] = [k for k in self.metadata["keys"] if k["name"] != key_name]
        self.metadata["keys"].append(key_info)
        self.save_metadata()

        self.print_success(f"Key '{key_name}' saved to {key_file}")

    def load_key(self, key_name: str) -> Optional[bytes]:
        """Load key from file"""
        key_info = next((k for k in self.metadata["keys"] if k["name"] == key_name), None)

        if not key_info:
            self.print_error(f"Key '{key_name}' not found in metadata")
            return None

        key_file = Path(key_info["file"])
        if not key_file.exists():
            self.print_error(f"Key file not found: {key_file}")
            return None

        with open(key_file, 'rb') as f:
            return f.read()

    def list_keys(self):
        """List all stored keys"""
        if not self.metadata["keys"]:
            self.print_info("No keys stored yet")
            return

        print(f"\n{Colors.BOLD}Stored Keys:{Colors.END}")
        print(f"{Colors.DIM}{'Name':<20} {'Algorithm':<15} {'Type':<15} {'Created':<20}{Colors.END}")
        print("-" * 70)

        for key_info in self.metadata["keys"]:
            print(f"{key_info['name']:<20} {key_info['algorithm']:<15} "
                  f"{key_info['type']:<15} {key_info['created'][:19]:<20}")

    # ===================================================================
    # FILE OPERATIONS
    # ===================================================================

    def encrypt_file(self, input_file: str, output_file: str, algorithm: str, key: bytes):
        """Encrypt a file"""
        try:
            with open(input_file, 'rb') as f:
                data = f.read()

            # Encrypt based on algorithm
            if algorithm == "aes":
                ciphertext, nonce, tag, _ = self.aes_encrypt(data, key)
                # Store nonce and tag with ciphertext
                encrypted_data = nonce + tag + ciphertext
            elif algorithm == "chacha20":
                ciphertext, nonce, _ = self.chacha20_encrypt(data, key)
                encrypted_data = nonce + ciphertext
            elif algorithm == "des" and HAS_PYCRYPTODOME:
                ciphertext, iv, _ = self.des_encrypt(data, key)
                encrypted_data = iv + ciphertext
            elif algorithm == "3des" and HAS_PYCRYPTODOME:
                ciphertext, iv, _ = self.des3_encrypt(data, key)
                encrypted_data = iv + ciphertext
            elif algorithm == "blowfish" and HAS_PYCRYPTODOME:
                ciphertext, iv, _ = self.blowfish_encrypt(data, key)
                encrypted_data = iv + ciphertext
            else:
                self.print_error(f"Unsupported algorithm: {algorithm}")
                return False

            # Write encrypted file
            with open(output_file, 'wb') as f:
                f.write(encrypted_data)

            self.print_success(f"File encrypted: {output_file}")
            return True

        except Exception as e:
            self.print_error(f"File encryption failed: {e}")
            return False

    def decrypt_file(self, input_file: str, output_file: str, algorithm: str, key: bytes):
        """Decrypt a file"""
        try:
            with open(input_file, 'rb') as f:
                encrypted_data = f.read()

            # Decrypt based on algorithm
            if algorithm == "aes":
                nonce = encrypted_data[:12]
                tag = encrypted_data[12:28]
                ciphertext = encrypted_data[28:]
                plaintext = self.aes_decrypt(ciphertext, key, nonce, tag)
            elif algorithm == "chacha20":
                nonce = encrypted_data[:16]
                ciphertext = encrypted_data[16:]
                plaintext = self.chacha20_decrypt(ciphertext, key, nonce)
            elif algorithm == "des" and HAS_PYCRYPTODOME:
                iv = encrypted_data[:8]
                ciphertext = encrypted_data[8:]
                plaintext = self.des_decrypt(ciphertext, key, iv)
            elif algorithm == "3des" and HAS_PYCRYPTODOME:
                iv = encrypted_data[:8]
                ciphertext = encrypted_data[8:]
                plaintext = self.des3_decrypt(ciphertext, key, iv)
            elif algorithm == "blowfish" and HAS_PYCRYPTODOME:
                iv = encrypted_data[:8]
                ciphertext = encrypted_data[8:]
                plaintext = self.blowfish_decrypt(ciphertext, key, iv)
            else:
                self.print_error(f"Unsupported algorithm: {algorithm}")
                return False

            # Write decrypted file
            with open(output_file, 'wb') as f:
                f.write(plaintext)

            self.print_success(f"File decrypted: {output_file}")
            return True

        except Exception as e:
            self.print_error(f"File decryption failed: {e}")
            return False

    # ===================================================================
    # MENU SYSTEM
    # ===================================================================

    def symmetric_menu(self):
        """Symmetric encryption menu"""
        while True:
            self.print_header("SYMMETRIC ENCRYPTION")
            print(f"{Colors.CYAN}1.{Colors.END} AES-256-GCM Encrypt/Decrypt")
            print(f"{Colors.CYAN}2.{Colors.END} ChaCha20 Encrypt/Decrypt")
            print(f"{Colors.CYAN}3.{Colors.END} DES Encrypt/Decrypt {Colors.RED}(Insecure){Colors.END}")
            print(f"{Colors.CYAN}4.{Colors.END} 3DES Encrypt/Decrypt")
            print(f"{Colors.CYAN}5.{Colors.END} Blowfish Encrypt/Decrypt")
            print(f"{Colors.CYAN}0.{Colors.END} Back to Main Menu")

            choice = input(f"\n{Colors.YELLOW}Enter choice:{Colors.END} ").strip()

            if choice == "0":
                break
            elif choice == "1":
                self.symmetric_operation("aes", "AES-256-GCM")
            elif choice == "2":
                self.symmetric_operation("chacha20", "ChaCha20")
            elif choice == "3":
                if not HAS_PYCRYPTODOME:
                    self.print_error("PyCryptodome not installed. Run: pip3 install pycryptodome")
                else:
                    self.print_warning("DES is insecure and deprecated. Use for education only!")
                    self.symmetric_operation("des", "DES")
            elif choice == "4":
                if not HAS_PYCRYPTODOME:
                    self.print_error("PyCryptodome not installed. Run: pip3 install pycryptodome")
                else:
                    self.symmetric_operation("3des", "3DES")
            elif choice == "5":
                if not HAS_PYCRYPTODOME:
                    self.print_error("PyCryptodome not installed. Run: pip3 install pycryptodome")
                else:
                    self.symmetric_operation("blowfish", "Blowfish")

    def symmetric_operation(self, algorithm: str, display_name: str):
        """Handle symmetric encryption/decryption operation"""
        self.print_header(f"{display_name} Operation")

        print(f"{Colors.CYAN}1.{Colors.END} Encrypt Text")
        print(f"{Colors.CYAN}2.{Colors.END} Decrypt Text")
        print(f"{Colors.CYAN}3.{Colors.END} Encrypt File")
        print(f"{Colors.CYAN}4.{Colors.END} Decrypt File")

        mode = input(f"\n{Colors.YELLOW}Choose operation:{Colors.END} ").strip()

        if mode in ["1", "2"]:
            # Text mode
            if mode == "1":
                text = input(f"\n{Colors.YELLOW}Enter text to encrypt:{Colors.END} ")

                # Ask for key
                use_saved = input(f"{Colors.YELLOW}Use saved key? (y/n):{Colors.END} ").lower()
                if use_saved == 'y':
                    self.list_keys()
                    key_name = input(f"{Colors.YELLOW}Enter key name:{Colors.END} ")
                    key = self.load_key(key_name)
                    if not key:
                        return
                else:
                    key = None  # Will generate new key

                # Encrypt
                data = text.encode('utf-8')

                if algorithm == "aes":
                    ciphertext, nonce, tag, key = self.aes_encrypt(data, key)
                    result = base64.b64encode(nonce + tag + ciphertext).decode()
                elif algorithm == "chacha20":
                    ciphertext, nonce, key = self.chacha20_encrypt(data, key)
                    result = base64.b64encode(nonce + ciphertext).decode()
                elif algorithm in ["des", "3des", "blowfish"]:
                    if algorithm == "des":
                        ciphertext, iv, key = self.des_encrypt(data, key)
                    elif algorithm == "3des":
                        ciphertext, iv, key = self.des3_encrypt(data, key)
                    else:
                        ciphertext, iv, key = self.blowfish_encrypt(data, key)
                    result = base64.b64encode(iv + ciphertext).decode()

                print(f"\n{Colors.GREEN}Encrypted (base64):{Colors.END}")
                print(f"{Colors.BOLD}{result}{Colors.END}")
                print(f"\n{Colors.YELLOW}Key (hex):{Colors.END}")
                print(f"{Colors.BOLD}{key.hex()}{Colors.END}")

                # Offer to save key
                save = input(f"\n{Colors.YELLOW}Save key? (y/n):{Colors.END} ").lower()
                if save == 'y':
                    key_name = input(f"{Colors.YELLOW}Enter key name:{Colors.END} ")
                    self.save_key(key, key_name, algorithm, "symmetric")

            else:  # Decrypt
                encrypted_b64 = input(f"\n{Colors.YELLOW}Enter encrypted text (base64):{Colors.END} ")
                key_hex = input(f"{Colors.YELLOW}Enter key (hex):{Colors.END} ")

                try:
                    encrypted_data = base64.b64decode(encrypted_b64)
                    key = bytes.fromhex(key_hex)

                    if algorithm == "aes":
                        nonce = encrypted_data[:12]
                        tag = encrypted_data[12:28]
                        ciphertext = encrypted_data[28:]
                        plaintext = self.aes_decrypt(ciphertext, key, nonce, tag)
                    elif algorithm == "chacha20":
                        nonce = encrypted_data[:16]
                        ciphertext = encrypted_data[16:]
                        plaintext = self.chacha20_decrypt(ciphertext, key, nonce)
                    elif algorithm == "des":
                        iv = encrypted_data[:8]
                        ciphertext = encrypted_data[8:]
                        plaintext = self.des_decrypt(ciphertext, key, iv)
                    elif algorithm == "3des":
                        iv = encrypted_data[:8]
                        ciphertext = encrypted_data[8:]
                        plaintext = self.des3_decrypt(ciphertext, key, iv)
                    elif algorithm == "blowfish":
                        iv = encrypted_data[:8]
                        ciphertext = encrypted_data[8:]
                        plaintext = self.blowfish_decrypt(ciphertext, key, iv)

                    print(f"\n{Colors.GREEN}Decrypted text:{Colors.END}")
                    print(f"{Colors.BOLD}{plaintext.decode('utf-8')}{Colors.END}")

                except Exception as e:
                    self.print_error(f"Decryption failed: {e}")

        elif mode in ["3", "4"]:
            # File mode
            input_file = input(f"\n{Colors.YELLOW}Enter input file path:{Colors.END} ")
            output_file = input(f"{Colors.YELLOW}Enter output file path:{Colors.END} ")

            if mode == "3":  # Encrypt file
                # Get key
                use_saved = input(f"{Colors.YELLOW}Use saved key? (y/n):{Colors.END} ").lower()
                if use_saved == 'y':
                    self.list_keys()
                    key_name = input(f"{Colors.YELLOW}Enter key name:{Colors.END} ")
                    key = self.load_key(key_name)
                else:
                    # Generate new key
                    if algorithm == "des":
                        key = os.urandom(8)
                    elif algorithm == "3des":
                        key = os.urandom(24)
                    else:
                        key = os.urandom(32)

                    print(f"\n{Colors.YELLOW}Generated key (hex):{Colors.END}")
                    print(f"{Colors.BOLD}{key.hex()}{Colors.END}")

                    save = input(f"\n{Colors.YELLOW}Save key? (y/n):{Colors.END} ").lower()
                    if save == 'y':
                        key_name = input(f"{Colors.YELLOW}Enter key name:{Colors.END} ")
                        self.save_key(key, key_name, algorithm, "symmetric")

                if key:
                    self.encrypt_file(input_file, output_file, algorithm, key)

            else:  # Decrypt file
                key_hex = input(f"{Colors.YELLOW}Enter key (hex):{Colors.END} ")
                try:
                    key = bytes.fromhex(key_hex)
                    self.decrypt_file(input_file, output_file, algorithm, key)
                except Exception as e:
                    self.print_error(f"Invalid key format: {e}")

    def asymmetric_menu(self):
        """Asymmetric encryption menu"""
        while True:
            self.print_header("ASYMMETRIC ENCRYPTION")
            print(f"{Colors.CYAN}1.{Colors.END} Generate RSA Key Pair")
            print(f"{Colors.CYAN}2.{Colors.END} RSA Encrypt/Decrypt Text")
            print(f"{Colors.CYAN}3.{Colors.END} Generate ECC Key Pair")
            print(f"{Colors.CYAN}4.{Colors.END} List Saved Key Pairs")
            print(f"{Colors.CYAN}0.{Colors.END} Back to Main Menu")

            choice = input(f"\n{Colors.YELLOW}Enter choice:{Colors.END} ").strip()

            if choice == "0":
                break
            elif choice == "1":
                self.generate_rsa_keypair()
            elif choice == "2":
                self.rsa_operation()
            elif choice == "3":
                self.generate_ecc_keypair()
            elif choice == "4":
                self.list_keys()

    def generate_rsa_keypair(self):
        """Generate and save RSA key pair"""
        self.print_header("Generate RSA Key Pair")

        print(f"{Colors.CYAN}1.{Colors.END} 2048-bit (Recommended)")
        print(f"{Colors.CYAN}2.{Colors.END} 4096-bit (More Secure)")

        size_choice = input(f"\n{Colors.YELLOW}Choose key size:{Colors.END} ").strip()
        key_size = 4096 if size_choice == "2" else 2048

        self.print_info(f"Generating {key_size}-bit RSA key pair...")
        private_pem, public_pem = self.rsa_generate_keypair(key_size)

        key_name = input(f"\n{Colors.YELLOW}Enter name for this key pair:{Colors.END} ")

        # Save private key
        self.save_key(private_pem, f"{key_name}_private", "RSA", "private",
                     {"key_size": key_size})

        # Save public key
        self.save_key(public_pem, f"{key_name}_public", "RSA", "public",
                     {"key_size": key_size})

        self.print_success(f"RSA {key_size}-bit key pair generated and saved!")

    def generate_ecc_keypair(self):
        """Generate and save ECC key pair"""
        self.print_header("Generate ECC Key Pair")

        print(f"{Colors.CYAN}1.{Colors.END} secp256r1 (256-bit)")
        print(f"{Colors.CYAN}2.{Colors.END} secp384r1 (384-bit)")

        curve_choice = input(f"\n{Colors.YELLOW}Choose curve:{Colors.END} ").strip()
        curve = "secp384r1" if curve_choice == "2" else "secp256r1"

        self.print_info(f"Generating ECC key pair ({curve})...")
        private_pem, public_pem = self.ecc_generate_keypair(curve)

        key_name = input(f"\n{Colors.YELLOW}Enter name for this key pair:{Colors.END} ")

        # Save keys
        self.save_key(private_pem, f"{key_name}_private", "ECC", "private",
                     {"curve": curve})
        self.save_key(public_pem, f"{key_name}_public", "ECC", "public",
                     {"curve": curve})

        self.print_success(f"ECC {curve} key pair generated and saved!")

    def rsa_operation(self):
        """RSA encrypt/decrypt operation"""
        self.print_header("RSA Encrypt/Decrypt")

        print(f"{Colors.CYAN}1.{Colors.END} Encrypt Text")
        print(f"{Colors.CYAN}2.{Colors.END} Decrypt Text")

        mode = input(f"\n{Colors.YELLOW}Choose operation:{Colors.END} ").strip()

        if mode == "1":
            text = input(f"\n{Colors.YELLOW}Enter text to encrypt:{Colors.END} ")

            self.list_keys()
            key_name = input(f"\n{Colors.YELLOW}Enter PUBLIC key name:{Colors.END} ")
            public_key = self.load_key(key_name)

            if not public_key:
                return

            try:
                # RSA can only encrypt small amounts of data
                if len(text) > 190:  # Safe limit for 2048-bit RSA with OAEP
                    self.print_warning("Text too long for RSA. Consider using hybrid encryption.")
                    return

                ciphertext = self.rsa_encrypt(text.encode(), public_key)
                result = base64.b64encode(ciphertext).decode()

                print(f"\n{Colors.GREEN}Encrypted (base64):{Colors.END}")
                print(f"{Colors.BOLD}{result}{Colors.END}")

            except Exception as e:
                self.print_error(f"Encryption failed: {e}")

        elif mode == "2":
            encrypted_b64 = input(f"\n{Colors.YELLOW}Enter encrypted text (base64):{Colors.END} ")

            self.list_keys()
            key_name = input(f"\n{Colors.YELLOW}Enter PRIVATE key name:{Colors.END} ")
            private_key = self.load_key(key_name)

            if not private_key:
                return

            try:
                ciphertext = base64.b64decode(encrypted_b64)
                plaintext = self.rsa_decrypt(ciphertext, private_key)

                print(f"\n{Colors.GREEN}Decrypted text:{Colors.END}")
                print(f"{Colors.BOLD}{plaintext.decode('utf-8')}{Colors.END}")

            except Exception as e:
                self.print_error(f"Decryption failed: {e}")

    def classic_ciphers_menu(self):
        """Classic ciphers menu"""
        while True:
            self.print_header("CLASSIC CIPHERS")
            self.print_warning("These ciphers are insecure - for education only!")

            print(f"\n{Colors.CYAN}1.{Colors.END} Caesar Cipher")
            print(f"{Colors.CYAN}2.{Colors.END} Vigenere Cipher")
            print(f"{Colors.CYAN}3.{Colors.END} ROT13")
            print(f"{Colors.CYAN}0.{Colors.END} Back to Main Menu")

            choice = input(f"\n{Colors.YELLOW}Enter choice:{Colors.END} ").strip()

            if choice == "0":
                break
            elif choice == "1":
                self.caesar_operation()
            elif choice == "2":
                self.vigenere_operation()
            elif choice == "3":
                self.rot13_operation()

    def caesar_operation(self):
        """Caesar cipher operation"""
        self.print_header("Caesar Cipher")

        print(f"{Colors.CYAN}1.{Colors.END} Encrypt")
        print(f"{Colors.CYAN}2.{Colors.END} Decrypt")

        mode = input(f"\n{Colors.YELLOW}Choose operation:{Colors.END} ").strip()
        text = input(f"{Colors.YELLOW}Enter text:{Colors.END} ")
        shift = int(input(f"{Colors.YELLOW}Enter shift (1-25):{Colors.END} "))

        decrypt = (mode == "2")
        result = self.caesar_cipher(text, shift, decrypt)

        print(f"\n{Colors.GREEN}Result:{Colors.END}")
        print(f"{Colors.BOLD}{result}{Colors.END}")

    def vigenere_operation(self):
        """Vigenere cipher operation"""
        self.print_header("Vigenere Cipher")

        print(f"{Colors.CYAN}1.{Colors.END} Encrypt")
        print(f"{Colors.CYAN}2.{Colors.END} Decrypt")

        mode = input(f"\n{Colors.YELLOW}Choose operation:{Colors.END} ").strip()
        text = input(f"{Colors.YELLOW}Enter text:{Colors.END} ")
        key = input(f"{Colors.YELLOW}Enter key (letters only):{Colors.END} ")

        decrypt = (mode == "2")
        result = self.vigenere_cipher(text, key, decrypt)

        print(f"\n{Colors.GREEN}Result:{Colors.END}")
        print(f"{Colors.BOLD}{result}{Colors.END}")

    def rot13_operation(self):
        """ROT13 operation"""
        self.print_header("ROT13")

        text = input(f"{Colors.YELLOW}Enter text:{Colors.END} ")
        result = self.rot13(text)

        print(f"\n{Colors.GREEN}Result:{Colors.END}")
        print(f"{Colors.BOLD}{result}{Colors.END}")

    def key_management_menu(self):
        """Key management menu"""
        while True:
            self.print_header("KEY MANAGEMENT")

            print(f"{Colors.CYAN}1.{Colors.END} View Stored Keys")
            print(f"{Colors.CYAN}2.{Colors.END} Delete Key")
            print(f"{Colors.CYAN}3.{Colors.END} Export Key")
            print(f"{Colors.CYAN}0.{Colors.END} Back to Main Menu")

            choice = input(f"\n{Colors.YELLOW}Enter choice:{Colors.END} ").strip()

            if choice == "0":
                break
            elif choice == "1":
                self.list_keys()
            elif choice == "2":
                self.delete_key()
            elif choice == "3":
                self.export_key()

    def delete_key(self):
        """Delete a stored key"""
        self.list_keys()
        key_name = input(f"\n{Colors.YELLOW}Enter key name to delete:{Colors.END} ")

        key_info = next((k for k in self.metadata["keys"] if k["name"] == key_name), None)
        if not key_info:
            self.print_error(f"Key '{key_name}' not found")
            return

        confirm = input(f"{Colors.RED}Delete '{key_name}'? (yes/no):{Colors.END} ")
        if confirm.lower() == "yes":
            # Delete file
            key_file = Path(key_info["file"])
            if key_file.exists():
                key_file.unlink()

            # Remove from metadata
            self.metadata["keys"] = [k for k in self.metadata["keys"] if k["name"] != key_name]
            self.save_metadata()

            self.print_success(f"Key '{key_name}' deleted")

    def export_key(self):
        """Export key to specified location"""
        self.list_keys()
        key_name = input(f"\n{Colors.YELLOW}Enter key name to export:{Colors.END} ")
        export_path = input(f"{Colors.YELLOW}Enter export path:{Colors.END} ")

        key_data = self.load_key(key_name)
        if key_data:
            with open(export_path, 'wb') as f:
                f.write(key_data)
            self.print_success(f"Key exported to {export_path}")

    def password_based_menu(self):
        """Password-based encryption menu"""
        while True:
            self.print_header("PASSWORD-BASED ENCRYPTION")
            self.print_info("Uses PBKDF2 (600,000 iterations) with AES-256-GCM")

            print(f"\n{Colors.CYAN}1.{Colors.END} Encrypt Text with Password")
            print(f"{Colors.CYAN}2.{Colors.END} Decrypt Text with Password")
            print(f"{Colors.CYAN}3.{Colors.END} Encrypt File with Password")
            print(f"{Colors.CYAN}4.{Colors.END} Decrypt File with Password")
            print(f"{Colors.CYAN}0.{Colors.END} Back to Main Menu")

            choice = input(f"\n{Colors.YELLOW}Enter choice:{Colors.END} ").strip()

            if choice == "0":
                break
            elif choice == "1":
                text = input(f"\n{Colors.YELLOW}Enter text to encrypt:{Colors.END} ")
                password = input(f"{Colors.YELLOW}Enter password:{Colors.END} ")

                try:
                    encrypted, salt = self.password_encrypt(text.encode(), password)
                    result = base64.b64encode(encrypted).decode()

                    print(f"\n{Colors.GREEN}Encrypted (base64):{Colors.END}")
                    print(f"{Colors.BOLD}{result}{Colors.END}")
                    self.print_info("Save this encrypted text and remember your password to decrypt later")
                except Exception as e:
                    self.print_error(f"Encryption failed: {e}")

            elif choice == "2":
                encrypted_b64 = input(f"\n{Colors.YELLOW}Enter encrypted text (base64):{Colors.END} ")
                password = input(f"{Colors.YELLOW}Enter password:{Colors.END} ")

                try:
                    encrypted = base64.b64decode(encrypted_b64)
                    plaintext = self.password_decrypt(encrypted, password)

                    print(f"\n{Colors.GREEN}Decrypted text:{Colors.END}")
                    print(f"{Colors.BOLD}{plaintext.decode('utf-8')}{Colors.END}")
                except Exception as e:
                    self.print_error(f"Decryption failed: {e}")

            elif choice == "3":
                input_file = input(f"\n{Colors.YELLOW}Enter input file path:{Colors.END} ")
                output_file = input(f"{Colors.YELLOW}Enter output file path:{Colors.END} ")
                password = input(f"{Colors.YELLOW}Enter password:{Colors.END} ")

                try:
                    with open(input_file, 'rb') as f:
                        data = f.read()

                    encrypted, salt = self.password_encrypt(data, password)

                    with open(output_file, 'wb') as f:
                        f.write(encrypted)

                    self.print_success(f"File encrypted: {output_file}")
                    self.print_info("Remember your password to decrypt the file")
                except Exception as e:
                    self.print_error(f"File encryption failed: {e}")

            elif choice == "4":
                input_file = input(f"\n{Colors.YELLOW}Enter encrypted file path:{Colors.END} ")
                output_file = input(f"{Colors.YELLOW}Enter output file path:{Colors.END} ")
                password = input(f"{Colors.YELLOW}Enter password:{Colors.END} ")

                try:
                    with open(input_file, 'rb') as f:
                        encrypted = f.read()

                    plaintext = self.password_decrypt(encrypted, password)

                    with open(output_file, 'wb') as f:
                        f.write(plaintext)

                    self.print_success(f"File decrypted: {output_file}")
                except Exception as e:
                    self.print_error(f"File decryption failed: {e}")

    def hashing_menu(self):
        """Hashing and verification menu"""
        while True:
            self.print_header("HASHING & VERIFICATION")

            print(f"\n{Colors.CYAN}1.{Colors.END} Hash Text")
            print(f"{Colors.CYAN}2.{Colors.END} Hash File")
            print(f"{Colors.CYAN}3.{Colors.END} Verify File Integrity")
            print(f"{Colors.CYAN}4.{Colors.END} Compare Hashes")
            print(f"{Colors.CYAN}0.{Colors.END} Back to Main Menu")

            choice = input(f"\n{Colors.YELLOW}Enter choice:{Colors.END} ").strip()

            if choice == "0":
                break
            elif choice == "1":
                text = input(f"\n{Colors.YELLOW}Enter text to hash:{Colors.END} ")

                print(f"\n{Colors.BOLD}Select hash algorithm:{Colors.END}")
                print(f"{Colors.CYAN}1.{Colors.END} MD5 (insecure)")
                print(f"{Colors.CYAN}2.{Colors.END} SHA-1 (insecure)")
                print(f"{Colors.CYAN}3.{Colors.END} SHA-256 (recommended)")
                print(f"{Colors.CYAN}4.{Colors.END} SHA-512")
                print(f"{Colors.CYAN}5.{Colors.END} SHA3-256")
                print(f"{Colors.CYAN}6.{Colors.END} SHA3-512")
                print(f"{Colors.CYAN}7.{Colors.END} BLAKE2b")
                print(f"{Colors.CYAN}8.{Colors.END} BLAKE2s")

                algo_choice = input(f"\n{Colors.YELLOW}Choose algorithm:{Colors.END} ").strip()

                algo_map = {
                    "1": "md5", "2": "sha1", "3": "sha256", "4": "sha512",
                    "5": "sha3-256", "6": "sha3-512", "7": "blake2b", "8": "blake2s"
                }

                algorithm = algo_map.get(algo_choice, "sha256")

                try:
                    hash_result = self.hash_data(text.encode(), algorithm)
                    print(f"\n{Colors.GREEN}{algorithm.upper()} Hash:{Colors.END}")
                    print(f"{Colors.BOLD}{hash_result}{Colors.END}")
                except Exception as e:
                    self.print_error(f"Hashing failed: {e}")

            elif choice == "2":
                file_path = input(f"\n{Colors.YELLOW}Enter file path:{Colors.END} ")

                print(f"\n{Colors.BOLD}Select hash algorithm:{Colors.END}")
                print(f"{Colors.CYAN}1.{Colors.END} MD5")
                print(f"{Colors.CYAN}2.{Colors.END} SHA-1")
                print(f"{Colors.CYAN}3.{Colors.END} SHA-256 (recommended)")
                print(f"{Colors.CYAN}4.{Colors.END} SHA-512")
                print(f"{Colors.CYAN}5.{Colors.END} All algorithms")

                algo_choice = input(f"\n{Colors.YELLOW}Choose algorithm:{Colors.END} ").strip()

                try:
                    if algo_choice == "5":
                        # Show all hashes
                        print(f"\n{Colors.BOLD}File Hashes:{Colors.END}")
                        for algo in ["md5", "sha1", "sha256", "sha512", "sha3-256", "blake2b"]:
                            hash_result = self.hash_file(file_path, algo)
                            print(f"{Colors.CYAN}{algo.upper():<12}{Colors.END}: {hash_result}")
                    else:
                        algo_map = {"1": "md5", "2": "sha1", "3": "sha256", "4": "sha512"}
                        algorithm = algo_map.get(algo_choice, "sha256")
                        hash_result = self.hash_file(file_path, algorithm)
                        print(f"\n{Colors.GREEN}{algorithm.upper()} Hash:{Colors.END}")
                        print(f"{Colors.BOLD}{hash_result}{Colors.END}")
                except Exception as e:
                    self.print_error(f"Hashing failed: {e}")

            elif choice == "3":
                file_path = input(f"\n{Colors.YELLOW}Enter file path:{Colors.END} ")
                expected_hash = input(f"{Colors.YELLOW}Enter expected hash:{Colors.END} ")

                print(f"\n{Colors.BOLD}Select hash algorithm:{Colors.END}")
                print(f"{Colors.CYAN}1.{Colors.END} MD5")
                print(f"{Colors.CYAN}2.{Colors.END} SHA-1")
                print(f"{Colors.CYAN}3.{Colors.END} SHA-256")
                print(f"{Colors.CYAN}4.{Colors.END} SHA-512")

                algo_choice = input(f"\n{Colors.YELLOW}Choose algorithm:{Colors.END} ").strip()
                algo_map = {"1": "md5", "2": "sha1", "3": "sha256", "4": "sha512"}
                algorithm = algo_map.get(algo_choice, "sha256")

                try:
                    computed_hash = self.hash_file(file_path, algorithm)

                    if computed_hash.lower() == expected_hash.lower():
                        self.print_success("✓ File integrity verified - Hashes match!")
                    else:
                        self.print_error("✗ File integrity check failed - Hashes do NOT match!")
                        print(f"\n{Colors.YELLOW}Expected:{Colors.END}  {expected_hash}")
                        print(f"{Colors.YELLOW}Computed:{Colors.END}  {computed_hash}")
                except Exception as e:
                    self.print_error(f"Verification failed: {e}")

            elif choice == "4":
                hash1 = input(f"\n{Colors.YELLOW}Enter first hash:{Colors.END} ")
                hash2 = input(f"{Colors.YELLOW}Enter second hash:{Colors.END} ")

                if hash1.lower() == hash2.lower():
                    self.print_success("✓ Hashes match!")
                else:
                    self.print_error("✗ Hashes do NOT match!")

    def main_menu(self):
        """Main menu"""
        self.print_header(f"CRYPTOKIT v{VERSION}")
        print(f"{Colors.DIM}Multi-Method Encryption Tool{Colors.END}")

        while True:
            print(f"\n{Colors.BOLD}Main Menu:{Colors.END}")
            print(f"{Colors.CYAN}1.{Colors.END} Symmetric Encryption")
            print(f"{Colors.CYAN}2.{Colors.END} Asymmetric Encryption")
            print(f"{Colors.CYAN}3.{Colors.END} Classic Ciphers")
            print(f"{Colors.CYAN}4.{Colors.END} Password-Based Encryption")
            print(f"{Colors.CYAN}5.{Colors.END} Hashing & Verification")
            print(f"{Colors.CYAN}6.{Colors.END} Key Management")
            print(f"{Colors.CYAN}7.{Colors.END} About")
            print(f"{Colors.CYAN}0.{Colors.END} Exit")

            choice = input(f"\n{Colors.YELLOW}Enter choice:{Colors.END} ").strip()

            if choice == "0":
                print(f"\n{Colors.GREEN}Thanks for using CryptoKit!{Colors.END}")
                break
            elif choice == "1":
                self.symmetric_menu()
            elif choice == "2":
                self.asymmetric_menu()
            elif choice == "3":
                self.classic_ciphers_menu()
            elif choice == "4":
                self.password_based_menu()
            elif choice == "5":
                self.hashing_menu()
            elif choice == "6":
                self.key_management_menu()
            elif choice == "7":
                self.show_about()
            else:
                self.print_error("Invalid choice")

    def show_about(self):
        """Show about information"""
        self.print_header("ABOUT CRYPTOKIT")
        print(f"{Colors.BOLD}Version:{Colors.END} {VERSION}")
        print(f"{Colors.BOLD}Purpose:{Colors.END} Educational multi-method encryption tool")
        print(f"\n{Colors.BOLD}Supported Features:{Colors.END}")
        print(f"  {Colors.GREEN}Symmetric:{Colors.END} AES-256-GCM, ChaCha20, DES, 3DES, Blowfish")
        print(f"  {Colors.GREEN}Asymmetric:{Colors.END} RSA (2048/4096), ECC (secp256r1/secp384r1)")
        print(f"  {Colors.GREEN}Classic:{Colors.END} Caesar, Vigenere, ROT13")
        print(f"  {Colors.GREEN}Password:{Colors.END} PBKDF2 (600k iterations) with AES-256-GCM")
        print(f"  {Colors.GREEN}Hashing:{Colors.END} MD5, SHA-1, SHA-256, SHA-512, SHA3, BLAKE2")
        print(f"  {Colors.GREEN}Utilities:{Colors.END} File integrity, compression, key management")
        print(f"\n{Colors.BOLD}Storage:{Colors.END} {BASE_DIR}")
        print(f"\n{Colors.YELLOW}Dependencies:{Colors.END}")
        print(f"  cryptography: {'✓ Installed' if HAS_CRYPTOGRAPHY else '✗ Missing'}")
        print(f"  pycryptodome: {'✓ Installed' if HAS_PYCRYPTODOME else '✗ Missing'}")

        if not HAS_CRYPTOGRAPHY or not HAS_PYCRYPTODOME:
            print(f"\n{Colors.RED}Install missing dependencies:{Colors.END}")
            print(f"  pip3 install cryptography pycryptodome")


def main():
    """Main entry point"""
    print(f"""
{Colors.BOLD}{Colors.CYAN}
╔═══════════════════════════════════════════════════════════════╗
║              CryptoKit - Multi-Method Encryption              ║
║                   v{VERSION} - Educational Tool                  ║
╚═══════════════════════════════════════════════════════════════╝
{Colors.END}
""")

    # Check dependencies
    if not HAS_CRYPTOGRAPHY:
        print(f"{Colors.RED}✗ Missing required library: cryptography{Colors.END}")
        print(f"{Colors.YELLOW}Install: pip3 install cryptography{Colors.END}\n")
        sys.exit(1)

    # Warn about optional dependencies
    if not HAS_PYCRYPTODOME:
        print(f"{Colors.YELLOW}⚠ Optional library missing: pycryptodome{Colors.END}")
        print(f"{Colors.YELLOW}  DES/3DES/Blowfish will be unavailable{Colors.END}")
        print(f"{Colors.YELLOW}  Install: pip3 install pycryptodome{Colors.END}\n")

    try:
        kit = CryptoKit()
        kit.main_menu()
    except KeyboardInterrupt:
        print(f"\n\n{Colors.YELLOW}Interrupted by user{Colors.END}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Colors.RED}Fatal error: {e}{Colors.END}")
        sys.exit(1)


if __name__ == "__main__":
    main()
