# CryptoKit - Multi-Method Encryption Tool v2.0

![License](https://img.shields.io/badge/license-Educational-blue)
![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey)

A comprehensive, interactive encryption/decryption tool supporting multiple cryptographic methods for educational purposes and authorized security testing.

```
╔═══════════════════════════════════════════════════════════════╗
║              CryptoKit - Multi-Method Encryption              ║
║          Symmetric | Asymmetric | Classic Ciphers             ║
╚═══════════════════════════════════════════════════════════════╝
```

## Features

### 🔐 Symmetric Encryption
- **AES-256-GCM** - Industry standard authenticated encryption
- **ChaCha20** - Modern stream cipher
- **3DES** - Triple DES for legacy compatibility
- **Blowfish** - Fast block cipher
- **DES** - Educational purposes only (insecure)

### 🔑 Asymmetric Encryption
- **RSA** - 2048-bit or 4096-bit key pairs with OAEP padding
- **ECC** - Elliptic Curve Cryptography (secp256r1, secp384r1)
- Key pair generation and management
- Public/private key operations

### 🎓 Classic Ciphers
- **Caesar Cipher** - Substitution cipher with custom shift
- **Vigenere Cipher** - Polyalphabetic substitution
- **ROT13** - Simple letter substitution

### 🔒 Password-Based Encryption
- **PBKDF2** key derivation with 600,000 iterations (OWASP recommended)
- Password-protected file and text encryption
- Built on AES-256-GCM for maximum security
- Salt-based protection against rainbow tables

### #️⃣ Hashing & Verification
- **MD5** - Legacy support (insecure)
- **SHA-1** - Legacy support (insecure)
- **SHA-256** - Recommended for most uses
- **SHA-512** - High-security applications
- **SHA3-256/SHA3-512** - Next-generation SHA
- **BLAKE2b/BLAKE2s** - Fast cryptographic hash
- File integrity verification
- Hash comparison utilities

### 🛠️ Additional Features
- Interactive menu-driven interface
- Text and file encryption support
- Comprehensive key management system
- Secure key storage with metadata
- Base64 encoding for text output
- Color-coded terminal output
- Cross-platform compatibility

## Installation

### Requirements
- Python 3.8 or higher
- pip package manager

### Quick Install

```bash
# Clone the repository
git clone https://github.com/yourusername/cryptokit.git
cd cryptokit

# Install dependencies
pip install cryptography pycryptodome

# Make executable (Linux/macOS)
chmod +x cryptokit.py

# Run the tool
./cryptokit.py
# or
python3 cryptokit.py
```

### Dependencies

```bash
cryptography>=45.0.0    # Core cryptographic functions
pycryptodome>=3.20.0    # DES, 3DES, Blowfish support
```

## Usage

### Launch the Tool

```bash
python3 cryptokit.py
```

### Main Menu

```
Main Menu:
1. Symmetric Encryption
2. Asymmetric Encryption
3. Classic Ciphers
4. Password-Based Encryption
5. Hashing & Verification
6. Key Management
7. About
0. Exit
```

### Quick Start Examples

#### Encrypt Text with Password

```
Main Menu > 4 (Password-Based Encryption)
> 1 (Encrypt Text with Password)
Enter text: My Secret Message
Enter password: YourStrongPassword123

✓ Encrypted text will be displayed in base64 format
```

#### Hash a File for Integrity Verification

```
Main Menu > 5 (Hashing & Verification)
> 2 (Hash File)
Enter file path: document.pdf
> 3 (SHA-256)

✓ SHA-256 hash will be displayed
```

#### Generate RSA Key Pair

```
Main Menu > 2 (Asymmetric Encryption)
> 1 (Generate RSA Key Pair)
> 1 (2048-bit Recommended)
Enter name: my_keypair

✓ Keys saved as my_keypair_private.key and my_keypair_public.key
```

#### Encrypt File with AES

```
Main Menu > 1 (Symmetric Encryption)
> 1 (AES-256-GCM)
> 3 (Encrypt File)
Enter input file: sensitive_data.txt
Enter output file: sensitive_data.txt.enc
Use saved key? n

✓ New key generated and displayed
✓ Option to save key for later decryption
```

## Security Notes

⚠️ **Important Security Considerations:**

1. **Key Storage**: Keys are stored unencrypted in `~/.cryptokit/keys/`. Protect this directory with appropriate file permissions.

2. **Password Strength**: Use strong, unique passwords for password-based encryption. Minimum 12 characters with mixed case, numbers, and symbols.

3. **Algorithm Selection**:
   - ✅ **Recommended**: AES-256-GCM, ChaCha20, SHA-256, RSA 2048+
   - ⚠️ **Deprecated**: DES, MD5, SHA-1 (use only for legacy compatibility)
   - 🎓 **Educational Only**: Caesar, Vigenere, ROT13

4. **File Permissions**: Ensure encrypted files and keys have restricted permissions:
   ```bash
   chmod 600 ~/.cryptokit/keys/*
   ```

5. **RSA Limitations**: RSA can only encrypt data smaller than the key size minus padding (≈190 bytes for 2048-bit). For larger data, use hybrid encryption.

6. **Backup Keys**: Always backup encryption keys securely. Lost keys mean permanently encrypted data.

## Use Cases

### Educational Learning
- Understand different encryption algorithms
- Compare classical vs modern cryptography
- Learn about key derivation and hashing
- Experiment with various cipher modes

### Security Testing
- Test file encryption workflows
- Verify hash-based integrity systems
- Practice key management procedures
- Authorized penetration testing scenarios

### Personal Use
- Encrypt sensitive personal files
- Generate secure key pairs
- Verify downloaded file integrity
- Password-protect confidential documents

## File Structure

```
~/.cryptokit/
├── keys/
│   ├── metadata.json          # Key metadata database
│   ├── *.key                  # Stored encryption keys
│   ├── *_private.key          # Private keys
│   └── *_public.key           # Public keys
```

## Advanced Features

### Key Management

CryptoKit provides comprehensive key management:

- **Generate Keys**: Create symmetric or asymmetric keys
- **Save Keys**: Store keys with metadata (algorithm, date, size)
- **Load Keys**: Retrieve saved keys by name
- **Export Keys**: Copy keys to custom locations
- **Delete Keys**: Remove keys with confirmation
- **List Keys**: View all stored keys with details

### Password-Based Encryption (PBKDF2)

Uses industry-standard key derivation:

- 600,000 iterations (OWASP 2023 recommendation)
- SHA-256 based
- Random 16-byte salt per encryption
- Combined with AES-256-GCM for authenticated encryption

### File Integrity Verification

Multiple verification workflows:

1. **Generate hash** before distribution
2. **Distribute hash** through secure channel
3. **Recipient verifies** file integrity
4. **Compare hashes** to detect tampering

## Troubleshooting

### "Missing required library" Error

```bash
pip install cryptography pycryptodome
```

If using a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # Linux/macOS
# or
venv\Scripts\activate  # Windows
pip install cryptography pycryptodome
```

### Permission Errors

```bash
chmod +x cryptokit.py
# or
chmod 755 cryptokit.py
```

### Module Import Errors

Ensure Python 3.8+ is installed:
```bash
python3 --version
```

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit changes (`git commit -m 'Add AmazingFeature'`)
4. Push to branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## Educational Disclaimer

⚠️ **FOR EDUCATIONAL AND AUTHORIZED TESTING ONLY**

This tool is designed for:
- Learning cryptographic concepts
- Educational demonstrations
- Authorized security testing
- Personal file encryption

**NOT** for:
- Illegal activities
- Unauthorized access
- Production systems without proper security review
- Malicious purposes

Always obtain proper authorization before security testing.

## Algorithm Details

| Algorithm | Type | Key Size | Security Level | Use Case |
|-----------|------|----------|----------------|----------|
| AES-256-GCM | Symmetric | 256-bit | ⭐⭐⭐⭐⭐ High | General encryption (recommended) |
| ChaCha20 | Symmetric | 256-bit | ⭐⭐⭐⭐⭐ High | Mobile/low-power devices |
| 3DES | Symmetric | 168-bit | ⭐⭐⭐ Medium | Legacy compatibility |
| Blowfish | Symmetric | 128-bit | ⭐⭐⭐ Medium | Fast encryption |
| RSA-2048 | Asymmetric | 2048-bit | ⭐⭐⭐⭐ High | Key exchange, signatures |
| RSA-4096 | Asymmetric | 4096-bit | ⭐⭐⭐⭐⭐ High | High-security applications |
| ECC-256 | Asymmetric | 256-bit | ⭐⭐⭐⭐ High | Efficient public-key crypto |
| SHA-256 | Hash | 256-bit | ⭐⭐⭐⭐ High | File integrity, passwords |
| SHA3-256 | Hash | 256-bit | ⭐⭐⭐⭐⭐ High | Next-gen applications |
| BLAKE2 | Hash | Variable | ⭐⭐⭐⭐ High | High-performance hashing |

## Version History

### v2.0.0 (Current)
- Added password-based encryption with PBKDF2
- Comprehensive hashing suite (MD5, SHA1, SHA256, SHA512, SHA3, BLAKE2)
- File integrity verification
- Hash comparison utilities
- Improved error handling
- Enhanced menu system

### v1.0.0
- Initial release
- Symmetric encryption (AES, ChaCha20, DES, 3DES, Blowfish)
- Asymmetric encryption (RSA, ECC)
- Classic ciphers (Caesar, Vigenere, ROT13)
- Key management system
- File and text encryption

## License

This project is licensed for **Educational and Authorized Testing Purposes Only**.

See the LICENSE file for details.

## Acknowledgments

- Built with Python's `cryptography` library
- Uses `pycryptodome` for additional cipher support
- Follows OWASP security recommendations
- Implements NIST-approved algorithms

## Support

For issues, questions, or contributions:
- Open an issue on GitHub
- Check existing documentation
- Review security best practices

## Roadmap

Future enhancements planned:
- [ ] Digital signatures (RSA, ECDSA)
- [ ] Hybrid encryption for large files
- [ ] Key encryption with master password
- [ ] Batch file operations
- [ ] Compression before encryption
- [ ] GUI version
- [ ] Plugin system for custom algorithms

## Links

- [Cryptography Documentation](https://cryptography.io/)
- [OWASP Cryptographic Storage](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [NIST Cryptographic Standards](https://csrc.nist.gov/)

---

**Remember:** Strong cryptography starts with good operational security. Protect your keys, use strong passwords, and always have backups!
