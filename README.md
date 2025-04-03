# Porcupine File Encryption
Porcupine is a file encryption tool that uses the AES-256 algorithm to encrypt and decrypt files. It is designed to be simple and easy to use, with a focus on security. It uses Rust's `aes_gcm` crate for encryption and decryption, and `argon2` for password hashing. For secure password input, it uses `rpassword` to read passwords from the terminal without echoing them. The project is built using Rust and is cross-platform compatible.
## Features
- AES-256 encryption
- Argon2 password hashing
- File encryption and decryption
- Simple command-line interface
- Cross-platform compatibility
## Installation
To install Porcupine, clone the repository and build the project using Cargo:
```bash
git clone https://github.com/tchello45/porcupine.git
cd porcupine
cargo build --release
```
This will create an executable file in the `target/release` directory.
## Usage
To encrypt a file, use the following command:
```bash
./target/release/porcupine encrypt <input_file> -o <output_file>
```
To decrypt a file, use the following command:
```bash
./target/release/porcupine decrypt <input_file> -o <output_file>
```
The default output file name is the same as the input file.
## License
This project is licensed under the MIT License. See the [LICENSE.md](LICENSE.md) file for details.