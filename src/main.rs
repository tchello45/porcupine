use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::{
    Aes256Gcm,
    aead::{Aead, AeadCore, Key, KeyInit, OsRng},
};
use argon2::Argon2;
use argon2::password_hash::SaltString;
use clap::{Parser, Subcommand};
use rpassword;
use std::fs;
use std::io::Write;

#[derive(Parser)]
#[command(author, version, about)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Encrypt a file
    Encrypt {
        /// Input file
        input: String,

        /// Output file (optional, default: input)
        #[arg(short, long)]
        output: Option<String>,
    },
    /// Decrypt a file
    Decrypt {
        /// Encrypted input file
        input: String,

        /// Output file (optional, default: input)
        #[arg(short, long)]
        output: Option<String>,
    },
}

fn encrypt(data: &[u8], key: &Key<Aes256Gcm>, nonce: &[u8]) -> Vec<u8> {
    let nonce: &GenericArray<
        u8,
        aes_gcm::aes::cipher::typenum::UInt<
            aes_gcm::aes::cipher::typenum::UInt<
                aes_gcm::aes::cipher::typenum::UInt<
                    aes_gcm::aes::cipher::typenum::UInt<
                        aes_gcm::aes::cipher::typenum::UTerm,
                        aes_gcm::aead::consts::B1,
                    >,
                    aes_gcm::aead::consts::B1,
                >,
                aes_gcm::aead::consts::B0,
            >,
            aes_gcm::aead::consts::B0,
        >,
    > = GenericArray::from_slice(nonce);
    let cipher: aes_gcm::AesGcm<
        aes_gcm::aes::Aes256,
        aes_gcm::aes::cipher::typenum::UInt<
            aes_gcm::aes::cipher::typenum::UInt<
                aes_gcm::aes::cipher::typenum::UInt<
                    aes_gcm::aes::cipher::typenum::UInt<
                        aes_gcm::aes::cipher::typenum::UTerm,
                        aes_gcm::aead::consts::B1,
                    >,
                    aes_gcm::aead::consts::B1,
                >,
                aes_gcm::aead::consts::B0,
            >,
            aes_gcm::aead::consts::B0,
        >,
    > = Aes256Gcm::new(key);
    cipher.encrypt(&nonce, data).expect("Encryption failed")
}
fn decrypt(data: &[u8], key: &Key<Aes256Gcm>, nonce: &[u8]) -> Vec<u8> {
    let nonce: &GenericArray<
        u8,
        aes_gcm::aes::cipher::typenum::UInt<
            aes_gcm::aes::cipher::typenum::UInt<
                aes_gcm::aes::cipher::typenum::UInt<
                    aes_gcm::aes::cipher::typenum::UInt<
                        aes_gcm::aes::cipher::typenum::UTerm,
                        aes_gcm::aead::consts::B1,
                    >,
                    aes_gcm::aead::consts::B1,
                >,
                aes_gcm::aead::consts::B0,
            >,
            aes_gcm::aead::consts::B0,
        >,
    > = GenericArray::from_slice(nonce);
    let cipher: aes_gcm::AesGcm<
        aes_gcm::aes::Aes256,
        aes_gcm::aes::cipher::typenum::UInt<
            aes_gcm::aes::cipher::typenum::UInt<
                aes_gcm::aes::cipher::typenum::UInt<
                    aes_gcm::aes::cipher::typenum::UInt<
                        aes_gcm::aes::cipher::typenum::UTerm,
                        aes_gcm::aead::consts::B1,
                    >,
                    aes_gcm::aead::consts::B1,
                >,
                aes_gcm::aead::consts::B0,
            >,
            aes_gcm::aead::consts::B0,
        >,
    > = Aes256Gcm::new(key);
    cipher.decrypt(&nonce, data).expect("Decryption failed")
}

fn generate_key(password: &[u8], salt: &[u8; 12]) -> Key<Aes256Gcm> {
    let mut key: [u8; 32] = [0u8; 32];
    Argon2::default()
        .hash_password_into(password, salt, &mut key)
        .expect("Hashing failed");
    key.into()
}

fn generate_salt() -> [u8; 12] {
    let salt: SaltString = SaltString::generate(&mut OsRng);
    let salt_bytes: &[u8] = salt.as_str().as_bytes();
    let mut salt_array: [u8; 12] = [0u8; 12];
    salt_array.copy_from_slice(&salt_bytes[..12]);
    salt_array
}

fn encrypt_file(input_file: &str, output_file: &str, password: &[u8]) {
    // Generate a random salt
    let salt: [u8; 12] = generate_salt();
    // Generate a key from the password and salt
    let key: GenericArray<u8, _> = generate_key(password, &salt);
    let nonce: GenericArray<
        u8,
        aes_gcm::aes::cipher::typenum::UInt<
            aes_gcm::aes::cipher::typenum::UInt<
                aes_gcm::aes::cipher::typenum::UInt<
                    aes_gcm::aes::cipher::typenum::UInt<
                        aes_gcm::aes::cipher::typenum::UTerm,
                        aes_gcm::aead::consts::B1,
                    >,
                    aes_gcm::aead::consts::B1,
                >,
                aes_gcm::aead::consts::B0,
            >,
            aes_gcm::aead::consts::B0,
        >,
    > = Aes256Gcm::generate_nonce(OsRng);

    let data: Vec<u8> = fs::read(input_file).expect("Unable to read input file");
    let ciphertext: Vec<u8> = encrypt(&data, &key, &nonce);
    let mut output: fs::File = fs::File::create(output_file).expect("Unable to create output file");
    output.write_all(&nonce).expect("Unable to write nonce");
    output.write_all(&salt).expect("Unable to write salt");
    output
        .write_all(&ciphertext)
        .expect("Unable to write ciphertext");

    println!("File encrypted successfully.");
}

fn decrypt_file(input_file: &str, output_file: &str, password: &[u8]) {
    let data: Vec<u8> = fs::read(input_file).expect("Unable to read input file");
    let nonce_slice: &[u8] = &data[..12];
    let nonce: &GenericArray<
        u8,
        aes_gcm::aes::cipher::typenum::UInt<
            aes_gcm::aes::cipher::typenum::UInt<
                aes_gcm::aes::cipher::typenum::UInt<
                    aes_gcm::aes::cipher::typenum::UInt<
                        aes_gcm::aes::cipher::typenum::UTerm,
                        aes_gcm::aead::consts::B1,
                    >,
                    aes_gcm::aead::consts::B1,
                >,
                aes_gcm::aead::consts::B0,
            >,
            aes_gcm::aead::consts::B0,
        >,
    > = GenericArray::from_slice(nonce_slice);
    let salt_slice: &[u8] = &data[12..24];
    let salt: &[u8; 12] = salt_slice.try_into().expect("Slice with incorrect length");
    let ciphertext: &[u8] = &data[24..];
    let key: GenericArray<u8, _> = generate_key(password, salt);
    let plaintext: Vec<u8> = decrypt(ciphertext, &key, &nonce);
    let mut output: fs::File = fs::File::create(output_file).expect("Unable to create output file");
    output
        .write_all(&plaintext)
        .expect("Unable to write plaintext");
    println!("File decrypted successfully.");
}

fn main() {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Encrypt { input, output } => {
            let out_file = output.clone().unwrap_or(format!("{input}"));
            println!("Encrypting: {input} -> {out_file}");

            let password: String = rpassword::prompt_password("Password: ").unwrap();
            let password: &[u8] = password.as_bytes();
            encrypt_file(input, &out_file, password);
        }
        Commands::Decrypt { input, output } => {
            let out_file = output.clone().unwrap_or(format!("{input}"));
            println!("Decrypting: {input} -> {out_file}");

            let password: String = rpassword::prompt_password("Password: ").unwrap();
            let password: &[u8] = password.as_bytes();
            decrypt_file(input, &out_file, password);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env::temp_dir;

    #[test]
    fn test_encrypt_decrypt() {
        let password: &[u8] = b"password";
        let salt: [u8; 12] = generate_salt();
        let key: GenericArray<u8, _> = generate_key(password, &salt);
        let nonce = [0u8; 12];
        let data: &[u8] = b"Hello, world!";
        let ciphertext: Vec<u8> = encrypt(data, &key, &nonce);
        let decrypted_data: Vec<u8> = decrypt(&ciphertext, &key, &nonce);
        assert_eq!(data, decrypted_data.as_slice());
    }

    #[test]
    fn test_generate_salt() {
        let salt: [u8; 12] = generate_salt();
        assert_eq!(salt.len(), 12);
    }

    #[test]
    fn test_generate_key() {
        let password: &[u8] = b"password";
        let salt: [u8; 12] = generate_salt();
        let key: GenericArray<u8, _> = generate_key(password, &salt);
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_encrypt_file() {
        let input_file = temp_dir().join("test_input.txt");
        let output_file = temp_dir().join("test_output.txt");
        let password: &[u8] = b"password";
        fs::write(&input_file, b"Hello, world!").expect("Unable to write input file");
        encrypt_file(
            input_file.to_str().unwrap(),
            output_file.to_str().unwrap(),
            password,
        );
        let encrypted_data: Vec<u8> = fs::read(&output_file).expect("Unable to read output file");
        assert!(encrypted_data.len() > 0);
        fs::remove_file(&input_file).expect("Unable to remove input file");
        fs::remove_file(&output_file).expect("Unable to remove output file");
    }
}
