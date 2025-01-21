use base64::engine::general_purpose::STANDARD_NO_PAD as BASE64;
use base64::Engine as _;
use ring::rand::SecureRandom;
use ring::{aead, rand};
use std::collections::HashMap;
use std::error::Error;
use std::fs::read_to_string;
use std::io::Write;
use std::iter::repeat_with;
use std::sync::{Arc, LazyLock, RwLock};

const API_KEYS_FILE: &str = "api-keys.txt";
const MASTER_KEY_FILE: &str = "master.key";
const SALT_LENGTH: usize = 16;
const MASTER_KEY_LENGTH: usize = 32;

type Result<T> = std::result::Result<T, Box<dyn Error>>;

#[allow(clippy::type_complexity)]
static API_KEYS: LazyLock<Arc<RwLock<HashMap<String, Vec<u8>>>>> =
    LazyLock::new(|| Arc::new(RwLock::new(HashMap::new())));

fn get_or_create_master_key() -> Result<aead::LessSafeKey> {
    let key = if let Ok(existing_key) = read_to_string(MASTER_KEY_FILE) {
        BASE64.decode(existing_key.trim())?
    } else {
        let rng = rand::SystemRandom::new();
        let mut key = [0; MASTER_KEY_LENGTH];
        rng.fill(&mut key)
            .map_err(|_| "Failed to generate random key")?;
        let encoded_key = BASE64.encode(key);
        std::fs::write(MASTER_KEY_FILE, encoded_key)?;
        key.to_vec()
    };

    if key.len() != MASTER_KEY_LENGTH {
        return Err("Invalid master key length".into());
    }

    Ok(aead::LessSafeKey::new(
        aead::UnboundKey::new(&aead::AES_256_GCM, &key).map_err(|_| "Invalid key length")?,
    ))
}

fn generate_salt() -> Result<[u8; SALT_LENGTH]> {
    let rng = rand::SystemRandom::new();
    let mut salt = [0u8; SALT_LENGTH];
    rng.fill(&mut salt).map_err(|_| "Failed to generate salt")?;
    Ok(salt)
}

fn encrypt(plaintext: &str, salt: &[u8]) -> Result<String> {
    let key = get_or_create_master_key()?;
    let nonce = aead::Nonce::assume_unique_for_key([0; 12]);
    let mut in_out = plaintext.as_bytes().to_vec();
    key.seal_in_place_append_tag(nonce, aead::Aad::from(salt), &mut in_out)
        .map_err(|_| "Encryption failed")?;
    Ok(BASE64.encode(in_out))
}

fn decrypt(ciphertext: &str, salt: &[u8]) -> Result<String> {
    let key = get_or_create_master_key()?;
    let nonce = aead::Nonce::assume_unique_for_key([0; 12]);
    let mut in_out = BASE64.decode(ciphertext)?;
    let plaintext = key
        .open_in_place(nonce, aead::Aad::from(salt), &mut in_out)
        .map_err(|_| "Decryption failed")?;
    Ok(String::from_utf8(plaintext.to_vec())?)
}

#[allow(unused)]
pub fn create_api_key() -> String {
    repeat_with(fastrand::alphanumeric).take(40).collect()
}

#[allow(unused)]
pub fn load_api_keys() -> Result<()> {
    let stored_keys = match read_to_string(API_KEYS_FILE) {
        Ok(stored_keys) => stored_keys,
        Err(err) if matches!(err.kind(), std::io::ErrorKind::NotFound) => {
            // Assume that an API_KEYS_FILE isn't available
            return Ok(());
        }
        Err(err) => return Err(err.into()),
    };

    let mut api_keys: std::sync::RwLockWriteGuard<'_, HashMap<String, Vec<u8>>> =
        API_KEYS.write()?;

    for line in stored_keys.lines() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let parts: Vec<&str> = line.split(':').collect();
        if parts.len() != 2 {
            return Err("Invalid line format in API keys file".into());
        }

        let salt = BASE64.decode(parts[0])?;
        let encrypted_token = parts[1];

        let decrypted_token = decrypt(encrypted_token, &salt)?;
        api_keys.insert(decrypted_token, salt);
    }

    Ok(())
}

pub fn store_api_key(api_key: &str) -> Result<()> {
    let salt = generate_salt()?;
    let encrypted_key = encrypt(api_key, &salt)?;
    let salt = BASE64.encode(salt);

    let mut f = std::fs::File::options()
        .create(true)
        .append(true)
        .open(API_KEYS_FILE)?;
    writeln!(f, "{salt}:{encrypted_key}")?;

    let mut api_keys = API_KEYS.write()?;
    api_keys.insert(api_key.to_string(), salt.into());

    Ok(())
}

pub fn revoke_api_key(api_key: &str) -> Result<()> {
    let mut api_keys = API_KEYS.write()?;
    api_keys.remove(api_key);

    let mut f = std::fs::File::options()
        .write(true)
        .truncate(true)
        .open(API_KEYS_FILE)?;

    for (key, salt) in api_keys.iter() {
        let encrypted_key = encrypt(key, salt)?;
        let salt = BASE64.encode(salt);
        writeln!(f, "{salt}:{encrypted_key}")?;
    }

    Ok(())
}

pub fn is_key_allowed_access(token: &str) -> Result<bool> {
    let api_keys = API_KEYS.read()?;

    Ok(api_keys.contains_key(token))
}