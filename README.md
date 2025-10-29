## nockchain-tx

(WIP) Rust implementation that can target wasm of transaction operations (signing, verification) for the nockchain blockchain. 


Tentative equivalence with hoon based nockchain-wallet CLI methods as per tests below (will integrate them later). Notably, signing transactions, signing messages, deriving keys from seeds, deriving child keys, signing hashes etc.

---

\(See: https://github.com/bigbizze/nockchain-schnorr-rust\)
\(See: https://github.com/bigbizze/nockchain-math-core\)



---

```rs
use bs58::encode as base58_encode;
use hex::encode as hex_encode;
use ibig::UBig;
use nockchain_math_core::belt::PRIME;
use nockchain_schnorr_rust::{
    sign_message,
    util::serialize_point,
    ExtendedPrivateKey, ExtendedPublicKey, Signature, WalletMnemonic,
};
use nockchain_tx::{hash_noun, Lock, Noun, Seed, SimpleNote, Spend, Tip5Digest, ToNoun, TransactionBuilder};
use nockvm::mem::NockStack;
use nockvm::noun::{Atom as VmAtom, Noun as VmNoun};
use nockvm::serialization::{cue, jam};
use std::path::PathBuf;
use std::process::Command;

const TEST_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

fn setup_cli_wallet() {
    let _ = Command::new("nockchain-wallet")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .env("NO_COLOR", "1")
        .args(["--new", "import-keys", "--seedphrase", TEST_MNEMONIC, "--version", "0"])
        .output()
        .expect("failed to import keys to CLI wallet");
}

#[test]
fn master_key_matches_cli_export() {
    let mnemonic = WalletMnemonic::from_phrase(TEST_MNEMONIC).unwrap();
    let seed = mnemonic.seed("");
    let master = ExtendedPrivateKey::from_seed(&seed, 0).unwrap();

    assert_eq!(
        hex_encode(master.secret_key().to_be_bytes()),
        "54d89f8a505e75c1b1ecdb0ca7be19524e68370ed0c21eb2d0fb5a3dfad6553b"
    );
    assert_eq!(
        hex_encode(master.chain_code()),
        "6616d5b4b53a6e3932d04eee8dbb042819da1d056d490e15ca6cae30ed39b25e"
    );

    let public_bytes = master.public_key().to_bytes();
    assert_eq!(
        hex_encode(public_bytes),
        "0199504a8a7bc93f083d244623c458410dd300c9ea8c2c822841d5a706285c06ec25595d68b0912d0c80488556f45b95390fa1239e1327643b138caf5c879d9e44cbab87a8dde3147e7102985af71fae78d1141f457adfe23d2c523e5b70c88604"
    );
    assert_eq!(
        master.public_key().to_base58().unwrap(),
        "3Rzu9ga8nUCm3LSiSs6oh4uNYFos8cL6TmwQP8dXMheJTsvwCZjvDKndhU8dKvBvrrU88exM7fTo5WpEG75EwUrSPxgXLC8VhGESektqKUbFFPjTX8b4DJvZ6t9U3L4PGXeK"
    );

    let serialized = serialize_point(master.public_key().as_point());
    assert_eq!(hex_encode(serialized), hex_encode(public_bytes));
}

#[test]
fn child_account_parity() {
    let mnemonic = WalletMnemonic::from_phrase(TEST_MNEMONIC).unwrap();
    let seed = mnemonic.seed("");
    let master = ExtendedPrivateKey::from_seed(&seed, 0).unwrap();
    let path = "m/0".parse().unwrap();
    let child = master.derive_path(&path).unwrap();

    const EXPECTED_CHILD_ADDR: &str =
        "2edZZJn9nB1LHf8Mmo9H5SjxSHVSYZSvqd4wnGmXQAEzZY3uoDPwwcyD3jtvCMu8KytwuNyNSynf3ReGWGXR58Bd8U9bStJz6GtU3E7gFrxtUKhUxYEPFpuqbc7NwzSyFCC2";

    assert_eq!(child.public_key().to_base58().unwrap(), EXPECTED_CHILD_ADDR);
}

#[test]
fn sign_message_matches_cli_hash() {
    setup_cli_wallet();

    let mnemonic = WalletMnemonic::from_phrase(TEST_MNEMONIC).unwrap();
    let seed = mnemonic.seed("");
    let master = ExtendedPrivateKey::from_seed(&seed, 0).unwrap();

    let message = b"test transaction";
    let signature = sign_message(master.secret_key(), message).unwrap();
    let hashed = signature_hash_base58(&signature);
    
    println!("hashed: {}", hashed);
    
    let cli_hash = cli_sign_message_hash("test transaction")
        .expect("nockchain-wallet sign-message should succeed");

    println!("cli hash: {}", cli_hash);

    assert_eq!(hashed, cli_hash);
}

#[test]
fn lib_sign_cli_verify() {
    let mnemonic = WalletMnemonic::from_phrase(TEST_MNEMONIC).unwrap();
    let seed = mnemonic.seed("");
    let master = ExtendedPrivateKey::from_seed(&seed, 0).unwrap();

    let message = b"test verification message";
    let signature = sign_message(master.secret_key(), message).unwrap();

    // Save signature to file for CLI to verify
    let sig_jam = jam_signature_from_words(
        &signature.challenge_words32(),
        &signature.response_words32(),
    );
    let sig_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("test_verify.sig");
    std::fs::write(&sig_path, &sig_jam).expect("failed to write signature file");

    // Get public key in base58
    let pubkey_b58 = master.public_key().to_base58().unwrap();

    // Verify with CLI
    let output = Command::new("nockchain-wallet")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .env("NO_COLOR", "1")
        .args([
            "verify-message",
            "test verification message",
            "-s",
            "test_verify.sig",
            "-p",
            &pubkey_b58,
        ])
        .output()
        .expect("failed to run nockchain-wallet verify-message");

    // Clean up
    std::fs::remove_file(&sig_path).ok();

    assert!(
        output.status.success(),
        "CLI verification failed. stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stdout_lower = stdout.to_lowercase();
    assert!(
        stdout_lower.contains("valid") && stdout_lower.contains("signature"),
        "CLI did not indicate valid signature: {}",
        stdout
    );
}

#[test]
fn cli_sign_lib_verify() {
    let mnemonic = WalletMnemonic::from_phrase(TEST_MNEMONIC).unwrap();
    let seed = mnemonic.seed("");
    let master = ExtendedPrivateKey::from_seed(&seed, 0).unwrap();

    let message = b"cli signature test";

    // Sign with CLI
    let output = Command::new("nockchain-wallet")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .env("NO_COLOR", "1")
        .args(["sign-message", "cli signature test"])
        .output()
        .expect("failed to run nockchain-wallet sign-message");

    assert!(
        output.status.success(),
        "CLI signing failed. stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Load the signature from message.sig
    let sig_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("message.sig");
    let sig_bytes = std::fs::read(&sig_path).expect("failed to read message.sig");

    // Decode signature
    let signature = decode_signature(&sig_bytes, true)
        .or_else(|| decode_signature(&sig_bytes, false))
        .expect("failed to decode CLI signature");

    // Verify with lib
    let pubkey = master.public_key();

    // Debug: try verifying the message as-is
    let is_valid = nockchain_schnorr_rust::verify_message(&pubkey, message, &signature);

    if !is_valid {
        // Debug: compute what digest we get
        let our_digest = nockchain_schnorr_rust::hash_message(message);
        println!("Our digest: {:?}", our_digest);

        // Try with null terminator
        let message_with_null = b"cli signature test\0";
        let is_valid_null = nockchain_schnorr_rust::verify_message(&pubkey, message_with_null, &signature);

        assert!(
            is_valid_null,
            "Lib failed to verify CLI signature even with null terminator. Challenge: {:?}, Response: {:?}",
            signature.challenge_words32(),
            signature.response_words32()
        );
    }
}

#[test]
fn verify_message_roundtrip() {
    let mnemonic = WalletMnemonic::from_phrase(TEST_MNEMONIC).unwrap();
    let seed = mnemonic.seed("");
    let master = ExtendedPrivateKey::from_seed(&seed, 0).unwrap();

    let message = b"roundtrip verification test";

    // Sign with lib
    let signature = sign_message(master.secret_key(), message).unwrap();

    // Verify with lib
    let is_valid = nockchain_schnorr_rust::verify_message(&master.public_key(), message, &signature);
    assert!(is_valid, "Lib failed to verify its own signature");

    // Verify wrong message fails
    let wrong_message = b"different message";
    let is_invalid = nockchain_schnorr_rust::verify_message(&master.public_key(), wrong_message, &signature);
    assert!(!is_invalid, "Lib incorrectly verified wrong message");
}

#[test]
fn lib_sign_hash_matches_cli() {
    setup_cli_wallet();

    let mnemonic = WalletMnemonic::from_phrase(TEST_MNEMONIC).unwrap();
    let seed = mnemonic.seed("");
    let master = ExtendedPrivateKey::from_seed(&seed, 0).unwrap();

    // Create a sample hash to sign
    let sample_digest: Tip5Digest = [
        0x0102030405060708,
        0x1112131415161718,
        0x2122232425262728,
        0x3132333435363738,
        0x4142434445464748,
    ];

    // Sign with library
    let lib_signature = nockchain_schnorr_rust::sign_digest(master.secret_key(), &sample_digest)
        .expect("library sign_digest failed");

    // Convert digest to base58 for CLI
    let hash_base58 = tip5_digest_to_base58(&sample_digest);

    // Sign with CLI
    let cli_output = Command::new("nockchain-wallet")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .env("NO_COLOR", "1")
        .args(["sign-hash", &hash_base58])
        .output()
        .expect("failed to run nockchain-wallet sign-hash");

    assert!(
        cli_output.status.success(),
        "CLI sign-hash failed. stderr: {}",
        String::from_utf8_lossy(&cli_output.stderr)
    );

    // Load the signature from hash.sig (sign-hash saves to hash.sig, not message.sig)
    let sig_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("hash.sig");
    let sig_bytes = std::fs::read(&sig_path).expect("failed to read hash.sig");

    // Decode CLI signature
    let cli_signature = decode_signature(&sig_bytes, true)
        .or_else(|| decode_signature(&sig_bytes, false))
        .expect("failed to decode CLI signature");

    // Compare signatures
    assert_eq!(
        lib_signature.challenge_words32(),
        cli_signature.challenge_words32(),
        "Challenge mismatch between lib and CLI"
    );
    assert_eq!(
        lib_signature.response_words32(),
        cli_signature.response_words32(),
        "Response mismatch between lib and CLI"
    );
}

#[test]
fn cli_sign_hash_lib_verify() {
    setup_cli_wallet();

    let mnemonic = WalletMnemonic::from_phrase(TEST_MNEMONIC).unwrap();
    let seed = mnemonic.seed("");
    let master = ExtendedPrivateKey::from_seed(&seed, 0).unwrap();

    // Create a sample hash to sign
    let sample_digest: Tip5Digest = [
        0x0102030405060708,
        0x1112131415161718,
        0x2122232425262728,
        0x3132333435363738,
        0x4142434445464748,
    ];

    // Convert digest to base58 for CLI
    let hash_base58 = tip5_digest_to_base58(&sample_digest);

    // Sign with CLI
    let cli_output = Command::new("nockchain-wallet")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .env("NO_COLOR", "1")
        .args(["sign-hash", &hash_base58])
        .output()
        .expect("failed to run nockchain-wallet sign-hash");

    assert!(
        cli_output.status.success(),
        "CLI sign-hash failed. stderr: {}",
        String::from_utf8_lossy(&cli_output.stderr)
    );

    // Load the signature from hash.sig (sign-hash saves to hash.sig, not message.sig)
    let sig_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("hash.sig");
    let sig_bytes = std::fs::read(&sig_path).expect("failed to read hash.sig");

    // Decode CLI signature
    let cli_signature = decode_signature(&sig_bytes, true)
        .or_else(|| decode_signature(&sig_bytes, false))
        .expect("failed to decode CLI signature");

    // Verify with library
    let is_valid = nockchain_schnorr_rust::verify_signature(
        &master.public_key(),
        &sample_digest,
        &cli_signature
    );

    assert!(
        is_valid,
        "Library failed to verify CLI signature for hash. Challenge: {:?}, Response: {:?}",
        cli_signature.challenge_words32(),
        cli_signature.response_words32()
    );
}

#[test]
fn lib_sign_hash_cli_verify() {
    setup_cli_wallet();

    let mnemonic = WalletMnemonic::from_phrase(TEST_MNEMONIC).unwrap();
    let seed = mnemonic.seed("");
    let master = ExtendedPrivateKey::from_seed(&seed, 0).unwrap();

    // Create a sample hash to sign
    let sample_digest: Tip5Digest = [
        0x0102030405060708,
        0x1112131415161718,
        0x2122232425262728,
        0x3132333435363738,
        0x4142434445464748,
    ];

    // Sign with library
    let lib_signature = nockchain_schnorr_rust::sign_digest(master.secret_key(), &sample_digest)
        .expect("library sign_digest failed");

    // Save signature to file for CLI to verify
    let sig_jam = jam_signature_from_words(
        &lib_signature.challenge_words32(),
        &lib_signature.response_words32(),
    );
    let sig_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("test_verify_hash.sig");
    std::fs::write(&sig_path, &sig_jam).expect("failed to write signature file");

    // Convert digest to base58 for CLI
    let hash_base58 = tip5_digest_to_base58(&sample_digest);

    // Get public key in base58
    let pubkey_b58 = master.public_key().to_base58().unwrap();

    // Verify with CLI
    let output = Command::new("nockchain-wallet")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .env("NO_COLOR", "1")
        .args([
            "verify-hash",
            &hash_base58,
            "-s",
            "test_verify_hash.sig",
            "-p",
            &pubkey_b58,
        ])
        .output()
        .expect("failed to run nockchain-wallet verify-hash");

    // Clean up
    std::fs::remove_file(&sig_path).ok();

    assert!(
        output.status.success(),
        "CLI verification failed. stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stdout_lower = stdout.to_lowercase();
    assert!(
        stdout_lower.contains("valid") && stdout_lower.contains("signature"),
        "CLI did not indicate valid signature: {}",
        stdout
    );
}

#[test]
fn master_zpub_matches_cli() {
    setup_cli_wallet();

    let mnemonic = WalletMnemonic::from_phrase(TEST_MNEMONIC).unwrap();
    let seed = mnemonic.seed("");
    let master = ExtendedPrivateKey::from_seed(&seed, 0).unwrap();

    // Get zpub from library
    let lib_zpub = master.extended_public_key().unwrap();

    // Get zpub from CLI
    let output = Command::new("nockchain-wallet")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .env("NO_COLOR", "1")
        .args(["show-master-zpub"])
        .output()
        .expect("failed to run nockchain-wallet show-master-zpub");

    assert!(
        output.status.success(),
        "CLI failed to show zpub. stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let cli_zpub = extract_base58_from_output(&output.stdout)
        .expect("failed to extract zpub from CLI output");

    assert_eq!(
        lib_zpub, cli_zpub,
        "Library zpub doesn't match CLI zpub"
    );
}

#[test]
fn master_zprv_matches_cli() {
    setup_cli_wallet();

    let mnemonic = WalletMnemonic::from_phrase(TEST_MNEMONIC).unwrap();
    let seed = mnemonic.seed("");
    let master = ExtendedPrivateKey::from_seed(&seed, 0).unwrap();

    // Get zprv from library
    let lib_zprv = master.extended_private_key().unwrap();

    // Get zprv from CLI
    let output = Command::new("nockchain-wallet")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .env("NO_COLOR", "1")
        .args(["show-master-zprv"])
        .output()
        .expect("failed to run nockchain-wallet show-master-zprv");

    assert!(
        output.status.success(),
        "CLI failed to show zprv. stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let cli_zprv = extract_base58_from_output(&output.stdout)
        .expect("failed to extract zprv from CLI output");

    assert_eq!(
        lib_zprv, cli_zprv,
        "Library zprv doesn't match CLI zprv"
    );
}

#[test]
fn lib_zpub_can_be_imported_to_cli() {
    let mnemonic = WalletMnemonic::from_phrase(TEST_MNEMONIC).unwrap();
    let seed = mnemonic.seed("");
    let master = ExtendedPrivateKey::from_seed(&seed, 0).unwrap();

    // Get zpub from library
    let lib_zpub = master.extended_public_key().unwrap();
    let expected_address = master.public_key().to_base58().unwrap();

    // Save to temp location for import
    let zpub_file = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("test_import.zpub");
    std::fs::write(&zpub_file, &lib_zpub).expect("failed to write zpub file");

    // Import to CLI
    let output = Command::new("nockchain-wallet")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .env("NO_COLOR", "1")
        .args(["--new", "import-keys", "--key", &lib_zpub])
        .output()
        .expect("failed to run nockchain-wallet import-keys");

    // Clean up
    std::fs::remove_file(&zpub_file).ok();

    assert!(
        output.status.success(),
        "CLI failed to import library zpub. stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Verify the imported key produces the same address
    // Need to query with show-master-zpub since import doesn't output address
    let show_output = Command::new("nockchain-wallet")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .env("NO_COLOR", "1")
        .args(["show-master-zpub"])
        .output()
        .expect("failed to run show-master-zpub");

    // Extract address from output (appears after "Corresponding Address:")
    let stdout = String::from_utf8_lossy(&show_output.stdout);
    let mut found_address = String::new();
    let mut capture = false;
    let alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    for line in stdout.lines() {
        if line.contains("Corresponding Address") {
            capture = true;
            continue;
        }
        if capture {
            let base58_part: String = line.trim().chars().take_while(|c| alphabet.contains(*c)).collect();
            if !base58_part.is_empty() {
                found_address.push_str(&base58_part);
            }
            // Stop if we hit a line that starts with a hyphen (next section)
            if line.trim().starts_with('-') && !found_address.is_empty() {
                break;
            }
        }
    }

    assert_eq!(
        found_address, expected_address,
        "Imported zpub doesn't produce expected address"
    );
}

#[test]
fn lib_zprv_can_be_imported_to_cli() {
    let mnemonic = WalletMnemonic::from_phrase(TEST_MNEMONIC).unwrap();
    let seed = mnemonic.seed("");
    let master = ExtendedPrivateKey::from_seed(&seed, 0).unwrap();

    // Get zprv from library
    let lib_zprv = master.extended_private_key().unwrap();
    let expected_address = master.public_key().to_base58().unwrap();

    // Import to CLI
    let output = Command::new("nockchain-wallet")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .env("NO_COLOR", "1")
        .args(["--new", "import-keys", "--key", &lib_zprv])
        .output()
        .expect("failed to run nockchain-wallet import-keys");

    assert!(
        output.status.success(),
        "CLI failed to import library zprv. stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Verify the imported key produces the same address
    // Need to query with show-master-zpub since import doesn't output address
    let show_output = Command::new("nockchain-wallet")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .env("NO_COLOR", "1")
        .args(["show-master-zpub"])
        .output()
        .expect("failed to run show-master-zpub");

    // Extract address from output (appears after "Corresponding Address:")
    let stdout = String::from_utf8_lossy(&show_output.stdout);
    let mut found_address = String::new();
    let mut capture = false;
    let alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    for line in stdout.lines() {
        if line.contains("Corresponding Address") {
            capture = true;
            continue;
        }
        if capture {
            let base58_part: String = line.trim().chars().take_while(|c| alphabet.contains(*c)).collect();
            if !base58_part.is_empty() {
                found_address.push_str(&base58_part);
            }
            // Stop if we hit a line that starts with a hyphen (next section)
            if line.trim().starts_with('-') && !found_address.is_empty() {
                break;
            }
        }
    }

    assert_eq!(
        found_address, expected_address,
        "Imported zprv doesn't produce expected address"
    );
}

#[test]
fn cli_zpub_can_be_parsed_by_lib() {
    setup_cli_wallet();

    // Get zpub from CLI
    let output = Command::new("nockchain-wallet")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .env("NO_COLOR", "1")
        .args(["show-master-zpub"])
        .output()
        .expect("failed to run nockchain-wallet show-master-zpub");

    assert!(
        output.status.success(),
        "CLI failed. stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let cli_zpub = extract_base58_from_output(&output.stdout)
        .expect("failed to extract zpub from CLI output");

    // Parse with library
    let parsed = ExtendedPublicKey::from_extended_str(&cli_zpub)
        .expect("library failed to parse CLI zpub");

    // Verify it produces the expected address
    let mnemonic = WalletMnemonic::from_phrase(TEST_MNEMONIC).unwrap();
    let seed = mnemonic.seed("");
    let master = ExtendedPrivateKey::from_seed(&seed, 0).unwrap();
    let expected_address = master.public_key().to_base58().unwrap();

    assert_eq!(
        parsed.public_key().to_base58().unwrap(),
        expected_address,
        "Parsed zpub doesn't produce expected address"
    );
}

#[test]
fn cli_zprv_can_be_parsed_by_lib() {
    setup_cli_wallet();

    // Get zprv from CLI
    let output = Command::new("nockchain-wallet")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .env("NO_COLOR", "1")
        .args(["show-master-zprv"])
        .output()
        .expect("failed to run nockchain-wallet show-master-zprv");

    assert!(
        output.status.success(),
        "CLI failed. stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let cli_zprv = extract_base58_from_output(&output.stdout)
        .expect("failed to extract zprv from CLI output");

    // Parse with library
    let parsed = ExtendedPrivateKey::from_extended_str(&cli_zprv)
        .expect("library failed to parse CLI zprv");

    // Verify it produces the expected address
    let mnemonic = WalletMnemonic::from_phrase(TEST_MNEMONIC).unwrap();
    let seed = mnemonic.seed("");
    let master = ExtendedPrivateKey::from_seed(&seed, 0).unwrap();
    let expected_address = master.public_key().to_base58().unwrap();

    assert_eq!(
        parsed.public_key().to_base58().unwrap(),
        expected_address,
        "Parsed zprv doesn't produce expected address"
    );
}

#[test]
fn child_extended_keys_match_cli() {
    setup_cli_wallet();

    let mnemonic = WalletMnemonic::from_phrase(TEST_MNEMONIC).unwrap();
    let seed = mnemonic.seed("");
    let master = ExtendedPrivateKey::from_seed(&seed, 0).unwrap();

    // Derive child with library
    let path = "m/0".parse().unwrap();
    let child = master.derive_path(&path).unwrap();
    let lib_child_zpub = child.extended_public_key().unwrap();
    let lib_child_zprv = child.extended_private_key().unwrap();

    // Derive child with CLI - the derive-child command outputs the child keys
    let derive_output = Command::new("nockchain-wallet")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .env("NO_COLOR", "1")
        .args(["derive-child", "0"])
        .output()
        .expect("failed to derive child");

    // Parse derive-child output to extract zpub and zprv
    let stdout = String::from_utf8_lossy(&derive_output.stdout);
    let mut lines = stdout.lines();

    // Find "Extended Public Key:" and extract next lines
    let mut cli_child_zpub = String::new();
    let mut found_pub = false;
    let alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    for line in lines.by_ref() {
        if line.contains("Extended Public Key:") {
            found_pub = true;
            continue;
        }
        if found_pub {
            let base58_part: String = line.trim().chars().take_while(|c| alphabet.contains(*c)).collect();
            if !base58_part.is_empty() {
                cli_child_zpub.push_str(&base58_part);
            }
            if line.trim().starts_with('-') && !cli_child_zpub.is_empty() {
                break;
            }
        }
    }

    // Find "Extended Private Key:" and extract next lines
    let mut cli_child_zprv = String::new();
    let mut found_priv = false;

    for line in stdout.lines() {
        if line.contains("Extended Private Key:") {
            found_priv = true;
            continue;
        }
        if found_priv {
            let base58_part: String = line.trim().chars().take_while(|c| alphabet.contains(*c)).collect();
            if !base58_part.is_empty() {
                cli_child_zprv.push_str(&base58_part);
            }
            if line.trim().starts_with('-') && !cli_child_zprv.is_empty() {
                break;
            }
        }
    }

    assert_eq!(
        lib_child_zpub, cli_child_zpub,
        "Child zpub doesn't match"
    );

    assert_eq!(
        lib_child_zprv, cli_child_zprv,
        "Child zprv doesn't match"
    );
}

#[test]
fn lib_sign_transaction_matches_structure() {
    let mnemonic = WalletMnemonic::from_phrase(TEST_MNEMONIC).unwrap();
    let seed = mnemonic.seed("");
    let master = ExtendedPrivateKey::from_seed(&seed, 0).unwrap();

    // Create a simple transaction
    let public_key = master.public_key();
    let recipient_lock = Lock::single(public_key.clone());
    let note = SimpleNote::new(
        1000,
        [1, 2, 3, 4, 5],  // parent hash
        Lock::single(public_key.clone()),
    );

    // Build and sign transaction with library
    let mut spend = Spend::simple_from_note(recipient_lock, &note, 100)
        .expect("failed to create spend");

    let sig_hash = spend.sig_hash();
    println!("Transaction sig_hash: {:?}", sig_hash);

    spend.sign(master.secret_key()).expect("failed to sign");

    // Verify signature was added
    let signatures: Vec<_> = spend.signatures().collect();
    assert_eq!(signatures.len(), 1, "Expected exactly one signature");

    let sig_entry = &signatures[0];
    assert_eq!(
        sig_entry.public_key.to_bytes(),
        public_key.to_bytes(),
        "Signature public key doesn't match"
    );

    // Verify the signature is valid for the sig_hash
    let is_valid = nockchain_schnorr_rust::verify_signature(
        &sig_entry.public_key,
        &sig_hash,
        &sig_entry.signature
    );
    assert!(is_valid, "Signature verification failed");
}

#[test]
fn lib_sign_transaction_builder() {
    let mnemonic = WalletMnemonic::from_phrase(TEST_MNEMONIC).unwrap();
    let seed = mnemonic.seed("");
    let master = ExtendedPrivateKey::from_seed(&seed, 0).unwrap();

    // Create a transaction using TransactionBuilder
    let public_key = master.public_key();
    let recipient_lock = Lock::single(public_key.clone());

    let seed1 = Seed::simple(
        recipient_lock.clone(),
        500,
        [10, 20, 30, 40, 50],
    );

    let seed2 = Seed::simple(
        recipient_lock,
        400,
        [11, 21, 31, 41, 51],
    );

    let spend = TransactionBuilder::new()
        .with_fee(100)
        .add_seed(seed1)
        .add_seed(seed2)
        .sign_v0(master.secret_key())
        .expect("failed to build and sign transaction");

    // Verify the transaction structure
    assert_eq!(spend.seeds().len(), 2, "Expected 2 seeds");
    assert_eq!(spend.fee(), 100, "Fee mismatch");

    let signatures: Vec<_> = spend.signatures().collect();
    assert_eq!(signatures.len(), 1, "Expected exactly one signature");

    // Verify signature
    let sig_entry = &signatures[0];
    let sig_hash = spend.sig_hash();
    let is_valid = nockchain_schnorr_rust::verify_signature(
        &sig_entry.public_key,
        &sig_hash,
        &sig_entry.signature
    );
    assert!(is_valid, "Transaction signature verification failed");
}

#[test]
fn transaction_sig_hash_deterministic() {
    let mnemonic = WalletMnemonic::from_phrase(TEST_MNEMONIC).unwrap();
    let seed = mnemonic.seed("");
    let master = ExtendedPrivateKey::from_seed(&seed, 0).unwrap();

    // Create identical transactions
    let public_key = master.public_key();
    let recipient_lock = Lock::single(public_key.clone());
    let note = SimpleNote::new(
        1000,
        [1, 2, 3, 4, 5],
        Lock::single(public_key.clone()),
    );

    let spend1 = Spend::simple_from_note(recipient_lock.clone(), &note, 100)
        .expect("failed to create spend1");
    let spend2 = Spend::simple_from_note(recipient_lock, &note, 100)
        .expect("failed to create spend2");

    // Verify sig_hash is deterministic
    assert_eq!(
        spend1.sig_hash(),
        spend2.sig_hash(),
        "Transaction sig_hash should be deterministic"
    );
}

#[test]
fn transaction_signature_deterministic() {
    let mnemonic = WalletMnemonic::from_phrase(TEST_MNEMONIC).unwrap();
    let seed = mnemonic.seed("");
    let master = ExtendedPrivateKey::from_seed(&seed, 0).unwrap();

    // Create and sign identical transactions
    let public_key = master.public_key();
    let recipient_lock = Lock::single(public_key.clone());
    let note = SimpleNote::new(
        1000,
        [1, 2, 3, 4, 5],
        Lock::single(public_key.clone()),
    );

    let mut spend1 = Spend::simple_from_note(recipient_lock.clone(), &note, 100)
        .expect("failed to create spend1");
    spend1.sign(master.secret_key()).expect("failed to sign spend1");

    let mut spend2 = Spend::simple_from_note(recipient_lock, &note, 100)
        .expect("failed to create spend2");
    spend2.sign(master.secret_key()).expect("failed to sign spend2");

    // Extract signatures
    let sig1: Vec<_> = spend1.signatures().collect();
    let sig2: Vec<_> = spend2.signatures().collect();

    assert_eq!(sig1.len(), 1, "Expected 1 signature in spend1");
    assert_eq!(sig2.len(), 1, "Expected 1 signature in spend2");

    // Verify signatures are identical (Schnorr signatures are deterministic)
    assert_eq!(
        sig1[0].signature.challenge_words32(),
        sig2[0].signature.challenge_words32(),
        "Signature challenge should be deterministic"
    );
    assert_eq!(
        sig1[0].signature.response_words32(),
        sig2[0].signature.response_words32(),
        "Signature response should be deterministic"
    );
}

fn signature_hash_base58(signature: &Signature) -> String {
    let signature_noun = signature.to_noun();
    let digest = hash_noun(&signature_noun);
    tip5_digest_to_base58(&digest)
}

fn tip5_digest_to_base58(digest: &Tip5Digest) -> String {
    let ubig = tip5_digest_to_ubig(digest);
    let mut bytes = ubig.to_be_bytes();
    if bytes.is_empty() {
        bytes.push(0);
    }
    base58_encode(bytes).into_string()
}

fn tip5_digest_to_ubig(digest: &Tip5Digest) -> UBig {
    let prime = UBig::from(PRIME);
    digest.iter().enumerate().fold(UBig::from(0u8), |acc, (i, limb)| {
        let term = UBig::from(*limb) * prime.pow(i);
        acc + term
    })
}

fn rip32_utf16_words(message: &str) -> Vec<u32> {
    let mut bytes = Vec::new();
    for unit in message.encode_utf16() {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
    if bytes.is_empty() {
        bytes.push(0);
        bytes.push(0);
    }
    let mut words = Vec::with_capacity((bytes.len() + 3) / 4);
    let mut chunk = [0u8; 4];
    for (idx, byte) in bytes.iter().enumerate() {
        chunk[idx % 4] = *byte;
        if idx % 4 == 3 {
            words.push(u32::from_le_bytes(chunk));
            chunk = [0u8; 4];
        }
    }
    let rem = bytes.len() % 4;
    if rem != 0 {
        for i in rem..4 {
            chunk[i] = 0;
        }
        words.push(u32::from_le_bytes(chunk));
    }
    words
}

fn digest_from_words(words: &[u32]) -> Tip5Digest {
    let atoms: Vec<Noun> = words
        .iter()
        .map(|&word| Noun::atom_u64(word as u64))
        .collect();
    let noun = Noun::list(&atoms);
    hash_noun(&noun)
}

fn cli_sign_message_hash(message: &str) -> Option<String> {
    let output = Command::new("nockchain-wallet")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .env("NO_COLOR", "1")
        .args(["sign-message", "--message", message])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    extract_base58_from_output(stdout.as_bytes())
}

fn extract_base58_from_output(output: &[u8]) -> Option<String> {
    let stdout = String::from_utf8_lossy(output);
    let alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    // Extended keys can be split across multiple lines
    // Look for lines starting with 'zpub' or 'zprv' and collect continuation lines
    let lines: Vec<&str> = stdout.lines().collect();
    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with("zpub") || trimmed.starts_with("zprv") {
            // Collect this line and subsequent lines that are all base58
            let mut result = trimmed.to_string();
            for next_line in lines.iter().skip(i + 1) {
                let next_trimmed = next_line.trim();
                if next_trimmed.is_empty() {
                    break;
                }
                // Extract base58 prefix from line (may have trailing text like " (save for import)")
                let base58_part: String = next_trimmed
                    .chars()
                    .take_while(|c| alphabet.contains(*c))
                    .collect();
                if base58_part.is_empty() {
                    break;
                }
                result.push_str(&base58_part);
                // If line had non-base58 trailing content, we're done
                if base58_part.len() < next_trimmed.len() {
                    break;
                }
            }
            return Some(result);
        }
    }

    // Fallback: look for single-line long base58 strings (for hashes)
    stdout
        .lines()
        .rev()
        .find(|line| {
            let trimmed = line.trim();
            trimmed.len() > 50 && trimmed.chars().all(|c| alphabet.contains(c))
        })
        .map(|line| line.trim().to_string())
}

fn load_cli_signature_from_file() -> Option<Signature> {
    let path: PathBuf = [env!("CARGO_MANIFEST_DIR"), "message.sig"].iter().collect();
    let bytes = std::fs::read(path).ok()?;
    decode_signature(&bytes, true).or_else(|| decode_signature(&bytes, false))
}

fn decode_signature(bytes: &[u8], little_endian: bool) -> Option<Signature> {
    let ubig = if little_endian {
        UBig::from_le_bytes(bytes)
    } else {
        UBig::from_be_bytes(bytes)
    };

    let (mut stack, _) = NockStack::new_((1 << 24), 1 << 16).ok()?;
    let atom = VmAtom::from_ubig(&mut stack, &ubig);
    let noun = cue(&mut stack, atom).ok()?;
    extract_signature(noun)
}

fn extract_signature(noun: VmNoun) -> Option<Signature> {
    // Signature is [challenge response] where both are 8-tuples
    let cell = noun.as_cell().ok()?;
    let challenge = cell.head();
    let response = cell.tail();

    let challenge_words = noun_tuple_to_words32(challenge)?;
    let response_words = noun_tuple_to_words32(response)?;

    let chal = <[u32; 8]>::try_from(challenge_words).ok()?;
    let resp = <[u32; 8]>::try_from(response_words).ok()?;
    Some(Signature::from_words32_le(&chal, &resp))
}

fn jam_signature_from_words(challenge: &[u32; 8], response: &[u32; 8]) -> Vec<u8> {
    let (mut stack, _) = NockStack::new_((1 << 24), 1 << 16).expect("stack allocation failed");

    // Build challenge tuple [w0 [w1 [w2 [w3 [w4 [w5 [w6 w7]]]]]]]
    let mut chal_noun = VmAtom::from_ubig(&mut stack, &UBig::from(challenge[7] as u64)).as_noun();
    for &word in challenge[..7].iter().rev() {
        let atom = VmAtom::from_ubig(&mut stack, &UBig::from(word as u64)).as_noun();
        chal_noun = nockvm::noun::Cell::new(&mut stack, atom, chal_noun).as_noun();
    }

    // Build response tuple [w0 [w1 [w2 [w3 [w4 [w5 [w6 w7]]]]]]]
    let mut resp_noun = VmAtom::from_ubig(&mut stack, &UBig::from(response[7] as u64)).as_noun();
    for &word in response[..7].iter().rev() {
        let atom = VmAtom::from_ubig(&mut stack, &UBig::from(word as u64)).as_noun();
        resp_noun = nockvm::noun::Cell::new(&mut stack, atom, resp_noun).as_noun();
    }

    // Build signature cell [challenge response]
    let sig_noun = nockvm::noun::Cell::new(&mut stack, chal_noun, resp_noun).as_noun();

    // Jam and return
    let jammed = jam(&mut stack, sig_noun);
    jammed.as_ubig(&mut stack).to_le_bytes()
}

fn noun_tuple_to_words32(mut noun: VmNoun) -> Option<Vec<u32>> {
    let mut words = Vec::new();
    // For tuples, we need to traverse 7 cells, then get the last atom
    for _ in 0..7 {
        if let Ok(cell) = noun.as_cell() {
            let atom = cell.head().as_atom().ok()?;
            words.push(atom.as_u64().ok()? as u32);
            noun = cell.tail();
        } else {
            return None;
        }
    }
    // Last element is just an atom (not a cell)
    let atom = noun.as_atom().ok()?;
    words.push(atom.as_u64().ok()? as u32);
    Some(words)
}

fn noun_list_to_words32(mut noun: VmNoun) -> Option<Vec<u32>> {
    let mut words = Vec::new();
    loop {
        if let Ok(cell) = noun.as_cell() {
            let atom = cell.head().as_atom().ok()?;
            words.push(atom.as_u64().ok()? as u32);
            noun = cell.tail();
        } else {
            let atom = noun.as_atom().ok()?;
            if atom.as_u64().ok()? != 0 {
                return None;
            }
            break;
        }
    }
    Some(words)
}

```
