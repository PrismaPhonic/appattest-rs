use appattest_rs::assertion::Assertion;
use base64::{engine::general_purpose, Engine};
use serde::Deserialize;
use sha2::{Digest, Sha256};

#[derive(Deserialize)]
struct ClientData {
    challenge: String,
}

fn main() {
    let client_data_json = r#"{"challenge": "5b3b2303-e650-4a56-a9ec-33e3e2a90d14"}"#
        .as_bytes()
        .to_vec();
    let app_id = "<APPLE_TEAM_ID>.<APPLE_APP_ID>"; // replace this with yours. E.g 9000738UU8.auth.iphone.com
    let public_key_base64 =
        "BLROJkpk8NoHVHAnkLOKWUrc4MhyMkATpDyDwjEk82o+uf+KCQiDoHZdlcJ1ff5HPgK7Jd/pTA3cyKOq5MYM6Gs=";
    let public_key_byte = general_purpose::STANDARD
        .decode(public_key_base64)
        .expect("unable to decode public key");

    let previous_counter = 0;
    let stored_challenge = "5b3b2303-e650-4a56-a9ec-33e3e2a90d14";
    let base64_cbor_data = "omlzaWduYXR1cmVYRjBEAiAImFuY4+UbGZ5/ZbjAJpjQ3bd8GxaKFpMEo58WMEUGbwIgaqdDJnVS8/3oJCz16O5Zp4Qga5g6zrFF7eoiYEWkdtNxYXV0aGVudGljYXRvckRhdGFYJaRc2WwGuoniZEqtF+kolObjxcczFdDxbrhJR/nT8ehTQAAAAAI=";

    // Convert from base64 CBOR to Assertion
    let mut buf = [0u8; 192];
    let assertion_result = Assertion::from_base64(base64_cbor_data, &mut buf);
    let client_data = serde_json::from_slice::<ClientData>(&client_data_json).unwrap();

    // 1. Compute clientDataHash as the SHA256 hash of clientData.
    let mut hasher = Sha256::new();
    hasher.update(&client_data_json);
    let client_data_hash = hasher.finalize();

    match assertion_result {
        Ok(assertion) => {
            match assertion.verify(
                client_data_hash,
                &client_data.challenge,
                app_id,
                public_key_byte,
                previous_counter,
                stored_challenge,
            ) {
                Ok(_) => println!("Verification successful!"),
                Err(e) => println!("Verification failed: {:?}", e),
            }
        }
        Err(e) => println!("Failed to decode and create assertion: {:?}", e),
    }
}
