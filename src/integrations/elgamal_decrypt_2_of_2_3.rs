use crate::integrations::util::*;
use crate::proto::{DecryptRequest, KeyType, ProtocolType};
use tokio::spawn;
use tonic::Request;

#[tokio::test]
async fn test() {
    spawn(server());

    let client_a = AuthClient::connect("a", 2).await;
    let client_b = AuthClient::connect("b", 3).await;

    let mut group = Group::create(
        "g",
        2,
        vec![client_a, client_b],
        0,
        ProtocolType::Elgamal,
        KeyType::Decrypt,
    )
    .await;

    let plaintext = Vec::from("hello");

    let ciphertext = call_c_api(|error| unsafe {
        meesign_crypto::c_api::encrypt(
            plaintext.as_ptr(),
            plaintext.len(),
            group.key.as_ptr(),
            group.key.len(),
            error,
        )
    })
    .unwrap();

    for decisions in &[
        [None, Some(true)],
        [Some(true), None],
        [Some(true), Some(false)],
        [Some(false), Some(true)],
        [Some(true), Some(true)],
    ] {
        group.parties[0]
            .connection()
            .decrypt(Request::new(DecryptRequest {
                name: "abcd".to_string(),
                group_id: group.identifier.clone(),
                data: ciphertext.clone(),
                data_type: "text/plain".to_string(),
            }))
            .await
            .unwrap();

        let results;
        (group, results) = group.run_protocols(decisions).await;

        for client in &group.parties {
            assert_eq!(results.get(&client.device_id).unwrap(), &plaintext);
        }
    }
}
