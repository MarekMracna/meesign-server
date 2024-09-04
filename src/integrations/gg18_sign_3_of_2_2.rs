use crate::integrations::util::*;
use crate::proto::{KeyType, ProtocolType, SignRequest};
use p256::ecdsa::{signature::Verifier as _, Signature, VerifyingKey};
use sha2::Digest as _;
use tokio::spawn;
use tonic::Request;

#[tokio::test]
async fn test() {
    spawn(server());

    let client_a = AuthClient::connect("a", 2).await;
    let client_b = AuthClient::connect("b", 2).await;

    let mut group = Group::create(
        "g",
        3,
        vec![client_a, client_b],
        0,
        ProtocolType::Gg18,
        KeyType::SignChallenge,
    )
    .await;

    let data = b"hello";
    let dgst = sha2::Sha256::digest(data);

    let pk = VerifyingKey::from_sec1_bytes(&group.key).unwrap();

    group.parties[0]
        .connection()
        .sign(Request::new(SignRequest {
            name: "abcd".to_string(),
            group_id: group.identifier.clone(),
            data: dgst.to_vec(),
        }))
        .await
        .unwrap();

    let results;
    (group, results) = group.run_protocols(&[Some(true), Some(true)]).await;

    let result = results.get(&group.parties[0].device_id).unwrap();
    for client in &group.parties {
        assert_eq!(results.get(&client.device_id).unwrap(), result);
    }

    let mut buffer = [0u8; 64];
    buffer.copy_from_slice(&result);
    let signature = Signature::from_bytes(&buffer.into()).unwrap();

    assert!(pk.verify(data, &signature).is_ok());
}
