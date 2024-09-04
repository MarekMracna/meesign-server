use crate::integrations::util::*;
use crate::proto::{KeyType, ProtocolType, SignRequest};
use frost_secp256k1::{Signature, VerifyingKey};
use serde_json;
use tokio::spawn;
use tonic::Request;

#[tokio::test]
async fn test() {
    spawn(server());

    let client_a = AuthClient::connect("a", 1).await;
    let client_b = AuthClient::connect("b", 1).await;
    let client_c = AuthClient::connect("c", 1).await;

    let mut group = Group::create(
        "g",
        2,
        vec![client_a, client_b, client_c],
        0,
        ProtocolType::Frost,
        KeyType::SignChallenge,
    )
    .await;

    let pk: VerifyingKey = serde_json::from_slice(&group.key).unwrap();

    let data = Vec::from("hello");

    for decisions in &[
        [Some(true), Some(true), None],
        [Some(true), None, Some(true)],
        [None, Some(true), Some(true)],
        [Some(true), Some(true), Some(false)],
        [Some(true), Some(false), Some(true)],
        [Some(false), Some(true), Some(true)],
    ] {
        group.parties[0]
            .connection()
            .sign(Request::new(SignRequest {
                name: "abcd".to_string(),
                group_id: group.identifier.clone(),
                data: data.clone(),
            }))
            .await
            .unwrap();

        let results;
        (group, results) = group.run_protocols(decisions).await;

        let result = results.get(&group.parties[0].device_id).unwrap();
        for client in &group.parties {
            assert_eq!(results.get(&client.device_id).unwrap(), result);
        }

        let signature: Signature = serde_json::from_slice(&result).unwrap();
        assert!(pk.verify(&data, &signature).is_ok());
    }
}
