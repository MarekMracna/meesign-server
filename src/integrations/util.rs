/// Various utilities for testing scenarios with multiple clients
use crate::interfaces;
use crate::proto::{task::TaskState, KeyType, MeeSignClient, ProtocolType, Task};
use crate::state::State;
use lazy_static::lazy_static;
use meesign_crypto::c_api::{Buffer, Protocol, ProtocolId};
use openssl::pkey::{PKey, Private};
use openssl::x509::X509;
use std::collections::HashMap;
use std::ffi::{c_char, CString};
use std::future::Future;
use std::hash::{DefaultHasher, Hash as _, Hasher as _};
use std::iter::repeat;
use std::panic;
use tokio::sync::Mutex;
use tokio_stream::{Stream, StreamExt as _};
use tonic::codegen::Arc;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity};
use tonic::{Request, Streaming};

lazy_static! {
    static ref CA_CERT: X509 =
        X509::from_pem(&std::fs::read("keys/meesign-ca-cert.pem").unwrap()).unwrap();
    static ref CA_KEY: PKey<Private> =
        PKey::private_key_from_pem(&std::fs::read("keys/meesign-ca-key.pem").unwrap()).unwrap();
}

fn unique_test_port() -> u16 {
    let tid = std::thread::current().id();
    let mut hasher = DefaultHasher::new();
    tid.hash(&mut hasher);
    let hash = hasher.finish();
    let port = hash % 10000 + 1024;
    port as u16
}

/// MeeSign server `Future` for testing
///
/// Listens on a port specific to a test.
/// # Examples
/// ```
/// use crate::integrations::util::*;
/// use tokio::spawn;
/// #[tokio::test]
/// async fn test() {
///     spawn(server());
///
///     // Automatically uses the same port as the server
///     let client_a = AuthClient::connect("a", 1).await;
/// }
/// ```
pub async fn server() {
    let state = Arc::new(Mutex::new(State::new()));
    let port = unique_test_port();
    interfaces::grpc::run_grpc(state, "127.0.0.1", port)
        .await
        .unwrap();
}

async fn join_all<F>(tasks: Vec<F>) -> Vec<F::Output>
where
    F: Future + Send + 'static,
    F::Output: Send,
{
    let mut handles = Vec::new();
    for task in tasks {
        handles.push(tokio::spawn(task));
    }
    let mut results = Vec::new();
    for handle in handles {
        results.push(handle.await.unwrap());
    }
    results
}

/// Helper for calling `meesign_crypto::c_api` functions
///
/// # Examples
/// ```
/// use crate::integrations::util::*;
/// use meesign_crypto::c_api;
/// fn finish_protocol(protocol: *mut c_api::Protocol) -> Result<c_api::Buffer, String> {
///     call_c_api(|error| unsafe {
///         c_api::protocol_finish(protocol, error)
///     })
/// }
/// ```
pub fn call_c_api(helper: impl Fn(*mut *mut c_char) -> Buffer) -> Result<Vec<u8>, String> {
    let mut error = std::ptr::null_mut();
    let buf = helper(&mut error);
    if !error.is_null() {
        let cstr = unsafe { CString::from_raw(error) };
        return Err(cstr.into_string().unwrap());
    }
    Ok(buf.to_slice().to_vec())
}

fn map_protocol_id(protocol: &ProtocolType) -> ProtocolId {
    match protocol {
        ProtocolType::Elgamal => ProtocolId::Elgamal,
        ProtocolType::Frost => ProtocolId::Frost,
        ProtocolType::Gg18 => ProtocolId::Gg18,
    }
}

struct Peekable<S: Stream> {
    stream: S,
    peeked: Option<S::Item>,
}

impl<S: Stream + std::marker::Unpin> Peekable<S> {
    pub fn new(stream: S) -> Self {
        Self {
            stream,
            peeked: None,
        }
    }

    pub async fn peek(&mut self) -> &S::Item {
        if self.peeked.is_none() {
            let task = self.stream.next().await;
            self.peeked = task;
        }
        self.peeked.as_ref().unwrap()
    }

    pub async fn next(&mut self) -> S::Item {
        if self.peeked.is_none() {
            return self.stream.next().await.unwrap();
        }
        std::mem::replace(&mut self.peeked, None).unwrap()
    }

    pub async fn skip_while(&mut self, pred: impl Fn(&S::Item) -> bool) {
        while pred(self.peek().await) {
            self.next().await;
        }
    }

    pub async fn take(&mut self, n: usize) -> Vec<S::Item> {
        let mut res = Vec::new();
        for _ in 0..n {
            res.push(self.next().await);
        }
        res
    }
}

/// Wrapper around a basic connection to the server
pub struct Client(MeeSignClient<Channel>);

impl Client {
    /// Connects to the server, optionally authentified
    pub async fn connect(auth: Option<Identity>) -> Self {
        let mut tls = ClientTlsConfig::new()
            .domain_name("meesign.local")
            .ca_certificate(Certificate::from_pem(CA_CERT.to_pem().unwrap()));

        if let Some(auth) = auth {
            tls = tls.identity(auth);
        }

        let port = unique_test_port();

        let channel = Endpoint::try_from(format!("https://meesign.local:{}", port))
            .unwrap()
            .tls_config(tls)
            .unwrap()
            .connect()
            .await
            .unwrap();

        Self(MeeSignClient::new(channel))
    }

    pub fn connection(&mut self) -> &mut MeeSignClient<Channel> {
        &mut self.0
    }
}

/// A group with a generated key
pub struct Group {
    name: String,
    pub identifier: Vec<u8>,
    threshold: u32,
    pub parties: Vec<AuthClient>,
    contexts: HashMap<Vec<u8>, Vec<u8>>,
    protocol: ProtocolType,
    pub key: Vec<u8>,
}

impl Group {
    /// Creates a group and generates a key
    /// `creator_index` points to the client in `parties` who initiates the group creation
    pub async fn create(
        name: &str,
        threshold: u32,
        parties: Vec<AuthClient>,
        creator_index: usize,
        protocol: ProtocolType,
        key_type: KeyType,
    ) -> Self {
        let mut parties = parties;
        let device_ids = parties
            .iter()
            .flat_map(|client| repeat(client.device_id.clone()).take(client.shares))
            .collect();

        parties[creator_index]
            .client
            .connection()
            .group(Request::new(crate::proto::GroupRequest {
                name: name.to_string(),
                device_ids,
                threshold: 2,
                protocol: protocol.into(),
                key_type: key_type.into(),
                note: None,
            }))
            .await
            .unwrap();

        let protocol_id = map_protocol_id(&protocol);

        let keygen_protocol =
            move |s, _| unsafe { meesign_crypto::c_api::protocol_keygen(protocol_id, false, s) };

        let results = join_all(
            parties
                .into_iter()
                .map(|mut client| async move {
                    let res = client.run_protocol(Some(true), None, keygen_protocol).await;
                    (client, res)
                })
                .collect(),
        );

        let mut keys = Vec::new();
        let mut parties = Vec::new();

        let contexts = results
            .await
            .into_iter()
            .map(|(client, (ctx, key))| {
                keys.push(key);
                let id = client.device_id.clone();
                parties.push(client);
                (id, ctx)
            })
            .collect();

        let key = keys[0].clone();
        assert!(keys.iter().all(|k| k == &key));

        let creator_id = parties[creator_index].device_id.clone();

        let groups = parties[creator_index]
            .client
            .connection()
            .get_groups(Request::new(crate::proto::GroupsRequest {
                device_id: Some(creator_id),
            }))
            .await
            .unwrap()
            .into_inner()
            .groups;

        Self {
            name: name.to_string(),
            identifier: groups[0].identifier.clone(),
            threshold,
            parties,
            contexts,
            protocol,
            key,
        }
    }

    /// Runs the rounds of a threshold protocol
    /// The protocol must be initiated first
    pub async fn run_protocols(
        mut self,
        decisions: &[Option<bool>],
    ) -> (Self, HashMap<Vec<u8>, Vec<u8>>) {
        assert_eq!(self.parties.len(), decisions.len());

        let protocol_id = map_protocol_id(&self.protocol);

        let threshold_protocol = move |s, c: Option<Vec<u8>>| unsafe {
            let c = c.unwrap();
            meesign_crypto::c_api::protocol_init(protocol_id, c.as_ptr(), c.len(), s)
        };

        let results = join_all(
            self.parties
                .into_iter()
                .zip(decisions)
                .map(|(mut client, &decision)| {
                    let ctx = self.contexts.get(&client.device_id).unwrap().clone();
                    async move {
                        let (_, res) = client
                            .run_protocol(decision, Some(ctx.clone()), threshold_protocol)
                            .await;
                        (client, res)
                    }
                })
                .collect(),
        );

        self.parties = Vec::new();
        let results = results
            .await
            .into_iter()
            .map(|(client, res)| {
                let id = client.device_id.clone();
                self.parties.push(client);
                (id, res)
            })
            .collect();

        (self, results)
    }
}

struct SendProtocol(*mut Protocol);
unsafe impl Send for SendProtocol {}

/// An authenticated connection for running a protocol
pub struct AuthClient {
    client: Client,
    name: String,
    pub device_id: Vec<u8>,
    shares: usize,
    stream: Peekable<Streaming<Task>>,
}

impl AuthClient {
    /// Creates an authenticated connection to the server and prepares for running a protocol
    pub async fn connect(name: &str, shares: usize) -> Self {
        let mut client = Client::connect(None).await;
        let (device_id, identity) = Self::register(&mut client, name).await;
        let mut client = Client::connect(Some(identity)).await;
        let stream = Peekable::new(Self::subscribe(&mut client).await);

        Self {
            client,
            name: name.to_string(),
            device_id,
            shares,
            stream,
        }
    }

    /// Gets the underlying connection to the server
    pub fn connection(&mut self) -> &mut MeeSignClient<Channel> {
        self.client.connection()
    }

    /// Runs a protocol created by `create_protocol`
    /// `create_protocol` takes the number of shares and an optional context: `ctx`
    pub async fn run_protocol(
        &mut self,
        decision: Option<bool>,
        ctx: Option<Vec<u8>>,
        create_protocol: impl Fn(usize, Option<Vec<u8>>) -> *mut Protocol,
    ) -> (Vec<u8>, Vec<u8>) {
        let task_id = {
            let task = self.stream.peek().await.as_ref().unwrap();
            assert_eq!(task.state(), TaskState::Created);
            task.id.clone()
        };

        assert!(self
            .stream
            .take(self.shares)
            .await
            .into_iter()
            .all(|task| task.unwrap().state() == TaskState::Created));

        if let Some(accept) = decision {
            self.client
                .0
                .decide_task(Request::new(crate::proto::TaskDecision {
                    task: task_id.clone(),
                    accept,
                }))
                .await
                .unwrap();
        }

        let first_task = self.stream.peek().await.clone().unwrap();
        assert_ne!(first_task.state(), TaskState::Created);

        // NOTE: The number of shares the server chose to participate
        let shares_used = first_task.data.len();

        if shares_used == 0 {
            self.stream
                .skip_while(|task| task.as_ref().unwrap().state() != TaskState::Finished)
                .await;
            let tasks = self.stream.take(self.shares).await;
            let res = tasks[0].as_ref().unwrap().data[0].clone();
            assert!(tasks.iter().all(|task| {
                let task = task.as_ref().unwrap();
                task.state() == TaskState::Finished && task.data[0] == res
            }));
            return (Vec::new(), res);
        }

        let protocol = SendProtocol(create_protocol(shares_used, ctx));

        for round in 1..u16::MAX as u32 {
            let mut data = Vec::new();
            for share in 0..shares_used {
                let task = self.stream.next().await.unwrap();

                if task.state() == crate::proto::task::TaskState::Finished {
                    let buf = call_c_api(|error| unsafe {
                        meesign_crypto::c_api::protocol_finish(protocol.0, error)
                    })
                    .unwrap();

                    self.client
                        .0
                        .acknowledge_task(Request::new(crate::proto::TaskAcknowledgement {
                            task_id: task_id.clone(),
                        }))
                        .await
                        .unwrap();

                    // NOTE: Flush the rest of the Tasks
                    for _ in 1..self.shares {
                        let task = self.stream.next().await.unwrap();
                        assert_eq!(task.state(), TaskState::Finished);
                    }

                    return (buf, task.data[0].clone());
                }

                assert_eq!(round, task.round);

                assert_eq!(task.data.len(), shares_used);

                let buf = call_c_api(|error| unsafe {
                    meesign_crypto::c_api::protocol_advance(
                        protocol.0,
                        share,
                        task.data[share].as_ptr(),
                        task.data[share].len(),
                        error,
                    )
                })
                .unwrap();

                data.push(buf);
            }

            for _ in shares_used..self.shares {
                let task = self.stream.next().await.unwrap();
                assert_eq!(task.state(), TaskState::Running);
            }

            self.client
                .0
                .update_task(Request::new(crate::proto::TaskUpdate {
                    task: task_id.clone(),
                    data,
                    attempt: 0,
                }))
                .await
                .unwrap();
        }

        panic!("protocol did not run");
    }

    async fn register(client: &mut Client, name: &str) -> (Vec<u8>, Identity) {
        let (key, csr) = meesign_crypto::auth::gen_key_with_csr(name).unwrap();

        let request = Request::new(crate::proto::RegistrationRequest {
            name: name.to_string(),
            kind: crate::proto::DeviceKind::User.into(),
            csr,
        });

        let response = client.0.register(request).await.unwrap();
        let crate::proto::RegistrationResponse {
            certificate,
            device_id,
        } = response.into_inner();

        // NOTE: Convert cert and key from DER to PEM
        let cert_pem = X509::from_der(&certificate).unwrap().to_pem().unwrap();
        let key = PKey::private_key_from_der(&key).unwrap();
        let key = key.private_key_to_pem_pkcs8().unwrap();

        (device_id, Identity::from_pem(&cert_pem, &key))
    }

    async fn subscribe(client: &mut Client) -> Streaming<Task> {
        client
            .0
            .subscribe_updates(Request::new(crate::proto::SubscribeRequest {}))
            .await
            .unwrap()
            .into_inner()
    }
}
