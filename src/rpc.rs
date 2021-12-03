use crate::proto::*;
use crate::proto::mpc_server::{Mpc, MpcServer};
use tonic::{Request, Status, Response};
use tonic::transport::Server;
use crate::State;
use tokio::sync::Mutex;
use crate::task::TaskStatus;

pub struct MPCService {
    state: Mutex<State>
}

impl MPCService {
    pub fn new(state: State) -> Self {
        MPCService { state: Mutex::new(state) }
    }
}

#[tonic::async_trait]
impl Mpc for MPCService {
    async fn register(&self, request: Request<RegistrationRequest>) -> Result<Response<Resp>, Status> {
        let request = request.into_inner();
        let device_id = request.device_id;

        let mut state = self.state.lock().await;
        state.add_device(device_id);

        let resp = Resp {
            variant: Some(resp::Variant::Success("OK".into()))
        };

        Ok(Response::new(resp))
    }

    async fn sign(&self, request: Request<SignRequest>) -> Result<Response<Resp>, Status> {
        let request = request.into_inner();
        let device_ids = request.device_ids;
        let data = request.data;

        let mut state = self.state.lock().await;
        state.add_sign_task(&device_ids, &data);

        let resp = Resp {
            variant: Some(resp::Variant::Success("OK".into()))
        };

        Ok(Response::new(resp))
    }

    async fn get_task(&self, request: Request<TaskRequest>) -> Result<Response<Task>, Status> {
        let request = request.into_inner();
        let task_id = request.task_id;

        let state = self.state.lock().await;
        let data = match state.get_task(task_id) {
            TaskStatus::Waiting(_, data) => task::State::Waiting(data),
            TaskStatus::Finished(data) => task::State::Finished(data),
        };

        let resp = Task {
            task_id,
            state: Some(data),
        };

        Ok(Response::new(resp))
    }

    async fn update_task(&self, request: Request<TaskUpdate>) -> Result<Response<Resp>, Status> {
        let request = request.into_inner();
        let task_id = request.task_id;
        let device_id = request.device_id;

        self.state.lock().await.update_task(task_id, &device_id, &Vec::new());

        let resp = Resp {
            variant: Some(resp::Variant::Success("OK".into()))
        };

        Ok(Response::new(resp))
    }

    async fn get_info(&self, request: Request<InfoRequest>) -> Result<Response<Info>, Status> {
        let request = request.into_inner();
        let device_id = request.device_id;

        let resp = Info {
            task_ids: self.state.lock().await.get_device_tasks(&device_id)
        };

        Ok(Response::new(resp))
    }
}

pub async fn run_rpc(state: State) -> Result<(), String> {
    let addr = "127.0.0.1:1337".parse().unwrap();
    let node = MPCService::new(state);

    Server::builder()
        .add_service(MpcServer::new(node))
        .serve(addr)
        .await
        .unwrap();

    Ok(())
}
