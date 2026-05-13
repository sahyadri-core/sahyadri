use super::method::{DropFn, Method, MethodTrait, RoutingPolicy};
use crate::{
    connection::Connection,
    connection_handler::ServerContext,
    error::{GrpcServerError, GrpcServerResult},
};
use sahyadri_grpc_core::{
    ops::SahyadridPayloadOps,
    protowire::{SahyadridRequest, SahyadridResponse},
};
use std::fmt::Debug;
use std::{collections::HashMap, sync::Arc};

pub type SahyadridMethod = Method<ServerContext, Connection, SahyadridRequest, SahyadridResponse>;
pub type DynSahyadridMethod = Arc<dyn MethodTrait<ServerContext, Connection, SahyadridRequest, SahyadridResponse>>;
pub type SahyadridDropFn = DropFn<SahyadridRequest, SahyadridResponse>;
pub type SahyadridRoutingPolicy = RoutingPolicy<SahyadridRequest, SahyadridResponse>;

/// An interface providing methods implementations and a fallback "not implemented" method
/// actually returning a message with a "not implemented" error.
///
/// The interface can provide a method clone for every [`SahyadridPayloadOps`] variant for later
/// processing of related requests.
///
/// It is also possible to directly let the interface itself process a request by invoking
/// the `call()` method.
pub struct Interface {
    server_ctx: ServerContext,
    methods: HashMap<SahyadridPayloadOps, DynSahyadridMethod>,
    method_not_implemented: DynSahyadridMethod,
}

impl Interface {
    pub fn new(server_ctx: ServerContext) -> Self {
        let method_not_implemented = Arc::new(Method::new(|_, _, sahyadrid_request: SahyadridRequest| {
            Box::pin(async move {
                match sahyadrid_request.payload {
                    Some(ref request) => Ok(SahyadridResponse {
                        id: sahyadrid_request.id,
                        payload: Some(SahyadridPayloadOps::from(request).to_error_response(GrpcServerError::MethodNotImplemented.into())),
                    }),
                    None => Err(GrpcServerError::InvalidRequestPayload),
                }
            })
        }));
        Self { server_ctx, methods: Default::default(), method_not_implemented }
    }

    pub fn method(&mut self, op: SahyadridPayloadOps, method: SahyadridMethod) {
        let method: DynSahyadridMethod = Arc::new(method);
        if self.methods.insert(op, method).is_some() {
            panic!("RPC method {op:?} is declared multiple times")
        }
    }

    pub fn replace_method(&mut self, op: SahyadridPayloadOps, method: SahyadridMethod) {
        let method: DynSahyadridMethod = Arc::new(method);
        let _ = self.methods.insert(op, method);
    }

    pub fn set_method_properties(
        &mut self,
        op: SahyadridPayloadOps,
        tasks: usize,
        queue_size: usize,
        routing_policy: SahyadridRoutingPolicy,
    ) {
        self.methods.entry(op).and_modify(|x| {
            let method: Method<ServerContext, Connection, SahyadridRequest, SahyadridResponse> =
                Method::with_properties(x.method_fn(), tasks, queue_size, routing_policy);
            let method: Arc<dyn MethodTrait<ServerContext, Connection, SahyadridRequest, SahyadridResponse>> = Arc::new(method);
            *x = method;
        });
    }

    pub async fn call(
        &self,
        op: &SahyadridPayloadOps,
        connection: Connection,
        request: SahyadridRequest,
    ) -> GrpcServerResult<SahyadridResponse> {
        self.methods.get(op).unwrap_or(&self.method_not_implemented).call(self.server_ctx.clone(), connection, request).await
    }

    pub fn get_method(&self, op: &SahyadridPayloadOps) -> DynSahyadridMethod {
        self.methods.get(op).unwrap_or(&self.method_not_implemented).clone()
    }
}

impl Debug for Interface {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Interface").finish()
    }
}
