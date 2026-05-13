use crate::protowire::{SahyadridRequest, SahyadridResponse, sahyadrid_request};

impl From<sahyadrid_request::Payload> for SahyadridRequest {
    fn from(item: sahyadrid_request::Payload) -> Self {
        SahyadridRequest { id: 0, payload: Some(item) }
    }
}

impl AsRef<SahyadridRequest> for SahyadridRequest {
    fn as_ref(&self) -> &Self {
        self
    }
}

impl AsRef<SahyadridResponse> for SahyadridResponse {
    fn as_ref(&self) -> &Self {
        self
    }
}

pub mod sahyadrid_request_convert {
    use crate::protowire::*;
    use sahyadri_rpc_core::{RpcError, RpcResult};

    impl_into_sahyadrid_request!(Shutdown);
    impl_into_sahyadrid_request!(SubmitBlock);
    impl_into_sahyadrid_request!(GetBlockTemplate);
    impl_into_sahyadrid_request!(GetBlock);
    impl_into_sahyadrid_request!(GetInfo);

    impl_into_sahyadrid_request!(GetCurrentNetwork);
    impl_into_sahyadrid_request!(GetPeerAddresses);
    impl_into_sahyadrid_request!(GetSink);
    impl_into_sahyadrid_request!(GetMempoolEntry);
    impl_into_sahyadrid_request!(GetMempoolEntries);
    impl_into_sahyadrid_request!(GetConnectedPeerInfo);
    impl_into_sahyadrid_request!(AddPeer);
    impl_into_sahyadrid_request!(SubmitTransaction);
    impl_into_sahyadrid_request!(SubmitTransactionReplacement);
    impl_into_sahyadrid_request!(SubmitAccountTransaction);
    impl_into_sahyadrid_request!(GetSubnetwork);
    impl_into_sahyadrid_request!(GetVirtualChainFromBlock);
    impl_into_sahyadrid_request!(GetBlocks);
    impl_into_sahyadrid_request!(GetBlockCount);
    impl_into_sahyadrid_request!(GetSahyadriDagInfo);
    impl_into_sahyadrid_request!(ResolveFinalityConflict);
    impl_into_sahyadrid_request!(GetHeaders);
    impl_into_sahyadrid_request!(GetUtxosByAddresses);
    impl_into_sahyadrid_request!(GetBalanceByAddress);
    impl_into_sahyadrid_request!(GetBalancesByAddresses);
    impl_into_sahyadrid_request!(GetSinkBlueScore);
    impl_into_sahyadrid_request!(Ban);
    impl_into_sahyadrid_request!(Unban);
    impl_into_sahyadrid_request!(EstimateNetworkHashesPerSecond);
    impl_into_sahyadrid_request!(GetMempoolEntriesByAddresses);
    impl_into_sahyadrid_request!(GetCoinSupply);
    impl_into_sahyadrid_request!(Ping);
    impl_into_sahyadrid_request!(GetMetrics);
    impl_into_sahyadrid_request!(GetConnections);
    impl_into_sahyadrid_request!(GetSystemInfo);
    impl_into_sahyadrid_request!(GetServerInfo);
    impl_into_sahyadrid_request!(GetSyncStatus);
    impl_into_sahyadrid_request!(GetDaaScoreTimestampEstimate);
    impl_into_sahyadrid_request!(GetFeeEstimate);
    impl_into_sahyadrid_request!(GetFeeEstimateExperimental);
    impl_into_sahyadrid_request!(GetCurrentBlockColor);
    impl_into_sahyadrid_request!(GetUtxoReturnAddress);
    impl_into_sahyadrid_request!(GetVirtualChainFromBlockV2);

    impl_into_sahyadrid_request!(NotifyBlockAdded);
    impl_into_sahyadrid_request!(NotifyNewBlockTemplate);
    impl_into_sahyadrid_request!(NotifyUtxosChanged);
    impl_into_sahyadrid_request!(NotifyPruningPointUtxoSetOverride);
    impl_into_sahyadrid_request!(NotifyFinalityConflict);
    impl_into_sahyadrid_request!(NotifyVirtualDaaScoreChanged);
    impl_into_sahyadrid_request!(NotifyVirtualChainChanged);
    impl_into_sahyadrid_request!(NotifySinkBlueScoreChanged);

    macro_rules! impl_into_sahyadrid_request {
        ($name:tt) => {
            paste::paste! {
                impl_into_sahyadrid_request_ex!(sahyadri_rpc_core::[<$name Request>],[<$name RequestMessage>],[<$name Request>]);
            }
        };
    }

    use impl_into_sahyadrid_request;

    macro_rules! impl_into_sahyadrid_request_ex {
        // ($($core_struct:ident)::+, $($protowire_struct:ident)::+, $($variant:ident)::+) => {
        ($core_struct:path, $protowire_struct:ident, $variant:ident) => {
            // ----------------------------------------------------------------------------
            // rpc_core to protowire
            // ----------------------------------------------------------------------------

            impl From<&$core_struct> for sahyadrid_request::Payload {
                fn from(item: &$core_struct) -> Self {
                    Self::$variant(item.into())
                }
            }

            impl From<&$core_struct> for SahyadridRequest {
                fn from(item: &$core_struct) -> Self {
                    Self { id: 0, payload: Some(item.into()) }
                }
            }

            impl From<$core_struct> for sahyadrid_request::Payload {
                fn from(item: $core_struct) -> Self {
                    Self::$variant((&item).into())
                }
            }

            impl From<$core_struct> for SahyadridRequest {
                fn from(item: $core_struct) -> Self {
                    Self { id: 0, payload: Some((&item).into()) }
                }
            }

            // ----------------------------------------------------------------------------
            // protowire to rpc_core
            // ----------------------------------------------------------------------------

            impl TryFrom<&sahyadrid_request::Payload> for $core_struct {
                type Error = RpcError;
                fn try_from(item: &sahyadrid_request::Payload) -> RpcResult<Self> {
                    if let sahyadrid_request::Payload::$variant(request) = item {
                        request.try_into()
                    } else {
                        Err(RpcError::MissingRpcFieldError("Payload".to_string(), stringify!($variant).to_string()))
                    }
                }
            }

            impl TryFrom<&SahyadridRequest> for $core_struct {
                type Error = RpcError;
                fn try_from(item: &SahyadridRequest) -> RpcResult<Self> {
                    item.payload
                        .as_ref()
                        .ok_or(RpcError::MissingRpcFieldError("SahyadriRequest".to_string(), "Payload".to_string()))?
                        .try_into()
                }
            }

            impl From<$protowire_struct> for SahyadridRequest {
                fn from(item: $protowire_struct) -> Self {
                    Self { id: 0, payload: Some(sahyadrid_request::Payload::$variant(item)) }
                }
            }

            impl From<$protowire_struct> for sahyadrid_request::Payload {
                fn from(item: $protowire_struct) -> Self {
                    sahyadrid_request::Payload::$variant(item)
                }
            }
        };
    }
    use impl_into_sahyadrid_request_ex;
}

pub mod sahyadrid_response_convert {
    use crate::protowire::*;
    use sahyadri_rpc_core::{RpcError, RpcResult};

    impl_into_sahyadrid_response!(Shutdown);
    impl_into_sahyadrid_response!(SubmitBlock);
    impl_into_sahyadrid_response!(GetBlockTemplate);
    impl_into_sahyadrid_response!(GetBlock);
    impl_into_sahyadrid_response!(GetInfo);
    impl_into_sahyadrid_response!(GetCurrentNetwork);

    impl_into_sahyadrid_response!(GetPeerAddresses);
    impl_into_sahyadrid_response!(GetSink);
    impl_into_sahyadrid_response!(GetMempoolEntry);
    impl_into_sahyadrid_response!(GetMempoolEntries);
    impl_into_sahyadrid_response!(GetConnectedPeerInfo);
    impl_into_sahyadrid_response!(AddPeer);
    impl_into_sahyadrid_response!(SubmitTransaction);
    impl_into_sahyadrid_response!(SubmitTransactionReplacement);
    impl_into_sahyadrid_response!(SubmitAccountTransaction);
    impl_into_sahyadrid_response!(GetSubnetwork);
    impl_into_sahyadrid_response!(GetVirtualChainFromBlock);
    impl_into_sahyadrid_response!(GetBlocks);
    impl_into_sahyadrid_response!(GetBlockCount);
    impl_into_sahyadrid_response!(GetSahyadriDagInfo);
    impl_into_sahyadrid_response!(ResolveFinalityConflict);
    impl_into_sahyadrid_response!(GetHeaders);
    impl_into_sahyadrid_response!(GetUtxosByAddresses);
    impl_into_sahyadrid_response!(GetBalanceByAddress);
    impl_into_sahyadrid_response!(GetBalancesByAddresses);
    impl_into_sahyadrid_response!(GetSinkBlueScore);
    impl_into_sahyadrid_response!(Ban);
    impl_into_sahyadrid_response!(Unban);
    impl_into_sahyadrid_response!(EstimateNetworkHashesPerSecond);
    impl_into_sahyadrid_response!(GetMempoolEntriesByAddresses);
    impl_into_sahyadrid_response!(GetCoinSupply);
    impl_into_sahyadrid_response!(Ping);
    impl_into_sahyadrid_response!(GetMetrics);
    impl_into_sahyadrid_response!(GetConnections);
    impl_into_sahyadrid_response!(GetSystemInfo);
    impl_into_sahyadrid_response!(GetServerInfo);
    impl_into_sahyadrid_response!(GetSyncStatus);
    impl_into_sahyadrid_response!(GetDaaScoreTimestampEstimate);
    impl_into_sahyadrid_response!(GetFeeEstimate);
    impl_into_sahyadrid_response!(GetFeeEstimateExperimental);
    impl_into_sahyadrid_response!(GetCurrentBlockColor);
    impl_into_sahyadrid_response!(GetUtxoReturnAddress);
    impl_into_sahyadrid_response!(GetVirtualChainFromBlockV2);

    impl_into_sahyadrid_notify_response!(NotifyBlockAdded);
    impl_into_sahyadrid_notify_response!(NotifyNewBlockTemplate);
    impl_into_sahyadrid_notify_response!(NotifyUtxosChanged);
    impl_into_sahyadrid_notify_response!(NotifyPruningPointUtxoSetOverride);
    impl_into_sahyadrid_notify_response!(NotifyFinalityConflict);
    impl_into_sahyadrid_notify_response!(NotifyVirtualDaaScoreChanged);
    impl_into_sahyadrid_notify_response!(NotifyVirtualChainChanged);
    impl_into_sahyadrid_notify_response!(NotifySinkBlueScoreChanged);

    impl_into_sahyadrid_notify_response!(NotifyUtxosChanged, StopNotifyingUtxosChanged);
    impl_into_sahyadrid_notify_response!(NotifyPruningPointUtxoSetOverride, StopNotifyingPruningPointUtxoSetOverride);

    macro_rules! impl_into_sahyadrid_response {
        ($name:tt) => {
            paste::paste! {
                impl_into_sahyadrid_response_ex!(sahyadri_rpc_core::[<$name Response>],[<$name ResponseMessage>],[<$name Response>]);
            }
        };
        ($core_name:tt, $protowire_name:tt) => {
            paste::paste! {
                impl_into_sahyadrid_response_base!(sahyadri_rpc_core::[<$core_name Response>],[<$protowire_name ResponseMessage>],[<$protowire_name Response>]);
            }
        };
    }
    use impl_into_sahyadrid_response;

    macro_rules! impl_into_sahyadrid_response_base {
        ($core_struct:path, $protowire_struct:ident, $variant:ident) => {
            // ----------------------------------------------------------------------------
            // rpc_core to protowire
            // ----------------------------------------------------------------------------

            impl From<RpcResult<$core_struct>> for $protowire_struct {
                fn from(item: RpcResult<$core_struct>) -> Self {
                    item.as_ref().map_err(|x| (*x).clone()).into()
                }
            }

            impl From<RpcError> for $protowire_struct {
                fn from(item: RpcError) -> Self {
                    let x: RpcResult<&$core_struct> = Err(item);
                    x.into()
                }
            }

            impl From<$protowire_struct> for sahyadrid_response::Payload {
                fn from(item: $protowire_struct) -> Self {
                    sahyadrid_response::Payload::$variant(item)
                }
            }

            impl From<$protowire_struct> for SahyadridResponse {
                fn from(item: $protowire_struct) -> Self {
                    Self { id: 0, payload: Some(sahyadrid_response::Payload::$variant(item)) }
                }
            }
        };
    }
    use impl_into_sahyadrid_response_base;

    macro_rules! impl_into_sahyadrid_response_ex {
        ($core_struct:path, $protowire_struct:ident, $variant:ident) => {
            // ----------------------------------------------------------------------------
            // rpc_core to protowire
            // ----------------------------------------------------------------------------

            impl From<RpcResult<&$core_struct>> for sahyadrid_response::Payload {
                fn from(item: RpcResult<&$core_struct>) -> Self {
                    sahyadrid_response::Payload::$variant(item.into())
                }
            }

            impl From<RpcResult<&$core_struct>> for SahyadridResponse {
                fn from(item: RpcResult<&$core_struct>) -> Self {
                    Self { id: 0, payload: Some(item.into()) }
                }
            }

            impl From<RpcResult<$core_struct>> for sahyadrid_response::Payload {
                fn from(item: RpcResult<$core_struct>) -> Self {
                    sahyadrid_response::Payload::$variant(item.into())
                }
            }

            impl From<RpcResult<$core_struct>> for SahyadridResponse {
                fn from(item: RpcResult<$core_struct>) -> Self {
                    Self { id: 0, payload: Some(item.into()) }
                }
            }

            impl_into_sahyadrid_response_base!($core_struct, $protowire_struct, $variant);

            // ----------------------------------------------------------------------------
            // protowire to rpc_core
            // ----------------------------------------------------------------------------

            impl TryFrom<&sahyadrid_response::Payload> for $core_struct {
                type Error = RpcError;
                fn try_from(item: &sahyadrid_response::Payload) -> RpcResult<Self> {
                    if let sahyadrid_response::Payload::$variant(response) = item {
                        response.try_into()
                    } else {
                        Err(RpcError::MissingRpcFieldError("Payload".to_string(), stringify!($variant).to_string()))
                    }
                }
            }

            impl TryFrom<&SahyadridResponse> for $core_struct {
                type Error = RpcError;
                fn try_from(item: &SahyadridResponse) -> RpcResult<Self> {
                    item.payload
                        .as_ref()
                        .ok_or(RpcError::MissingRpcFieldError("SahyadriResponse".to_string(), "Payload".to_string()))?
                        .try_into()
                }
            }
        };
    }
    use impl_into_sahyadrid_response_ex;

    macro_rules! impl_into_sahyadrid_notify_response {
        ($name:tt) => {
            impl_into_sahyadrid_response!($name);

            paste::paste! {
                impl_into_sahyadrid_notify_response_ex!(sahyadri_rpc_core::[<$name Response>],[<$name ResponseMessage>]);
            }
        };
        ($core_name:tt, $protowire_name:tt) => {
            impl_into_sahyadrid_response!($core_name, $protowire_name);

            paste::paste! {
                impl_into_sahyadrid_notify_response_ex!(sahyadri_rpc_core::[<$core_name Response>],[<$protowire_name ResponseMessage>]);
            }
        };
    }
    use impl_into_sahyadrid_notify_response;

    macro_rules! impl_into_sahyadrid_notify_response_ex {
        ($($core_struct:ident)::+, $protowire_struct:ident) => {
            // ----------------------------------------------------------------------------
            // rpc_core to protowire
            // ----------------------------------------------------------------------------

            impl<T> From<Result<(), T>> for $protowire_struct
            where
                T: Into<RpcError>,
            {
                fn from(item: Result<(), T>) -> Self {
                    item
                        .map(|_| $($core_struct)::+{})
                        .map_err(|err| err.into()).into()
                }
            }

        };
    }
    use impl_into_sahyadrid_notify_response_ex;
}
