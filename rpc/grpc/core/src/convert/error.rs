use crate::from;
use crate::protowire;

// ----------------------------------------------------------------------------
// rpc_core to protowire
// ----------------------------------------------------------------------------

from!(item: sahyadri_rpc_core::RpcError, protowire::RpcError, { Self { message: item.to_string() } });
from!(item: &sahyadri_rpc_core::RpcError, protowire::RpcError, { Self { message: item.to_string() } });

// ----------------------------------------------------------------------------
// protowire to rpc_core
// ----------------------------------------------------------------------------

from!(item: &protowire::RpcError, sahyadri_rpc_core::RpcError, { sahyadri_rpc_core::RpcError::from(item.message.to_string()) });
