//! Notification types and interfaces for wRPC events.

#![allow(non_snake_case)]

use crate::imports::*;
use sahyadri_rpc_macros::declare_typescript_wasm_interface as declare;

#[wasm_bindgen(typescript_custom_section)]
const TS_HEADER: &'static str = r#"

/**
 * RPC notification events.
 * 
 * @see {RpcClient.addEventListener}, {RpcClient.removeEventListener}
 */
export enum RpcEventType {
    Connect = "connect",
    Disconnect = "disconnect",
    BlockAdded = "block-added",
    VirtualChainChanged = "virtual-chain-changed",
    FinalityConflict = "finality-conflict",
    FinalityConflictResolved = "finality-conflict-resolved",
    RegistryChanged = "registry-changed",
    SinkBlueScoreChanged = "sink-blue-score-changed",
    VirtualDaaScoreChanged = "virtual-daa-score-changed",
    PruningPointRegistryUnitSetOverride = "pruning-point-registry_unit-set-override",
    NewBlockTemplate = "new-block-template",
}

/**
 * RPC notification data payload.
 * 
 * @category Node RPC
 */
export type RpcEventData = IBlockAdded 
    | IVirtualChainChanged 
    | IFinalityConflict 
    | IFinalityConflictResolved 
    | IRegistryChanged 
    | ISinkBlueScoreChanged 
    | IVirtualDaaScoreChanged 
    | IPruningPointRegistryUnitSetOverride 
    | INewBlockTemplate;

/**
 * RPC notification event data map.
 * 
 * @category Node RPC
 */
export type RpcEventMap = {
    "connect" : undefined,
    "disconnect" : undefined,
    "block-added" : IBlockAdded,
    "virtual-chain-changed" : IVirtualChainChanged,
    "finality-conflict" : IFinalityConflict,
    "finality-conflict-resolved" : IFinalityConflictResolved,
    "registry-changed" : IRegistryChanged,
    "sink-blue-score-changed" : ISinkBlueScoreChanged,
    "virtual-daa-score-changed" : IVirtualDaaScoreChanged,
    "pruning-point-registry_unit-set-override" : IPruningPointRegistryUnitSetOverride,
    "new-block-template" : INewBlockTemplate,
}

/**
 * RPC notification event.
 * 
 * @category Node RPC
 */
export type RpcEvent = {
    [K in keyof RpcEventMap]: { event: K, data: RpcEventMap[K] }
}[keyof RpcEventMap];

/**
 * RPC notification callback type.
 * 
 * This type is used to define the callback function that is called when an RPC notification is received.
 * 
 * @see {@link RpcClient.subscribeVirtualDaaScoreChanged},
 * {@link RpcClient.subscribeRegistryChanged}, 
 * {@link RpcClient.subscribeVirtualChainChanged},
 * {@link RpcClient.subscribeBlockAdded},
 * {@link RpcClient.subscribeFinalityConflict},
 * {@link RpcClient.subscribeFinalityConflictResolved},
 * {@link RpcClient.subscribeSinkBlueScoreChanged},
 * {@link RpcClient.subscribePruningPointRegistryUnitSetOverride},
 * {@link RpcClient.subscribeNewBlockTemplate},
 * 
 * @category Node RPC
 */
export type RpcEventCallback = (event: RpcEvent) => void;

"#;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(extends = js_sys::Function, typescript_type = "RpcEventCallback")]
    pub type RpcEventCallback;

    #[wasm_bindgen(extends = js_sys::Function, typescript_type = "RpcEventType | string")]
    #[derive(Debug)]
    pub type RpcEventType;

    #[wasm_bindgen(typescript_type = "RpcEventType | string | RpcEventCallback")]
    #[derive(Debug)]
    pub type RpcEventTypeOrCallback;
}

declare! {
    IBlockAdded,
    r#"
    /**
     * Block added notification event is produced when a new
     * block is added to the Sahyadri SahyadriDAG.
     * 
     * @category Node RPC
     */
    export interface IBlockAdded {
        [key: string]: any;
    }
    "#,
}

declare! {
    IVirtualChainChanged,
    r#"
    /**
     * Virtual chain changed notification event is produced when the virtual
     * chain changes in the Sahyadri SahyadriDAG.
     * 
     * @category Node RPC
     */
    export interface IVirtualChainChanged {
        [key: string]: any;
    }
    "#,
}

declare! {
    IFinalityConflict,
    r#"
    /**
     * Finality conflict notification event is produced when a finality
     * conflict occurs in the Sahyadri SahyadriDAG.
     * 
     * @category Node RPC
     */
    export interface IFinalityConflict {
        [key: string]: any;
    }
    "#,
}

declare! {
    IFinalityConflictResolved,
    r#"
    /**
     * Finality conflict resolved notification event is produced when a finality
     * conflict in the Sahyadri SahyadriDAG is resolved.
     * 
     * @category Node RPC
     */
    export interface IFinalityConflictResolved {
        [key: string]: any;
    }
    "#,
}

declare! {
    IRegistryChanged,
    r#"
    /**
     * REGISTRY_UNITs changed notification event is produced when the set
     * of unspent transaction outputs (REGISTRY_UNITs) changes in the
     * Sahyadri SahyadriDAG. The event notification is scoped to the
     * monitored list of addresses specified during the subscription.
     * 
     * @category Node RPC
     */
    export interface IRegistryChanged {
        [key: string]: any;
    }
    "#,
}

declare! {
    ISinkBlueScoreChanged,
    r#"
    /**
     * Sink blue score changed notification event is produced when the blue
     * score of the sink block changes in the Sahyadri SahyadriDAG.
     * 
     * @category Node RPC
     */
    export interface ISinkBlueScoreChanged {
        [key: string]: any;
    }
    "#,
}

declare! {
    IVirtualDaaScoreChanged,
    r#"
    /**
     * Virtual DAA score changed notification event is produced when the virtual
     * Difficulty Adjustment Algorithm (DAA) score changes in the Sahyadri SahyadriDAG.
     * 
     * @category Node RPC
     */
    export interface IVirtualDaaScoreChanged {
        [key: string]: any;
    }
    "#,
}

declare! {
    IPruningPointRegistryUnitSetOverride,
    r#"
    /**
     * Pruning point REGISTRY_UNIT set override notification event is produced when the
     * REGISTRY_UNIT set override for the pruning point changes in the Sahyadri SahyadriDAG.
     * 
     * @category Node RPC
     */
    export interface IPruningPointRegistryUnitSetOverride {
        [key: string]: any;
    }
    "#,
}

declare! {
    INewBlockTemplate,
    r#"
    /**
     * New block template notification event is produced when a new block
     * template is generated for mining in the Sahyadri SahyadriDAG.
     * 
     * @category Node RPC
     */
    export interface INewBlockTemplate {
        [key: string]: any;
    }
    "#,
}
