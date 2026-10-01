#![allow(non_snake_case)]
use cfg_if::cfg_if;
use sahyadri_wallet_macros::declare_typescript_wasm_interface as declare;
use wasm_bindgen::prelude::*;

cfg_if! {
    if #[cfg(any(feature = "wasm32-core", feature = "wasm32-sdk"))] {

        #[wasm_bindgen(typescript_custom_section)]
        const TS_NOTIFY: &'static str = r#"

        /**
         * Events emitted by the {@link RegistryUnitProcessor}.
         * @category Wallet SDK
         */
        export enum RegistryUnitProcessorEventType {
            Connect = "connect",
            Disconnect = "disconnect",
            RegistryUnitIndexNotEnabled = "registry_unit-index-not-enabled",
            SyncState = "sync-state",
            RegistryUnitProcStart = "registry_unit-proc-start",
            RegistryUnitProcStop = "registry_unit-proc-stop",
            RegistryUnitProcError = "registry_unit-proc-error",
            DaaScoreChange = "daa-score-change",
            Pending = "pending",
            Reorg = "reorg",
            Stasis = "stasis",
            Maturity = "maturity",
            Discovery = "discovery",
            Balance = "balance",
            Error = "error",
        }

        /**
         * {@link RegistryUnitProcessor} notification event data map.
         * 
         * @category Wallet API
         */
        export type RegistryUnitProcessorEventMap = {
            "connect": IConnectEvent,
            "disconnect": IDisconnectEvent,
            "registry_unit-index-not-enabled": IRegistryUnitIndexNotEnabledEvent,
            "sync-state": ISyncStateEvent,
            "server-status": IServerStatusEvent,
            "registry_unit-proc-start": undefined,
            "registry_unit-proc-stop": undefined,
            "registry_unit-proc-error": IRegistryUnitProcErrorEvent,
            "daa-score-change": IDaaScoreChangeEvent,
            "pending": IPendingEvent,
            "reorg": IReorgEvent,
            "stasis": IStasisEvent,
            "maturity": IMaturityEvent,
            "discovery": IDiscoveryEvent,
            "balance": IBalanceEvent,
            "error": IErrorEvent
        }

        /**
         * 
         * @category Wallet API
         */

        export type RegistryUnitProcessorEvent<T extends keyof RegistryUnitProcessorEventMap> = {
          [K in T]: {
            type: K,
            data: RegistryUnitProcessorEventMap[K]
          }
        }[T];
        
        /**
         * {@link RegistryUnitProcessor} notification callback type.
         * 
         * This type declares the callback function that is called when notification is emitted
         * from the RegistryUnitProcessor or RegistryUnitContext subsystems.
         * 
         * @see {@link RegistryUnitProcessor}, {@link RegistryUnitContext},
         * 
         * @category Wallet SDK
         */

        export type RegistryUnitProcessorNotificationCallback<E extends keyof RegistryUnitProcessorEventMap = keyof RegistryUnitProcessorEventMap> = (event: RegistryUnitProcessorEvent<E>) => void;
        "#;

        #[wasm_bindgen]
        extern "C" {
            #[wasm_bindgen(typescript_type = "RegistryUnitProcessorEventType | RegistryUnitProcessorEventType[] | string | string[]")]
            pub type RegistryUnitProcessorEventTarget;
            #[wasm_bindgen(extends = js_sys::Function, typescript_type = "RegistryUnitProcessorNotificationCallback")]
            pub type RegistryUnitProcessorNotificationCallback;
            #[wasm_bindgen(extends = js_sys::Function, typescript_type = "string | RegistryUnitProcessorNotificationCallback")]
            pub type RegistryUnitProcessorNotificationTypeOrCallback;
        }
    }
}

cfg_if! {
    if #[cfg(feature = "wasm32-sdk")] {
        #[wasm_bindgen(typescript_custom_section)]
        const TS_NOTIFY: &'static str = r#"

        /**
         * Events emitted by the {@link Wallet}.
         * @category Wallet API
         */
        export enum WalletEventType {
            Connect = "connect",
            Disconnect = "disconnect",
            RegistryUnitIndexNotEnabled = "registry_unit-index-not-enabled",
            SyncState = "sync-state",
            WalletHint = "wallet-hint",
            WalletOpen = "wallet-open",
            WalletCreate = "wallet-create",
            WalletReload = "wallet-reload",
            WalletError = "wallet-error",
            WalletClose = "wallet-close",
            PrvKeyDataCreate = "prv-key-data-create",
            AccountActivation = "account-activation",
            AccountDeactivation = "account-deactivation",
            AccountSelection = "account-selection",
            AccountCreate = "account-create",
            AccountUpdate = "account-update",
            ServerStatus = "server-status",
            RegistryUnitProcStart = "registry_unit-proc-start",
            RegistryUnitProcStop = "registry_unit-proc-stop",
            RegistryUnitProcError = "registry_unit-proc-error",
            DaaScoreChange = "daa-score-change",
            Pending = "pending",
            Reorg = "reorg",
            Stasis = "stasis",
            Maturity = "maturity",
            Discovery = "discovery",
            Balance = "balance",
            Error = "error",
            FeeRate = "fee-rate",
        }

        /**
         * Wallet notification event data map.
         * @see {@link Wallet.addEventListener}
         * @category Wallet API
         */
        export type WalletEventMap = {
            "connect": IConnectEvent,
            "disconnect": IDisconnectEvent,
            "registry_unit-index-not-enabled": IRegistryUnitIndexNotEnabledEvent,
            "sync-state": ISyncStateEvent,
            "wallet-hint": IWalletHintEvent,
            "wallet-open": IWalletOpenEvent,
            "wallet-create": IWalletCreateEvent,
            "wallet-reload": IWalletReloadEvent,
            "wallet-error": IWalletErrorEvent,
            "wallet-close": undefined,
            "prv-key-data-create": IPrvKeyDataCreateEvent,
            "account-activation": IAccountActivationEvent,
            "account-deactivation": IAccountDeactivationEvent,
            "account-selection": IAccountSelectionEvent,
            "account-create": IAccountCreateEvent,
            "account-update": IAccountUpdateEvent,
            "server-status": IServerStatusEvent,
            "registry_unit-proc-start": undefined,
            "registry_unit-proc-stop": undefined,
            "registry_unit-proc-error": IRegistryUnitProcErrorEvent,
            "daa-score-change": IDaaScoreChangeEvent,
            "pending": IPendingEvent,
            "reorg": IReorgEvent,
            "stasis": IStasisEvent,
            "maturity": IMaturityEvent,
            "discovery": IDiscoveryEvent,
            "balance": IBalanceEvent,
            "error": IErrorEvent,
            "fee-rate": IFeeRateEvent,
        }
        
        /**
         * {@link Wallet} notification event interface.
         * @category Wallet API
         */
        export type IWalletEvent<T extends keyof WalletEventMap> = {
            [K in T]: {
                type: K,
                data: WalletEventMap[K]
            }
        }[T];


        /**
         * Wallet notification callback type.
         * 
         * This type declares the callback function that is called when notification is emitted
         * from the Wallet (and the underlying RegistryUnitProcessor or RegistryUnitContext subsystems).
         * 
         * @see {@link Wallet}
         * 
         * @category Wallet API
         */
        export type WalletNotificationCallback<E extends keyof WalletEventMap = keyof WalletEventMap> = (event: IWalletEvent<E>) => void;
        "#;

        #[wasm_bindgen]
        extern "C" {
            #[wasm_bindgen(typescript_type = "WalletEventType | WalletEventType[] | string | string[]")]
            pub type WalletEventTarget;
            #[wasm_bindgen(extends = js_sys::Function, typescript_type = "WalletNotificationCallback")]
            pub type WalletNotificationCallback;
            #[wasm_bindgen(extends = js_sys::Function, typescript_type = "string | WalletNotificationCallback")]
            pub type WalletNotificationTypeOrCallback;
        }
    }
}

declare! {
    IConnectEvent,
    r#"
    /**
     * Emitted by {@link RegistryUnitProcessor} when it negotiates a successful RPC connection.
     * 
     * @category Wallet Events
     */
    export interface IConnectEvent {
        networkId : string;
        url? : string;
    }
    "#,
}

declare! {
    IDisconnectEvent,
    r#"
    /**
     * Emitted by {@link RegistryUnitProcessor} when it disconnects from RPC.
     * 
     * @category Wallet Events
     */
    export interface IDisconnectEvent {
        networkId : string;
        url? : string;
    }
    "#,
}

declare! {
    IRegistryUnitIndexNotEnabledEvent,
    r#"
    /**
     * Emitted by {@link RegistryUnitProcessor} when it detects that connected node does not have REGISTRY_UNIT index enabled.
     * 
     * @category Wallet Events
     */
    export interface IRegistryUnitIndexNotEnabledEvent {
        url? : string;
    }
    "#,
}

declare! {
    ISyncStateEvent,
    r#"

    /**
     * 
     * @category Wallet Events
     */
    export interface ISyncState {
        event : string;
        data? : ISyncProofEvent | ISyncHeadersEvent | ISyncBlocksEvent | ISyncRegistryUnitSyncEvent | ISyncTrustSyncEvent;
    }
    
    /**
     * 
     * @category Wallet Events
     */
    export interface ISyncStateEvent {
        syncState : ISyncState;
    }
    "#,
}

#[cfg(feature = "wasm32-sdk")]
declare! {
    IWalletHintEvent,
    r#"
    /**
     * Emitted by {@link Wallet} when it opens and contains an optional anti-phishing 'hint' set by the user.
     * 
     * @category Wallet Events
     */
    export interface IWalletHintEvent {
        hint? : string;
    }
    "#,
}

#[cfg(feature = "wasm32-sdk")]
declare! {
    IWalletOpenEvent,
    r#"
    /**
     * Emitted by {@link Wallet} when the wallet is successfully opened.
     * 
     * @category Wallet Events
     */
    export interface IWalletOpenEvent {
        walletDescriptor : IWalletDescriptor;
        accountDescriptors : IAccountDescriptor[];
    }
    "#,
}

#[cfg(feature = "wasm32-sdk")]
declare! {
    IFeeRateEvent,
    r#"
    /**
     * Emitted by {@link Wallet} when the fee rate changes.
     * 
     * @category Wallet Events
     */
    export interface IFeeRateEvent {
        priority: {
            feerate: bigint,
            seconds: bigint,
        },
        normal: {
            feerate: bigint,
            seconds: bigint,
        },
        low: {
            feerate: bigint,
            seconds: bigint,
        },
    }
    "#,
}

#[cfg(feature = "wasm32-sdk")]
declare! {
    IWalletCreateEvent,
    r#"
    /**
     * Emitted by {@link Wallet} when the wallet data storage has been successfully created.
     * 
     * @category Wallet Events
     */
    export interface IWalletCreateEvent {
        walletDescriptor : IWalletDescriptor;
        storageDescriptor : IStorageDescriptor;
    }
    "#,
}

#[cfg(feature = "wasm32-sdk")]
declare! {
    IWalletReloadEvent,
    r#"
    /**
     * Emitted by {@link Wallet} when the wallet is successfully reloaded.
     * 
     * @category Wallet Events
     */
    export interface IWalletReloadEvent {
        walletDescriptor : IWalletDescriptor;
        accountDescriptors : IAccountDescriptor[];
    }
    "#,
}

#[cfg(feature = "wasm32-sdk")]
declare! {
    IWalletErrorEvent,
    r#"
    /**
     * Emitted by {@link Wallet} when an error occurs (for example, the wallet has failed to open).
     * 
     * @category Wallet Events
     */
    export interface IWalletErrorEvent {
        message : string;
    }
    "#,
}

#[cfg(feature = "wasm32-sdk")]
declare! {
    IPrvKeyDataCreateEvent,
    r#"
    /**
     * Emitted by {@link Wallet} when the wallet has created a private key.
     * 
     * @category Wallet Events
     */
    export interface IPrvKeyDataCreateEvent {
        prvKeyDataInfo : IPrvKeyDataInfo;
    }
    "#,
}

#[cfg(feature = "wasm32-sdk")]
declare! {
    IAccountActivationEvent,
    r#"
    /**
     * Emitted by {@link Wallet} when an account has been activated.
     * 
     * @category Wallet Events
     */
    export interface IAccountActivationEvent {
        ids : HexString[];
    }
    "#,
}

#[cfg(feature = "wasm32-sdk")]
declare! {
    IAccountDeactivationEvent,
    r#"
    /**
     * Emitted by {@link Wallet} when an account has been deactivated.
     * 
     * @category Wallet Events
     */
    export interface IAccountDeactivationEvent {
        ids : HexString[];
    }
    "#,
}

#[cfg(feature = "wasm32-sdk")]
declare! {
    IAccountSelectionEvent,
    r#"
    /**
     * Emitted by {@link Wallet} when an account has been selected.
     * This event is used internally in Rust SDK to track currently
     * selected account in the Rust CLI wallet.
     * 
     * @category Wallet Events
     */
    export interface IAccountSelectionEvent {
        id? : HexString;
    }
    "#,
}

#[cfg(feature = "wasm32-sdk")]
declare! {
    IAccountCreateEvent,
    r#"
    /**
     * Emitted by {@link Wallet} when an account has been created.
     * 
     * @category Wallet Events
     */
    export interface IAccountCreateEvent {
        accountDescriptor : IAccountDescriptor;
    }
    "#,
}

#[cfg(feature = "wasm32-sdk")]
declare! {
    IAccountUpdateEvent,
    r#"
    /**
     * Emitted by {@link Wallet} when an account data has been updated.
     * This event signifies a chance in the internal account state that
     * includes new address generation.
     * 
     * @category Wallet Events
     */
    export interface IAccountUpdateEvent {
        accountDescriptor : IAccountDescriptor;
    }
    "#,
}

declare! {
    IServerStatusEvent,
    r#"
    /**
     * Emitted by {@link RegistryUnitProcessor} after successfully opening an RPC
     * connection to the Sahyadri node. This event contains general information
     * about the Sahyadri node.
     * 
     * @category Wallet Events
     */
    export interface IServerStatusEvent {
        networkId : string;
        serverVersion : string;
        isSynced : boolean;
        url? : string;
    }
    "#,
}

declare! {
    IRegistryUnitProcErrorEvent,
    r#"
    /**
     * Emitted by {@link RegistryUnitProcessor} indicating a non-recoverable internal error.
     * If such event is emitted, the application should stop the RegistryUnitProcessor
     * and restart all related subsystem. This event is emitted when the RegistryUnitProcessor
     * encounters a critical condition such as "out of memory".
     * 
     * @category Wallet Events
     */
    export interface IRegistryUnitProcErrorEvent {
        message : string;
    }
    "#,
}

declare! {
    IDaaScoreChangeEvent,
    r#"
    /**
     * Emitted by {@link RegistryUnitProcessor} on DAA score change.
     * 
     * @category Wallet Events
     */
    export interface IDaaScoreChangeEvent {
        currentDaaScore : number;
    }
    "#,
}

declare! {
    IPendingEvent,
    r#"
    /**
     * Emitted by {@link RegistryUnitContext} when detecting a pending transaction.
     * This notification will be followed by the "balance" event.
     * 
     * @category Wallet Events
     */
    export type IPendingEvent = TransactionRecord;
    "#,
}

declare! {
    IReorgEvent,
    r#"
    /**
     * Emitted by {@link RegistryUnitContext} when detecting a reorg transaction condition.
     * A transaction is considered reorg if it has been removed from the REGISTRY_UNIT set
     * as a part of the network reorg process. Transactions notified with this event
     * should be considered as invalid and should be removed from the application state.
     * Associated REGISTRY_UNITs will be automatically removed from the RegistryUnitContext state.
     * 
     * @category Wallet Events
     */
    export type IReorgEvent = TransactionRecord;
    "#,
}

declare! {
    IStasisEvent,
    r#"
    /**
     * Emitted by {@link RegistryUnitContext} when detecting a new coinbase transaction.
     * Transactions are kept in "stasis" for the half of the coinbase maturity DAA period.
     * A wallet should ignore these transactions until they are re-broadcasted
     * via the "pending" event.
     * 
     * @category Wallet Events
     */
    export type IStasisEvent = TransactionRecord;
    "#,
}

declare! {
    IMaturityEvent,
    r#"
    /**
     * Emitted by {@link RegistryUnitContext} when transaction is considered to be confirmed.
     * This notification will be followed by the "balance" event.
     * 
     * @category Wallet Events
     */
    export type IMaturityEvent = TransactionRecord;
    "#,
}

declare! {
    IDiscoveryEvent,
    r#"
    /**
     * Emitted by {@link RegistryUnitContext} when detecting a new transaction during
     * the initialization phase. Discovery transactions indicate that REGISTRY_UNITs
     * have been discovered during the initial REGISTRY_UNIT scan.
     * 
     * When receiving such notifications, the application should check its 
     * internal storage to see if the transaction already exists. If it doesn't,
     * it should create a correspond in record and notify the user of a new
     * transaction.
     * 
     * This event is emitted when an address has existing REGISTRY_UNIT entries that
     * may have been received during previous sessions or while the wallet
     * was offline.
     * 
     * @category Wallet Events
     */
    export type IDiscoveryEvent = TransactionRecord;
    "#,
}

declare! {
    IBalanceEvent,
    r#"
    /**
     * Emitted by {@link RegistryUnitContext} when detecting a balance change.
     * This notification is produced during the REGISTRY_UNIT scan, when RegistryUnitContext
     * detects incoming or outgoing transactions or when transactions
     * change their state (e.g. from pending to confirmed).
     * 
     * @category Wallet Events
     */
    export interface IBalanceEvent {
        id : HexString;
        balance? : IBalance;
    }
    "#,
}

declare! {
    IErrorEvent,
    r#"
    /**
     * Emitted when detecting a general error condition.
     * 
     * @category Wallet Events
     */
    export interface IErrorEvent {
        message : string;
    }
    "#,
}

// ---

declare! {
    ISyncProof,
    r#"
    /**
     * Emitted by {@link RegistryUnitProcessor} when node is syncing and processing cryptographic proofs.
     * 
     * @category Wallet Events
     */
    export interface ISyncProofEvent {
        level : number;
    }
    "#,
}

declare! {
    ISyncHeaders,
    r#"
    /**
     * Emitted by {@link RegistryUnitProcessor} when node is syncing headers as a part of the IBD (Initial Block Download) process.
     * 
     * @category Wallet Events
     */
    export interface ISyncHeadersEvent {
        headers : number;
        progress : number;
    }
    "#,
}

declare! {
    ISyncBlocks,
    r#"
    /**
     * Emitted by {@link RegistryUnitProcessor} when node is syncing blocks as a part of the IBD (Initial Block Download) process.
     * 
     * @category Wallet Events
     */
    export interface ISyncBlocksEvent {
        blocks : number;
        progress : number;
    }
    "#,
}

declare! {
    ISyncRegistryUnitSync,
    r#"
    /**
     * Emitted by {@link RegistryUnitProcessor} when node is syncing the REGISTRY_UNIT set as a part of the IBD (Initial Block Download) process.
     * 
     * @category Wallet Events
     */
    export interface ISyncRegistryUnitSyncEvent {
        chunks : number;
        total : number;
    }
    "#,
}

declare! {
    ISyncTrustSync,
    r#"
    /**
     * Emitted by {@link RegistryUnitProcessor} when node is syncing cryptographic trust data as a part of the IBD (Initial Block Download) process.
     * 
     * @category Wallet Events
     */
    export interface ISyncTrustSyncEvent {
        processed : number;
        total : number;
    }
    "#,
}
