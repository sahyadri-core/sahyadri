globalThis.WebSocket = require('websocket').w3cwebsocket; // W3C WebSocket module shim

let sahyadri = require('../sahyadri/sahyadri_wasm');
const { parseArgs, guardRpcIsSynced } = require("../utils");
let {
    RpcClient, RegistryUnitSet, Address, Encoding, RegistryUnitOrdering,
    PaymentOutputs, PaymentOutput,
    XPrivateKey,
    VirtualTransaction,
    createTransaction,
    signTransaction,
    signScriptHash
} = sahyadri;
sahyadri.init_console_panic_hook();

(async () => {
    const args = parseArgs({});

    // Either NetworkType.Mainnet or NetworkType.Testnet
    const networkType = args.networkType;
    // Either Encoding.Borsh or Encoding.JSON
    const encoding = args.encoding;
    // The sahyadri address that was passed as an argument or a default one
    const address = args.address ?? "sahyadritest:qz7ulu4c25dh7fzec9zjyrmlhnkzrg4wmf89q7gzr3gfrsj3uz6xjceef60sd";

    const rpc = new RpcClient({
        url : "127.0.0.1",
        encoding,
        networkId
    });

    console.log(`# connecting to ${URL}`)
    await rpc.connect();
    console.log(`# connected ...`)
    await guardRpcIsSynced(rpc);

    const info1 = await rpc.getInfo();
    console.log(info1);
    const info2 = await rpc.getInfo();
    console.log(info2);

    const addresses = [address];

    console.log("\nJSON.stringify(addresses):", JSON.stringify(addresses));

    console.log("\ngetting REGISTRY_UNITs...");
    const registry_unitsByAddress = await rpc.getRegistryUnitsByAddresses({ addresses });
    console.log("Creating RegistryUnitSet...");
    //console.log("registry_units_by_address", registry_units_by_address)
    const registry_unitSet = RegistryUnitSet.from(registry_unitsByAddress);

    //console.log("registry_units_by_address", registry_units_by_address)

    const amount = 1000n;

    const registry_unitSelection = await registry_unitSet.select(amount + 100n, RegistryUnitOrdering.AscendingAmount);

    console.log("registry_unit_selection.amount", registry_unitSelection.amount)
    console.log("registry_unit_selection.totalAmount", registry_unitSelection.totalAmount)

    const outputs = [
        [
            address,
            amount
        ]
    ];

    console.log("outputs", outputs)

    const changeAddress = addr;

    const priorityFee = 1500;
    const tx = createTransaction(registry_unitSelection, outputs, changeAddress, priorityFee);
    const scriptHashes = tx.getScriptHashes();
    console.log("scriptHashes", scriptHashes)

    const xKey = new XPrivateKey(
        "kprv5y2qurMHCsXYrNfU3GCihuwG3vMqFji7PZXajMEqyBkNh9UZUJgoHYBLTKu1eM4MvUtomcXPQ3Sw9HZ5ebbM4byoUciHo1zrPJBQfqpLorQ",
        false,
        0n
    );

    const private_key = xKey.receiveKey(0);

    const signatures = scriptHashes.map(hash => signScriptHash(hash, private_key));
    console.log("signatures", signatures)

    const transaction = tx.setSignatures(signatures);
    console.log("transaction", transaction)
    //let transaction = tx.toRpcTransaction();

    const result = await rpc.submitTransaction(transaction);

    console.log("result", result)

    await rpc.disconnect();
})();
