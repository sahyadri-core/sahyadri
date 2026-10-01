globalThis.WebSocket = require('websocket').w3cwebsocket; // W3C WebSocket module shim

const sahyadri = require('../sahyadri/sahyadri_wasm');
const { parseArgs, guardRpcIsSynced } = require("../utils");
const {
    RpcClient, RegistryUnitSet, Address, Encoding, RegistryUnitOrdering,
    PaymentOutputs, PaymentOutput,
    XPrivateKey,
    TransactionInput,
    Transaction,
    signTransaction,
    MutableTransaction,
    RegistryUnitEntries,
    NetworkType,
    minimumTransactionFee,
    adjustTransactionForFee,
    Sequence,
} = sahyadri;
sahyadri.init_console_panic_hook();

(async () => {
    const {
        encoding,
        address,
        networkType,
    } = parseArgs();

    const rpc = new RpcClient({
        url : "127.0.0.1",
        encoding,
        networkId
    });

    console.log(`Connecting to ${rpc.url}`)
    await rpc.connect();
    await guardRpcIsSynced(rpc);

    // let res = await rpc.getBlockTemplate({
    //     extraData:[],
    //     payAddress:"sahyadri:qrwee7xc2qw5whq8qzv82qjld6zunwy46lsy3hueej5kvgfwvamhswy03lsyh"
    // });
    // console.log("res", res.block.header.blueWork);

    // return

    const info = await rpc.getInfo();
    console.log("info", info);

    const addr = address ?? "sahyadritest:qz7ulu4c25dh7fzec9zjyrmlhnkzrg4wmf89q7gzr3gfrsj3uz6xjceef60sd";

    const addresses = [
        addr,
        //new Address("sahyadritest:qz7ulu4c25dh7fzec9zjyrmlhnkzrg4wmf89q7gzr3gfrsj3uz6xjceef60sd")
    ];

    console.log("\ngetting REGISTRY_UNITs...", addresses);
    // const registry_unitsByAddress = await rpc.getRegistryUnitsByAddresses({addresses});

    const registry_units = await rpc.getRegistryUnitsByAddresses({ addresses });

    const amount = 1000n;
    // const registry_unitSelection = await registry_unitSet.select(amount + 100n, RegistryUnitOrdering.AscendingAmount);
    //
    // console.log("registry_unit_selection.amount", registry_unitSelection.amount)
    // console.log("registry_unit_selection.totalAmount", registry_unitSelection.totalAmount)
    // // const registry_units = registry_unitSelection.registry_units;
    // console.log("registry_units[0].data.outpoint", registry_units[0]?.data.outpoint)
    // console.log("registry_units.*.data.outpoint", registry_units.map(a => a.data.outpoint))
    // console.log("registry_units.*.data.entry", registry_units.map(a => a.data.entry))

    const priorityFee = 0n;
    const changeAddress = addr;
    // let change = registry_unit_selection.totalAmount - amount - priorityFee;
    // if (change > 500){
    //     outputItems.push(new Output(
    //         change_address,
    //         change
    //     ))
    // }

    const outputs = [
        [
            addr,
            amount
        ]
    ];

    const registry_unitEntryList = [];
    const inputs = registry_units.map((registry_unit, sequence) => {
        registry_unitEntryList.push(registry_unit.data);

        return new TransactionInput({
            previousOutpoint: registry_unit.data.outpoint,
            signatureScript: [],
            sequence,
            sigOpCount: 0
        });
    });

    const registry_unitEntries = new RegistryUnitEntries(registry_unitEntryList);

    console.log("inputs", inputs);
    console.log("outputs", outputs);
    console.log("registry_unitEntries:", registry_unitEntries.items);

    // let outputs = [
    //     new sahyadri.TransactionOutput(300n, new sahyadri.ScriptPublicKey(0, keypair3.publicKey)),
    //     {
    //         value: 300n,
    //         scriptPublicKey : new sahyadri.ScriptPublicKey(0, keypair3.publicKey)
    //     },
    // ];

    let transaction = new Transaction({
        inputs,
        outputs,
        lockTime: 0,
        subnetworkId: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        version: 0,
        gas: 0,
        payload: [],
    });

    console.log("transaction", transaction)

    const minimumFee = minimumTransactionFee(transaction, networkType);

    console.log("minimumFee:", minimumFee);

    const xKey = new XPrivateKey(
        "kprv5y2qurMHCsXYrNfU3GCihuwG3vMqFji7PZXajMEqyBkNh9UZUJgoHYBLTKu1eM4MvUtomcXPQ3Sw9HZ5ebbM4byoUciHo1zrPJBQfqpLorQ",
        false,
        0n
    );

    const private_key = xKey.receiveKey(0);

    let mtx = new MutableTransaction(transaction, registry_unitEntries);
    const adjustTransactionResult = adjustTransactionForFee(mtx, changeAddress, priorityFee);
    console.log("adjustTransactionResult", adjustTransactionResult)
    mtx = signTransaction(mtx, [private_key], true);
    console.log("before submit mtx.id", mtx.id)
    transaction = mtx.toRpcTransaction();

    let result = await rpc.submitTransaction({ transaction, allowOrphan: false });

    console.log("result", result)

    await rpc.disconnect();
})();
