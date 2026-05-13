const sahyadri = require('../../../../nodejs/sahyadri');

sahyadri.initConsolePanicHook();

(async () => {

    let encrypted = sahyadri.encryptXChaCha20Poly1305("my message", "my_password");
    console.log("encrypted:", encrypted);
    let decrypted = sahyadri.decryptXChaCha20Poly1305(encrypted, "my_password");
    console.log("decrypted:", decrypted);

})();
