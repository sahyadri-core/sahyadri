#!/usr/bin/env python3
"""
SAHYADRI SECURITY FIX: Account Transaction Signature Verification Bypass
"""
import os, sys, shutil, re

ROOT = os.getcwd()
BACKUP_DIR = os.path.join(ROOT, "_sig_fix_backups")

def backup(filepath):
    os.makedirs(BACKUP_DIR, exist_ok=True)
    dest = os.path.join(BACKUP_DIR, os.path.relpath(filepath, ROOT))
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    shutil.copy2(filepath, dest)
    print(f"  [BACKUP] {os.path.relpath(filepath, ROOT)}")

def read_file(filepath):
    with open(filepath, "r") as f:
        return f.read()

def write_file(filepath, content):
    with open(filepath, "w") as f:
        f.write(content)

def patch_tx_validation():
    filepath = os.path.join(ROOT, "consensus/src/processes/transaction_validator/tx_validation_in_isolation.rs")
    if not os.path.exists(filepath):
        print(f"  [SKIP] {filepath} not found")
        return False
    content = read_file(filepath)
    backup(filepath)

    # 1a. Add imports
    import_block = "use sahyadri_dilithium::{DilithiumSignature, DilithiumKeyPair, PUBKEY_SIZE, SIG_SIZE, SAHYADRI_MODE};\nuse sha2::{Sha256, Digest};"
    if "use sahyadri_dilithium::" not in content:
        lines = content.split('\n')
        insert_idx = 0
        for i, line in enumerate(lines):
            if line.startswith('use '):
                insert_idx = i + 1
        content = '\n'.join(lines[:insert_idx]) + '\n' + import_block + '\n' + '\n'.join(lines[insert_idx:])
        print("  [OK] Added Dilithium + sha2 imports")
    else:
        print("  [SKIP] Imports already present")

    # 1b. Replace early return
    old = """        // SAHYADRI ACCOUNT MODEL: Skip isolation checks for account transactions
        if tx.inputs.is_empty() && !tx.payload.is_empty() && !tx.is_coinbase() {
            check_transaction_output_value_ranges(tx)?;
            return Ok(());
        }"""
    new = """        // SAHYADRI ACCOUNT MODEL: Verify signature for account transactions
        // Payload: [sender_pubkey:PUBKEY_SIZE][nonce:8][signature:SIG_SIZE]
        if tx.inputs.is_empty() && !tx.payload.is_empty() && !tx.is_coinbase() {
            check_transaction_output_value_ranges(tx)?;
            verify_account_tx_signature(tx)?;
            return Ok(());
        }"""
    if old in content:
        content = content.replace(old, new)
        print("  [OK] Replaced early-return with signature verification call")
    else:
        alt = re.search(
            r'// SAHYADRI ACCOUNT MODEL.*?return Ok\(\(\)\);\n\s*\}',
            content, re.DOTALL)
        if alt:
            content = content[:alt.start()] + new + "\n    }" + content[alt.end():]
            print("  [OK] Replaced using flexible match")
        else:
            print("  [ERROR] Could not find the block. Manual fix needed.")
            return False

    # 1c. Add verification functions
    sig_code = """
// SAHYADRI: Account Transaction Signature Verification
const ACCOUNT_TX_MIN_PAYLOAD: usize = PUBKEY_SIZE + 8 + SIG_SIZE;

fn verify_account_tx_signature(tx: &Transaction) -> TxResult<()> {
    if tx.payload.len() < ACCOUNT_TX_MIN_PAYLOAD {
        return Err(TxRuleError::Message(format!(
            "Account tx payload too small: {} bytes, minimum {}",
            tx.payload.len(), ACCOUNT_TX_MIN_PAYLOAD
        )));
    }

    let sig_start = tx.payload.len() - SIG_SIZE;
    let nonce_start = sig_start - 8;
    let sender_pubkey = &tx.payload[..nonce_start];
    let sig_bytes = &tx.payload[sig_start..];

    if sender_pubkey.len() != PUBKEY_SIZE {
        return Err(TxRuleError::Message(format!(
            "Account tx sender pubkey invalid: {} bytes, expected {}",
            sender_pubkey.len(), PUBKEY_SIZE
        )));
    }

    let signable_payload = &tx.payload[..sig_start];
    let sighash = compute_account_tx_sighash(tx, signable_payload);

    let sig = DilithiumSignature::from_slice(sig_bytes);
    let valid = DilithiumKeyPair::verify(sender_pubkey, &sig, &sighash, b"", SAHYADRI_MODE);
    if !valid {
        return Err(TxRuleError::Message(
            "Account tx Dilithium3 signature verification FAILED".to_string()
        ));
    }
    Ok(())
}

fn compute_account_tx_sighash(tx: &Transaction, signable_payload: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"SAHYADRI_ACCOUNT_TX_V1");
    hasher.update(&tx.version.to_le_bytes());
    for output in &tx.outputs {
        hasher.update(&output.value.to_le_bytes());
        hasher.update(&[output.script_public_key.version]);
        let script = output.script_public_key.script();
        hasher.update(&(script.len() as u64).to_le_bytes());
        hasher.update(script);
    }
    hasher.update(&tx.lock_time.to_le_bytes());
    hasher.update(tx.subnetwork_id.as_bytes());
    hasher.update(&tx.gas.to_le_bytes());
    hasher.update(&(signable_payload.len() as u64).to_le_bytes());
    hasher.update(signable_payload);
    hasher.finalize().into()
}
"""
    if "verify_account_tx_signature" not in content:
        content = content.rstrip() + "\n" + sig_code
        print("  [OK] Added verification functions")
    else:
        print("  [SKIP] Functions already present")

    write_file(filepath, content)
    print(f"  [DONE] {os.path.relpath(filepath, ROOT)}")
    return True

def patch_processor():
    filepath = os.path.join(ROOT, "consensus/src/pipeline/virtual_processor/processor.rs")
    if not os.path.exists(filepath):
        print(f"  [SKIP] {filepath} not found")
        return False
    content = read_file(filepath)
    backup(filepath)

    proc_imports = "use sahyadri_dilithium::{DilithiumSignature, DilithiumKeyPair, PUBKEY_SIZE, SIG_SIZE, SAHYADRI_MODE};\nuse sha2::{Sha256, Digest};"
    if "use sahyadri_dilithium::" not in content:
        lines = content.split('\n')
        insert_idx = 0
        for i, line in enumerate(lines):
            if line.startswith('use '):
                insert_idx = i + 1
        content = '\n'.join(lines[:insert_idx]) + '\n' + proc_imports + '\n' + '\n'.join(lines[insert_idx:])
        print("  [OK] Added imports to processor.rs")

    old_tx = """                    else {
                        for output in tx.outputs.iter() {
                            let amount = output.value as i64;
                            self.account_store.update_balance_batch(&mut batch, &output.script_public_key, amount)
                                .expect("SAHYADRI: CRITICAL \u2014 failed to credit receiver balance, state may be inconsistent");
                        }

                        if tx.payload.len() >= 8 {
                            let nonce_bytes_start = tx.payload.len() - 8;

                            let mut nonce_bytes = [0u8; 8];
                            nonce_bytes.copy_from_slice(&tx.payload[nonce_bytes_start..]);
                            let _expected_nonce = u64::from_le_bytes(nonce_bytes);

                            let sender_script = tx.payload[..nonce_bytes_start].to_vec();

                            let sender_spk = sahyadri_consensus_core::tx::ScriptPublicKey::from_vec(0, sender_script);

                            let mut total_spent: u64 = 0;
                            for output in tx.outputs.iter() {
                                total_spent += output.value;
                            }
                            total_spent += tx.gas;

                            self.account_store.update_balance_batch(&mut batch, &sender_spk, -(total_spent as i64))
                                .expect("SAHYADRI: CRITICAL \u2014 failed to deduct sender balance, state may be inconsistent");
                            self.account_store.increment_nonce_batch(&mut batch, &sender_spk)
                                .expect("SAHYADRI: CRITICAL \u2014 failed to increment sender nonce, state may be inconsistent");
                        }
                    }"""

    new_tx = """                    else {
                        let min_payload = PUBKEY_SIZE + 8 + SIG_SIZE;
                        if tx.payload.len() < min_payload {
                            panic!("SAHYADRI: CRITICAL — account tx undersized payload ({}) in commit_virtual_state", tx.payload.len());
                        }

                        let sig_start = tx.payload.len() - SIG_SIZE;
                        let nonce_start = sig_start - 8;
                        let sender_pubkey = &tx.payload[..nonce_start];
                        let expected_nonce = u64::from_le_bytes(tx.payload[nonce_start..sig_start].try_into().unwrap());
                        let sig_bytes = &tx.payload[sig_start..];
                        let sender_spk = sahyadri_consensus_core::tx::ScriptPublicKey::from_vec(0, sender_pubkey.to_vec());

                        // Defense-in-depth: re-verify Dilithium signature
                        {
                            let signable_payload = &tx.payload[..sig_start];
                            let sighash = {
                                let mut h = Sha256::new();
                                h.update(b"SAHYADRI_ACCOUNT_TX_V1");
                                h.update(&tx.version.to_le_bytes());
                                for output in &tx.outputs {
                                    h.update(&output.value.to_le_bytes());
                                    h.update(&[output.script_public_key.version]);
                                    let s = output.script_public_key.script();
                                    h.update(&(s.len() as u64).to_le_bytes());
                                    h.update(s);
                                }
                                h.update(&tx.lock_time.to_le_bytes());
                                h.update(tx.subnetwork_id.as_bytes());
                                h.update(&tx.gas.to_le_bytes());
                                h.update(&(signable_payload.len() as u64).to_le_bytes());
                                h.update(signable_payload);
                                h.finalize()
                            };
                            let sig = DilithiumSignature::from_slice(sig_bytes);
                            assert!(DilithiumKeyPair::verify(sender_pubkey, &sig, &sighash, b"", SAHYADRI_MODE),
                                "SAHYADRI: CRITICAL — invalid sig in commit_virtual_state");
                        }

                        // Verify nonce
                        let current_nonce = self.account_store.get_nonce(&sender_spk)
                            .expect("SAHYADRI: CRITICAL — failed to read nonce");
                        assert_eq!(expected_nonce, current_nonce,
                            "SAHYADRI: CRITICAL — nonce mismatch (have {}, tx claims {})", current_nonce, expected_nonce);

                        // Verify balance
                        let mut total_spent: u64 = 0;
                        for output in tx.outputs.iter() { total_spent += output.value; }
                        total_spent += tx.gas;
                        let balance = self.account_store.get_balance(&sender_spk)
                            .expect("SAHYADRI: CRITICAL — failed to read balance");
                        assert!((balance as u64) >= total_spent,
                            "SAHYADRI: CRITICAL — insufficient balance (have {}, need {})", balance, total_spent);

                        // All checks passed — apply state changes
                        for output in tx.outputs.iter() {
                            let amount = output.value as i64;
                            self.account_store.update_balance_batch(&mut batch, &output.script_public_key, amount)
                                .expect("SAHYADRI: CRITICAL — failed to credit receiver");
                        }
                        self.account_store.update_balance_batch(&mut batch, &sender_spk, -(total_spent as i64))
                            .expect("SAHYADRI: CRITICAL — failed to deduct sender");
                        self.account_store.increment_nonce_batch(&mut batch, &sender_spk)
                            .expect("SAHYADRI: CRITICAL — failed to increment nonce");
                    }"""

    if old_tx in content:
        content = content.replace(old_tx, new_tx)
        print("  [OK] Replaced USER TRANSACTIONS section")
    else:
        alt = re.search(
            r'else \{\s*for output in tx\.outputs.*?increment_nonce_batch.*?inconsistent\);\s*\}',
            content, re.DOTALL)
        if alt:
            content = content[:alt.start()] + new_tx + content[alt.end():]
            print("  [OK] Replaced using flexible match")
        else:
            print("  [ERROR] Could not find USER TRANSACTIONS block. Manual fix needed.")
            return False

    write_file(filepath, content)
    print(f"  [DONE] {os.path.relpath(filepath, ROOT)}")
    return True

def patch_errors():
    paths = [
        os.path.join(ROOT, "consensus/src/processes/transaction_validator/errors.rs"),
    ]
    filepath = None
    for p in paths:
        if os.path.exists(p):
            filepath = p
            break
    if filepath is None:
        print("  [WARN] errors.rs not found. If TxRuleError::Message missing, add it manually.")
        return True
    content = read_file(filepath)
    backup(filepath)
    if 'Message(String)' in content or 'Message("' in content:
        print("  [SKIP] TxRuleError::Message already exists")
        return True
    if 'pub enum TxRuleError' in content:
        content = content.replace('pub enum TxRuleError {', 'pub enum TxRuleError {\n    #[error("{0}")]\n    Message(String),', 1)
        write_file(filepath, content)
        print("  [OK] Added Message(String) to TxRuleError")
    else:
        print("  [WARN] Could not find TxRuleError enum. Add #[error(\"{0}\")] Message(String), manually.")
    return True

def main():
    print("=" * 60)
    print("  SAHYADRI SECURITY FIX: Account TX Sig Verification")
    print("=" * 60)
    if not os.path.exists(os.path.join(ROOT, "Cargo.toml")):
        print("[ERROR] Run from sahyadri project root!")
        sys.exit(1)
    print(f"Root: {ROOT}\n")
    r1 = patch_tx_validation()
    print()
    r2 = patch_processor()
    print()
    r3 = patch_errors()
    print()
    print("=" * 60)
    if all([r1, r2, r3]):
        print("  ALL PATCHES OK! Run: cargo build 2>&1 | head -100")
    else:
        print("  Some patches failed. Check errors above.")
    print("  Backups: _sig_fix_backups/")
    print("=" * 60)

if __name__ == "__main__":
    main()
