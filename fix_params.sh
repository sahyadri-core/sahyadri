#!/bin/bash
# ============================================================
# Sahyadri — 10,000 TPS Fix
# Replacing max_block_mass: 500_000 → 30_000_000 in 4 places
# ============================================================

PARAMS_FILE="$HOME/sahyadri-final/sahyadri/consensus/core/src/config/params.rs"

echo "[1] Creating backup..."
cp "$PARAMS_FILE" "$PARAMS_FILE.bak"
echo "    Backup created at: $PARAMS_FILE.bak"

echo "[2] Changing max_block_mass from 500_000 to 30_000_000..."
sed -i 's/max_block_mass: 500_000/max_block_mass: 30_000_000/g' "$PARAMS_FILE"

echo "[3] Verifying changes..."
grep -n "max_block_mass" "$PARAMS_FILE"

echo ""
echo "Done! Now run 'cargo build --release'."
