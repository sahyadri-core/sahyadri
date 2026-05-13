use sahyadri_cli_lib::sahyadri_cli;
use wasm_bindgen::prelude::*;
use workflow_terminal::Options;
use workflow_terminal::Result;

#[wasm_bindgen]
pub async fn load_sahyadri_wallet_cli() -> Result<()> {
    let options = Options { ..Options::default() };
    sahyadri_cli(options, None).await?;
    Ok(())
}
