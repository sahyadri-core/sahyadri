use sahyadri_cli_lib::{TerminalOptions, sahyadri_cli};

#[tokio::main]
async fn main() {
    let result = sahyadri_cli(TerminalOptions::new().with_prompt("$ "), None).await;
    if let Err(err) = result {
        println!("{err}");
    }
}
