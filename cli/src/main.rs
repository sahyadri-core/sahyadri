cfg_if::cfg_if! {
    if #[cfg(target_arch = "wasm32")] {
        fn main() {}
    } else {
        use sahyadri_cli_lib::{sahyadri_cli, TerminalOptions};

        #[tokio::main]
        async fn main() {
            let result = sahyadri_cli(TerminalOptions::new().with_prompt("$ "), None).await;
            if let Err(err) = result {
                println!("{err}");
            }
        }
    }
}
