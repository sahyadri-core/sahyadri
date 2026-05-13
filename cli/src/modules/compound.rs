use crate::imports::*;

#[derive(Default, Handler)]
#[help("Native Auto-Compounder: Merges dust into OTC-ready Master Notes")]
pub struct Compound;

impl Compound {
    async fn main(self: Arc<Self>, ctx: &Arc<dyn Context>, _argv: Vec<String>, _cmd: &str) -> Result<()> {
        let ctx = ctx.clone().downcast_arc::<SahyadriCli>()?;
        let account = ctx.wallet().account()?;
        let address = account.receive_address()?; 

        tprintln!(ctx, "[Sahyadri Native] Starting OTC Compounding Mode...");
        
        let abortable = Abortable::default();
        let (wallet_secret, payment_secret) = ctx.ask_wallet_secret(Some(&account)).await?;

        // OTC Master Tiers
        let tiers = vec![1_000_000_000_000, 500_000_000_000, 100_000_000_000, 10_000_000_000]; 

        for target_kana in tiers {
            let amount_display = target_kana / 100_000_000;
            let outputs = PaymentOutputs::from((address.clone(), target_kana));

            // .clone() added here to prevent "move" error
            match account.clone().send(
                outputs.into(),
                None,             
                0u64.into(),      
                None,             
                wallet_secret.clone(),
                payment_secret.clone(),
                &abortable,
                None,             
            ).await {
                Ok((summary, _)) => {
                    tprintln!(ctx, "[SUCCESS] Master Note Created ({} CSM): {}", amount_display, summary);
                    return Ok(());
                },
                Err(_) => {
                    continue; // Try next lower tier if this fails
                }
            }
        }
        Ok(())
    }
}
