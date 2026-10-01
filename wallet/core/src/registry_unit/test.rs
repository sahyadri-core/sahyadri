use crate::imports::*;
use crate::result::Result;
use crate::tests::RpcCoreMock;
use crate::tx::generator::test::*;
use crate::tx::*;
use crate::utils::*;
use crate::registry_unit::*;

#[tokio::test]
async fn test_registry_unit_subsystem_bootstrap() -> Result<()> {
    let network_id = NetworkId::with_suffix(NetworkType::Testnet, 10);
    let rpc_api_mock = Arc::new(RpcCoreMock::new());
    let processor = RegistryUnitProcessor::new(Some(rpc_api_mock.clone().into()), Some(network_id), None, None);
    let _context = RegistryUnitContext::new(&processor, RegistryUnitContextBinding::default());

    processor.mock_set_connected(true);
    processor.handle_daa_score_change(1).await?;
    // println!("daa score: {:?}", processor.current_daa_score());
    // context.register_addresses(&[output_address(network_id.into())]).await?;
    Ok(())
}

#[test]
#[ignore]
fn test_registry_unit_generator_empty_registry_unit_noop() -> Result<()> {
    let network_id = NetworkId::with_suffix(NetworkType::Testnet, 10);
    let output_address = output_address(network_id.into());

    let payment_output = PaymentOutput::new(output_address, sahyadri_to_kana(2.0));
    let generator =
        make_generator(network_id, &[10.0], &[], None, Fees::SenderPays(0), change_address, payment_output.into()).unwrap();
    let _tx = generator.generate_transaction().unwrap();
    // println!("tx: {:?}", tx);
    // assert!(tx.is_none());
    Ok(())
}
