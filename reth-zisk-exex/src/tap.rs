//! Payload tap: the engine's payload validator, wrapped so that every
//! newPayload is copied to the prover pipeline as soon as the engine tree
//! has decoded it, before reth executes it. That is t0 for the proof, with
//! the full block and its block access list in hand.

use std::time::SystemTime;

use alloy_rpc_types_engine::ExecutionData;
use reth_engine_primitives::{EngineApiValidator, PayloadValidator};
use reth_ethereum::node::api::{FullNodeComponents, NodeTypes};
use reth_ethereum::node::EthereumEngineValidator;
use reth_payload_primitives::{
    EngineApiMessageVersion, EngineObjectValidationError, NewPayloadError, PayloadOrAttributes, PayloadTypes,
};
use reth_ethereum::node::builder::rpc::PayloadValidatorBuilder;
use reth_ethereum::node::builder::AddOnsContext;
use reth_ethereum::primitives::SealedBlock;
use reth_ethereum::Block;
use tokio::sync::mpsc;
use tracing::warn;

use crate::pipeline::Incoming;

#[derive(Debug, Clone)]
pub struct TapValidator<V> {
    inner: V,
    tx: mpsc::Sender<Incoming>,
}

impl<V, Types> PayloadValidator<Types> for TapValidator<V>
where
    V: PayloadValidator<Types, Block = Block>,
    Types: PayloadTypes<ExecutionData = ExecutionData>,
{
    type Block = Block;

    fn convert_payload_to_block(
        &self,
        payload: ExecutionData,
    ) -> Result<SealedBlock<Block>, NewPayloadError> {
        let received = SystemTime::now();
        let bal = payload.payload.block_access_list().cloned();
        let block = self.inner.convert_payload_to_block(payload)?;
        // Never block the engine: drop the copy if the pipeline is behind.
        let incoming = Incoming { block: block.clone(), bal, beacon_root: None, source: "tap_payload", at: received, extra_marks: vec![] };
        if self.tx.try_send(incoming).is_err() {
            warn!(number = block.number, "payload tap: pipeline channel full, payload dropped");
        }
        Ok(block)
    }
}

impl<V, Types> EngineApiValidator<Types> for TapValidator<V>
where
    V: EngineApiValidator<Types>,
    Types: PayloadTypes,
{
    fn validate_version_specific_fields(
        &self,
        version: EngineApiMessageVersion,
        payload_or_attrs: PayloadOrAttributes<'_, Types::ExecutionData, Types::PayloadAttributes>,
    ) -> Result<(), EngineObjectValidationError> {
        self.inner.validate_version_specific_fields(version, payload_or_attrs)
    }

    fn ensure_well_formed_attributes(
        &self,
        version: EngineApiMessageVersion,
        attributes: &Types::PayloadAttributes,
    ) -> Result<(), EngineObjectValidationError> {
        self.inner.ensure_well_formed_attributes(version, attributes)
    }
}

/// Builds the Ethereum engine validator wrapped in the tap.
#[derive(Debug, Clone)]
pub struct TapValidatorBuilder {
    pub tx: mpsc::Sender<Incoming>,
}

impl<Node> PayloadValidatorBuilder<Node> for TapValidatorBuilder
where
    Node: FullNodeComponents,
    Node::Types: NodeTypes<ChainSpec = reth_ethereum::chainspec::ChainSpec>,
    <Node::Types as NodeTypes>::Payload: PayloadTypes<ExecutionData = ExecutionData>,
    EthereumEngineValidator<reth_ethereum::chainspec::ChainSpec>:
        PayloadValidator<<Node::Types as NodeTypes>::Payload, Block = Block>,
{
    type Validator = TapValidator<EthereumEngineValidator<reth_ethereum::chainspec::ChainSpec>>;

    async fn build(self, ctx: &AddOnsContext<'_, Node>) -> eyre::Result<Self::Validator> {
        Ok(TapValidator { inner: EthereumEngineValidator::new(ctx.config.chain.clone()), tx: self.tx })
    }
}
