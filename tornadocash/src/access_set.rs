use std::usize;

use anyhow::Result;
use plonky2::{
    hash::{merkle_tree::MerkleTree, poseidon::PoseidonHash},
    iop::witness::PartialWitness,
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData, VerifierCircuitData},
        config::Hasher,
        proof::ProofWithPublicInputs,
    },
};

use crate::signal::{Digest, Signal, C, F};

pub struct AccessSet(pub MerkleTree<F, PoseidonHash>);

impl AccessSet {
    pub fn verify_signal(
        &self,
        topic: Digest,
        signal: Signal,
        verifier_data: &VerifierCircuitData<F, C, 2>,
    ) -> Result<()> {
        let public_inputs: Vec<F> = self
            .0
            .cap
            .0
            .iter()
            .flat_map(|h| h.elements)
            .chain(signal.nullifier)
            .chain(topic)
            .collect();

        verifier_data.verify(ProofWithPublicInputs {
            proof: signal.proof,
            public_inputs,
        })
    }

    pub fn make_signal(
        &self,
        private_key: Digest,
        topic: Digest,
        public_key_index: usize,
    ) -> Result<(Signal, VerifierCircuitData<F, C, 2>)> {
        let nullifier = PoseidonHash::hash_no_pad(&[private_key, topic].concat()).elements;
        let config = CircuitConfig::standard_recursion_zk_config();
        let mut builder = CircuitBuilder::new(config);
        let mut pw = PartialWitness::new();

        let targets = self.semaphore_circuit(&mut builder);
        self.fill_semaphore_targets(&mut pw, private_key, topic, public_key_index, targets);

        let data = builder.build();
        let proof = data.prove(pw)?;

        Ok((
            Signal {
                nullifier,
                proof: proof.proof,
            },
            Self::to_verifier_data(data),
        ))
    }
    pub fn to_verifier_data(circuit_data: CircuitData<F, C, 2>) -> VerifierCircuitData<F, C, 2> {
        VerifierCircuitData {
            verifier_only: circuit_data.verifier_only.clone(),
            common: circuit_data.common.clone(),
        }
    }
}
