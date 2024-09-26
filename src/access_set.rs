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

use crate::{
    circuit::SemaphoreTargets,
    signal::{Digest, Signal, C, F},
};

pub struct AccessSet(pub MerkleTree<F, PoseidonHash>);

impl AccessSet {
    pub fn verify_signal(
        &self,
        external_nullifier: Digest,
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
            .chain(external_nullifier)
            .collect();

        verifier_data.verify(ProofWithPublicInputs {
            proof: signal.proof,
            public_inputs,
        })
    }

    pub fn make_signal(
        &self,
        identity_nullifier: Digest,
        identity_trapdoor: Digest,
        external_nullifier: Digest,
        public_key_index: usize,
        circuit_data: &CircuitData<F, C, 2>,
        targets: &SemaphoreTargets,
    ) -> Result<Signal> {
        // Compute nullifier: hash(identity_nullifier, external_nullifier)
        let nullifier_hash =
            PoseidonHash::hash_no_pad(&[identity_nullifier, external_nullifier].concat()).elements;

        let mut pw = PartialWitness::new();

        self.fill_semaphore_targets(
            &mut pw,
            identity_nullifier,
            identity_trapdoor,
            external_nullifier,
            public_key_index,
            targets.clone(),
        );

        let proof_with_pis = circuit_data.prove(pw)?;

        Ok(Signal {
            nullifier: nullifier_hash,
            proof: proof_with_pis.proof,
        })
    }

    pub fn build_circuit(&self) -> (CircuitData<F, C, 2>, SemaphoreTargets) {
        let config = CircuitConfig::standard_recursion_zk_config();
        let mut builder = CircuitBuilder::new(config);

        let targets = self.semaphore_circuit(&mut builder);

        let circuit_data = builder.build();

        (circuit_data, targets)
    }

    pub fn to_verifier_data(circuit_data: &CircuitData<F, C, 2>) -> VerifierCircuitData<F, C, 2> {
        VerifierCircuitData {
            verifier_only: circuit_data.verifier_only.clone(),
            common: circuit_data.common.clone(),
        }
    }
}
