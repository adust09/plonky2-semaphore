use plonky2::{
    field::types::Field,
    hash::{hash_types::HashOutTarget, merkle_proofs::MerkleProofTarget, poseidon::PoseidonHash},
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{circuit_builder::CircuitBuilder, config::Hasher},
};

use crate::access_set::AccessSet;
use crate::signal::{Digest, F};
#[derive(Clone)]

pub struct SemaphoreTargets {
    pub merkle_root: HashOutTarget,
    pub external_nullifier: [Target; 4],
    pub nullifier_hash: HashOutTarget,
    pub merkle_proof: MerkleProofTarget,
    pub identity_nullifier: [Target; 4],
    pub identity_trapdoor: [Target; 4],
    pub public_key_index: Target,
}

impl AccessSet {
    pub fn tree_height(&self) -> usize {
        self.0.leaves.len().trailing_zeros() as usize
    }

    pub fn semaphore_circuit(&self, builder: &mut CircuitBuilder<F, 2>) -> SemaphoreTargets {
        // Register public inputs.
        let merkle_root = builder.add_virtual_hash();
        builder.register_public_inputs(&merkle_root.elements);

        let nullifier_hash = builder.add_virtual_hash();
        builder.register_public_inputs(&nullifier_hash.elements);

        let external_nullifier: [Target; 4] = builder.add_virtual_targets(4).try_into().unwrap();
        builder.register_public_inputs(&external_nullifier);

        // Merkle proof
        let merkle_proof = MerkleProofTarget {
            siblings: builder.add_virtual_hashes(self.tree_height()),
        };

        // Identity secrets
        let identity_nullifier: [Target; 4] = builder.add_virtual_targets(4).try_into().unwrap();
        let identity_trapdoor: [Target; 4] = builder.add_virtual_targets(4).try_into().unwrap();

        let public_key_index = builder.add_virtual_target();
        let public_key_index_bits = builder.split_le(public_key_index, self.tree_height());

        // Compute identity commitment: hash(identity_nullifier, identity_trapdoor)
        let identity_commitment = builder.hash_n_to_hash_no_pad::<PoseidonHash>(
            [identity_nullifier.to_vec(), identity_trapdoor.to_vec()].concat(),
        );

        // Verify Merkle proof for identity commitment
        builder.verify_merkle_proof::<PoseidonHash>(
            identity_commitment.elements.to_vec(),
            &public_key_index_bits,
            merkle_root,
            &merkle_proof,
        );

        // Compute nullifier: hash(identity_nullifier, external_nullifier)
        let computed_nullifier = builder.hash_n_to_hash_no_pad::<PoseidonHash>(
            [identity_nullifier.to_vec(), external_nullifier.to_vec()].concat(),
        );

        // Connect computed nullifier to public input nullifier_hash
        for i in 0..4 {
            builder.connect(nullifier_hash.elements[i], computed_nullifier.elements[i]);
        }

        SemaphoreTargets {
            merkle_root,
            external_nullifier,
            nullifier_hash,
            merkle_proof,
            identity_nullifier,
            identity_trapdoor,
            public_key_index,
        }
    }

    pub fn fill_semaphore_targets(
        &self,
        pw: &mut PartialWitness<F>,
        identity_nullifier: Digest,
        identity_trapdoor: Digest,
        external_nullifier: Digest,
        public_key_index: usize,
        targets: SemaphoreTargets,
    ) {
        let SemaphoreTargets {
            merkle_root,
            external_nullifier: external_nullifier_target,
            nullifier_hash,
            merkle_proof: merkle_proof_target,
            identity_nullifier: identity_nullifier_target,
            identity_trapdoor: identity_trapdoor_target,
            public_key_index: public_key_index_target,
        } = targets;

        // Set public inputs
        let _ = pw.set_hash_target(merkle_root, self.0.cap.0[0]);
        Self::set_targets(pw, &external_nullifier_target, &external_nullifier);

        // Set private inputs
        Self::set_targets(pw, &identity_nullifier_target, &identity_nullifier);
        Self::set_targets(pw, &identity_trapdoor_target, &identity_trapdoor);
        let _ = pw.set_target(
            public_key_index_target,
            F::from_canonical_usize(public_key_index),
        );

        // Set Merkle proof
        let merkle_proof = self.0.prove(public_key_index);
        for (ht, h) in merkle_proof_target
            .siblings
            .into_iter()
            .zip(merkle_proof.siblings)
        {
            let _ = pw.set_hash_target(ht, h);
        }

        // Compute nullifier
        let computed_nullifier = PoseidonHash::hash_no_pad(
            &identity_nullifier
                .iter()
                .chain(external_nullifier.iter())
                .cloned()
                .collect::<Vec<F>>(),
        );

        // Set nullifier hash as public input
        let _ = pw.set_hash_target(nullifier_hash, computed_nullifier);
    }
    fn set_targets(pw: &mut PartialWitness<F>, targets: &[Target], values: &[F]) {
        for (&t, &v) in targets.iter().zip(values) {
            let _ = pw.set_target(t, v);
        }
    }
}
