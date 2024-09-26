use plonky2::{
    field::types::Field,
    hash::{hash_types::HashOutTarget, merkle_proofs::MerkleProofTarget, poseidon::PoseidonHash},
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::circuit_builder::CircuitBuilder,
};

use crate::access_set::AccessSet;
use crate::signal::{Digest, F};

pub struct SemaphoreTargets {
    merkle_root: HashOutTarget,
    topic: [Target; 4],
    merkle_proof: MerkleProofTarget,
    private_key: [Target; 4],
    public_key_index: Target,
}

impl AccessSet {
    pub fn tree_height(&self) -> usize {
        self.0.leaves.len().trailing_zeros() as usize
    }

    pub fn semaphore_circuit(&self, builder: &mut CircuitBuilder<F, 2>) -> SemaphoreTargets {
        // Register public inputs.
        let merkle_root = builder.add_virtual_hash();
        builder.register_public_inputs(&merkle_root.elements);
        let nullifier = builder.add_virtual_hash();
        builder.register_public_inputs(&nullifier.elements);
        let topic: [Target; 4] = builder.add_virtual_targets(4).try_into().unwrap();
        builder.register_public_inputs(&topic);

        // Merkle proof
        let merkle_proof = MerkleProofTarget {
            siblings: builder.add_virtual_hashes(self.tree_height()),
        };

        // Verify public key Merkle proof.
        let private_key: [Target; 4] = builder.add_virtual_targets(4).try_into().unwrap();
        let public_key_index = builder.add_virtual_target();
        let public_key_index_bits = builder.split_le(public_key_index, self.tree_height());
        let zero = builder.zero();
        builder.verify_merkle_proof::<PoseidonHash>(
            [private_key, [zero; 4]].concat(),
            &public_key_index_bits,
            merkle_root,
            &merkle_proof,
        );
        let should_be_nullifier =
            builder.hash_n_to_hash_no_pad::<PoseidonHash>([private_key, topic].concat());
        for i in 0..4 {
            builder.connect(nullifier.elements[i], should_be_nullifier.elements[i]);
        }

        SemaphoreTargets {
            merkle_root,
            topic,
            merkle_proof,
            private_key,
            public_key_index,
        }
    }

    pub fn fill_semaphore_targets(
        &self,
        pw: &mut PartialWitness<F>,
        private_key: Digest,
        topic: Digest,
        public_key_index: usize,
        targets: SemaphoreTargets,
    ) {
        let SemaphoreTargets {
            merkle_root,
            topic: topic_target,
            merkle_proof: merkle_proof_target,
            private_key: private_key_target,
            public_key_index: public_key_index_target,
        } = targets;

        let _ = pw.set_hash_target(merkle_root, self.0.cap.0[0]);
        Self::set_targets(pw, &private_key_target, &private_key);
        Self::set_targets(pw, &topic_target, &topic);
        let _ = pw.set_target(
            public_key_index_target,
            F::from_canonical_usize(public_key_index),
        );

        let merkle_proof = self.0.prove(public_key_index);
        for (ht, h) in merkle_proof_target
            .siblings
            .into_iter()
            .zip(merkle_proof.siblings)
        {
            let _ = pw.set_hash_target(ht, h);
        }
    }
    fn set_targets(pw: &mut PartialWitness<F>, targets: &[Target], values: &[F]) {
        for (&t, &v) in targets.iter().zip(values) {
            let _ = pw.set_target(t, v);
        }
    }
}
