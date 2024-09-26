use plonky2::{
    field::goldilocks_field::GoldilocksField,
    plonk::{config::PoseidonGoldilocksConfig, proof::Proof},
};

pub type F = GoldilocksField;
pub type C = PoseidonGoldilocksConfig;
pub type Digest = [F; 4];
pub type PlonkyProof = Proof<F, PoseidonGoldilocksConfig, 2>;

#[derive(Debug, Clone)]
pub struct Signal {
    pub nullifier: Digest,
    pub proof: PlonkyProof,
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use plonky2::{
        field::types::Sample,
        hash::{merkle_tree::MerkleTree, poseidon::PoseidonHash},
        plonk::config::Hasher,
    };

    use crate::{
        access_set::AccessSet,
        signal::{Digest, F},
    };
    #[test]
    fn test_semaphore() -> Result<()> {
        let n = 1 << 20;

        // 修正点 1: identity_nullifierとidentity_trapdoorのペアを生成
        let private_keys: Vec<(Digest, Digest)> =
            (0..n).map(|_| (F::rand_array(), F::rand_array())).collect();

        // 修正点 2: アイデンティティコミットメントの計算
        let identity_commitments: Vec<Vec<F>> = private_keys
            .iter()
            .map(|(identity_nullifier, identity_trapdoor)| {
                // 修正: 配列を結合する方法を変更
                let input: Vec<F> = identity_nullifier
                    .iter()
                    .chain(identity_trapdoor.iter())
                    .cloned()
                    .collect();

                PoseidonHash::hash_no_pad(&input).elements.to_vec()
            })
            .collect();

        // 以下、残りのコードはそのまま
        let access_set = AccessSet(MerkleTree::new(identity_commitments, 0));

        let i = 12;
        let external_nullifier = F::rand_array();

        let (circuit_data, targets) = access_set.build_circuit();
        let verifier_data = AccessSet::to_verifier_data(&circuit_data);

        let signal = access_set.make_signal(
            private_keys[i].0, // identity_nullifier
            private_keys[i].1, // identity_trapdoor
            external_nullifier,
            i,
            &circuit_data,
            &targets,
        )?;
        access_set.verify_signal(external_nullifier, signal, &verifier_data)
    }
}
