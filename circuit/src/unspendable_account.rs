use plonky2::{
    hash::{hash_types::HashOutTarget, poseidon::PoseidonHash},
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{circuit_builder::CircuitBuilder, config::Hasher},
};

use crate::utils::{bytes_to_felts, felts_to_bytes, string_to_felt};
use crate::{
    circuit::{CircuitFragment, D, F},
    codec::FieldElementCodec,
    utils::Digest
};
use crate::{codec::ByteCodec};

pub const SECRET_NUM_TARGETS: usize = 4;
pub const PREIMAGE_NUM_TARGETS: usize = 5;
pub const UNSPENDABLE_SALT: &str = "wormhole";

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct UnspendableAccount {
    account_id: Digest,
    secret: Vec<F>,
}

impl UnspendableAccount {
    pub fn new(secret: &[u8]) -> Self {
        // First, convert the preimage to its representation as field elements.
        let mut preimage = Vec::new();
        let secret_felts = bytes_to_felts(secret);
        preimage.push(string_to_felt(UNSPENDABLE_SALT));
        preimage.extend(secret_felts.clone());

        if preimage.len() != PREIMAGE_NUM_TARGETS {
            panic!("Expected secret to be 32 bytes (4 field elements), got {} field elements", preimage.len() - 1);
        }

        // Hash twice to get the account id.
        let inner_hash = PoseidonHash::hash_no_pad(&preimage).elements;
        // println!("inner_hash: {:?}", hex::encode(felts_to_bytes(&inner_hash)));
        let outer_hash = PoseidonHash::hash_no_pad(&inner_hash).elements;
        let account_id = Digest::from(outer_hash);

        Self {
            account_id,
            secret: secret_felts,
        }
    }
}

// impl From<&CircuitInputs> for UnspendableAccount {
//     fn from(inputs: &CircuitInputs) -> Self {
//         Self{
//             account_id: inputs.private.unspendable_account.account_id,
//             preimage: inputs.private.unspendable_account.preimage,
//         }
//     }
// }

impl ByteCodec for UnspendableAccount {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend(felts_to_bytes(&self.account_id));
        bytes.extend(felts_to_bytes(&self.secret));
        bytes
    }

    fn from_bytes(slice: &[u8]) -> anyhow::Result<Self> {
        let f_size = size_of::<F>(); // 8 bytes
        let account_id_size = 4 * f_size; // 4 field elements
        let preimage_size = 5 * f_size; // 5 field elements
        let total_size = account_id_size + preimage_size;

        if slice.len() != total_size {
            return Err(anyhow::anyhow!(
                "Expected {} bytes for UnspendableAccount, got: {}",
                total_size,
                slice.len()
            ));
        }

        let mut offset = 0;
        // Deserialize account_id
        let account_id = bytes_to_felts(&slice[offset..offset + account_id_size])
            .try_into()
            .map_err(|_| anyhow::anyhow!("Failed to deserialize unspendable account id"))?;
        offset += account_id_size;

        // Deserialize preimage
        let preimage = bytes_to_felts(&slice[offset..offset + preimage_size]);

        Ok(Self {
            account_id,
            secret: preimage,
        })
    }
}

impl FieldElementCodec for UnspendableAccount {
    fn to_field_elements(&self) -> Vec<F> {
        let mut elements = Vec::new();
        elements.extend(self.account_id.to_vec());
        elements.extend(self.secret.clone());
        elements
    }

    fn from_field_elements(elements: &[F]) -> anyhow::Result<Self> {
        // Expected sizes
        let account_id_size = 4;
        let preimage_size = 5; // 1 for salt + 4 for secret
        let total_size = account_id_size + preimage_size; // 4 + 5 = 9

        if elements.len() != total_size {
            return Err(anyhow::anyhow!(
                "Expected {} field elements for UnspendableAccount, got: {}",
                total_size,
                elements.len()
            ));
        }

        let mut offset = 0;
        // Deserialize account_id
        let account_id = elements[offset..offset + account_id_size]
            .try_into()
            .map_err(|_| anyhow::anyhow!("Failed to deserialize unspendable account id"))?;
        offset += account_id_size;

        // Deserialize preimage
        let preimage = elements[offset..offset + preimage_size].to_vec();

        Ok(Self {
            account_id,
            secret: preimage,
        })
    }
}

#[derive(Debug, Clone)]
pub struct UnspendableAccountTargets {
    account_id: HashOutTarget,
    pub secret: Vec<Target>,
}

impl UnspendableAccountTargets {
    pub fn new(builder: &mut CircuitBuilder<F, D>) -> Self {
        Self {
            account_id: builder.add_virtual_hash(),
            secret: builder.add_virtual_targets(SECRET_NUM_TARGETS),
        }
    }
}

impl CircuitFragment for UnspendableAccount {
    type Targets = UnspendableAccountTargets;

    /// Builds a circuit that asserts that the `unspendable_account` was generated from `H(H(salt+secret))`.
    fn circuit(
        &Self::Targets {
            account_id,
            ref secret,
        }: &Self::Targets,
        builder: &mut CircuitBuilder<F, D>,
    ) {
        let salt = builder.constant(string_to_felt(UNSPENDABLE_SALT));
        let mut preimage = Vec::new();
        preimage.push(salt);
        preimage.extend(secret);

        // Compute the `generated_account` by double-hashing the preimage (salt + secret).
        let inner_hash = builder.hash_n_to_hash_no_pad::<PoseidonHash>(preimage.clone());
        let generated_account =
            builder.hash_n_to_hash_no_pad::<PoseidonHash>(inner_hash.elements.to_vec());

        // Assert that hashes are equal.
        builder.connect_hashes(generated_account, account_id);
    }

    fn fill_targets(
        &self,
        pw: &mut PartialWitness<F>,
        targets: Self::Targets,
    ) -> anyhow::Result<()> {
        // Unspendable account circuit values.
        pw.set_hash_target(targets.account_id, self.account_id.into())?;
        pw.set_target_arr(&targets.secret, &self.secret)?;

        Ok(())
    }
}

pub mod test_helpers {
    use super::UnspendableAccount;

    /// An array of addresses generated from the Resoncance Node with `./resonance-node key resonance --scheme wormhole`.
    #[allow(dead_code)]
    pub const ADDRESSES: [&str; 5] = [
        "3af670a9aae5fa52ca14ab952a5d3dd80ffd97cf7fe4ec18febd6b6d48db9ff3",
        "8ae7f6db2098e39ef1156d4b8722c7a393480ee1711331a07217c7a8dd3f7424",
        "0cf7f0f8baf7a9ecca87a7496cc40d1b3e3be3bc773b84b079028f7ce689042a",
        "f41d2fd64d2d0e8e64a89cfe7e3402a46e0a52f8d89a09895dfb2e711fad617b",
        "4b7f14435f205b6d4449fde3132e80c35fcb059c83cc3e510f9b86061d247891",
    ];

    /// An array of secrets generated from the Resonance Node with `./resonance-node key resonance --scheme wormhole`.
    pub const SECRETS: [&str; 5] = [
        "3d2aa1def85521eca8de239acd6e124ce7830cff45e1d74f8b794e01ea5c29a1",
        "76d0c295490a8f7dd1047652cd91180bb54902c70c56a07df98dd03de5ff9280",
        "dd71a193c7676e4d606fee0d58b15044369b52ec306446c454e37388506dc960",
        "dda8f43788e46f64edef10b4aebfd1f17163d233afb54695a077bb68f0fe18ff",
        "1ea115b053fbc1aa8c162af6c5af24bf7978fe65b2c174b378f30fc1fc9fe222",
    ];


    impl Default for UnspendableAccount {
        fn default() -> Self {
            let preimage = hex::decode(SECRETS[0]).unwrap();
            Self::new(&preimage)
        }
    }
}

#[cfg(test)]
pub mod tests {
    use plonky2::{field::types::Field, plonk::proof::ProofWithPublicInputs};

    use super::{
        test_helpers::{ADDRESSES, SECRETS},
        UnspendableAccount, UnspendableAccountTargets,
    };
    use crate::circuit::{
        tests::{build_and_prove_test, setup_test_builder_and_witness},
        CircuitFragment, C, D, F,
    };
    use crate::codec::FieldElementCodec;
    use crate::utils::bytes_to_felts;

    fn run_test(
        unspendable_account: &UnspendableAccount,
    ) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
        let (mut builder, mut pw) = setup_test_builder_and_witness(false);
        let targets = UnspendableAccountTargets::new(&mut builder);
        UnspendableAccount::circuit(&targets, &mut builder);

        unspendable_account.fill_targets(&mut pw, targets)?;
        build_and_prove_test(builder, pw)
    }

    #[test]
    fn build_and_verify_unspendable_account_proof() {
        let unspendable_account = UnspendableAccount::default();
        run_test(&unspendable_account).unwrap();
    }

    #[test]
    fn preimage_matches_right_address() {
        for (secret, address) in SECRETS.iter().zip(ADDRESSES) {
            let decoded_secret = hex::decode(secret).unwrap();
            let decoded_address = hex::decode(address).unwrap();
            // println!("secret: {} address: {} decoded_secret: {:?} decoded_address {:?}", secret, address, hex::encode(decoded_secret.clone()), hex::encode(decoded_address.clone()));
            let unspendable_account = UnspendableAccount::new(&decoded_secret);

            let address = bytes_to_felts(&decoded_address);
            assert_eq!(unspendable_account.account_id.to_vec(), address);
            let result = run_test(&unspendable_account);
            assert!(result.is_ok());
        }
    }

    #[test]
    fn preimage_does_not_match_wrong_address() {
        let (secret, wrong_address) = (SECRETS[0], ADDRESSES[1]);
        let decoded_secret = hex::decode(secret).unwrap();
        let mut unspendable_account = UnspendableAccount::new(&decoded_secret);

        // Override the correct hash with the wrong one.
        let wrong_hash = bytes_to_felts(&hex::decode(wrong_address).unwrap());
        unspendable_account.account_id = wrong_hash.try_into().unwrap();

        let result = run_test(&unspendable_account);
        assert!(result.is_err());
    }

    #[test]
    fn all_zero_preimage_is_valid_and_hashes() {
        let secret_bytes = vec![0u8; 32];
        let account = UnspendableAccount::new(&secret_bytes);
        assert!(!account.account_id.to_vec().iter().all(Field::is_zero));
    }
}
