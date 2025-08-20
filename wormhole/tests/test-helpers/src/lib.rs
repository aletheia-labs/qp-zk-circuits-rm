use crate::storage_proof::{DEFAULT_ROOT_HASH, TestInputs};
use wormhole_circuit::{
    inputs::{CircuitInputs, PrivateCircuitInputs, PublicCircuitInputs},
    nullifier::Nullifier,
    storage_proof::ProcessedStorageProof,
    unspendable_account::UnspendableAccount,
};
use zk_circuits_common::utils::BytesDigest;

pub const DEFAULT_SECRET: &str = "9aa84f99ef2de22e3070394176868df41d6a148117a36132d010529e19b018b7";
pub const DEFAULT_TRANSFER_COUNT: u64 = 3032;
pub const DEFAULT_FUNDING_ACCOUNT: [u8; 32] = [
    223, 23, 232, 59, 97, 108, 223, 113, 2, 89, 54, 39, 126, 65, 248, 106, 156, 219, 7, 123, 213,
    197, 228, 118, 177, 81, 61, 77, 23, 89, 200, 80,
];
pub const DEFAULT_FUNDING_AMOUNT: u128 =
    u128::from_le_bytes([0, 202, 154, 59, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
pub const DEFAULT_TO_ACCOUNT: [u8; 32] = [
    57, 254, 35, 241, 226, 106, 166, 32, 1, 20, 78, 107, 50, 80, 183, 83, 245, 170, 187, 75, 94,
    205, 90, 134, 184, 196, 167, 48, 39, 68, 89, 126,
];

pub const DEFAULT_EXIT_ACCOUNT: [u8; 32] = [4u8; 32];

impl TestInputs for CircuitInputs {
    fn test_inputs() -> Self {
        let secret = hex::decode(DEFAULT_SECRET.trim()).unwrap();
        let root_hash = hex::decode(DEFAULT_ROOT_HASH.trim())
            .unwrap()
            .as_slice()
            .try_into()
            .unwrap();

        let funding_account = BytesDigest::from(DEFAULT_FUNDING_ACCOUNT);
        let nullifier = Nullifier::from_preimage(&secret, DEFAULT_TRANSFER_COUNT)
            .hash
            .into();
        let secret: [u8; 32] = secret.try_into().expect("Expected 32 bytes for secret");
        let unspendable_account = UnspendableAccount::from_secret(&secret).account_id.into();
        let exit_account = BytesDigest::from(DEFAULT_EXIT_ACCOUNT);

        let storage_proof = ProcessedStorageProof::test_inputs();
        Self {
            public: PublicCircuitInputs {
                funding_amount: DEFAULT_FUNDING_AMOUNT,
                nullifier,
                root_hash,
                exit_account,
            },
            private: PrivateCircuitInputs {
                secret,
                storage_proof,
                transfer_count: DEFAULT_TRANSFER_COUNT,
                funding_account,
                unspendable_account,
            },
        }
    }
}

pub mod storage_proof {
    use crate::{
        DEFAULT_FUNDING_ACCOUNT, DEFAULT_FUNDING_AMOUNT, DEFAULT_TO_ACCOUNT, DEFAULT_TRANSFER_COUNT,
    };
    use wormhole_circuit::storage_proof::{ProcessedStorageProof, StorageProof, leaf::LeafInputs};
    use zk_circuits_common::utils::BytesDigest;

    pub const DEFAULT_ROOT_HASH: &str =
        "dc474827d8c59d4fa86a8dc6e602a24c9a1e510ed76ac7c05ee7d820d0e66fa4";

    pub const DEFAULT_STORAGE_PROOF: [&str; 8] = [
        "0000000000000020ffb50000000000002000000000000000830584967637083caecc3adf192586fba0309514896aa962a568f32d8b860f7f20000000000000008c89cd41f0f18f07bf170f28475e7a7722b232ffb699c827b87fe3d82abb16ff2000000000000000b8e905ff1f0ddc3d7acba1e0c411a04e0747cf8762f33e9d1f9b71da871240242000000000000000717d7396e6b68aaba7fb9d6a6536f4aeb117e9e4295244321bb8b7dcd5387b77200000000000000026e341bfcbfdf2a6224ef9e956c0ebcabab788f8d9f3d8cb1ef68904ace9c22d2000000000000000d35701dbd2dc2ab5d35968e7a5e142f99eec0fb77021a5d9c29d1477ef95c9ce2000000000000000e6943b9c261b23746f4b267a59a5335857a7b321567da5c804f34c8fdad5ad1d2000000000000000ae61d065cc17398f8817929bf40deab3cf2dbcb4de5c8e758169c15c4073d9622000000000000000cc112839738c7a6205ea12619c165e7fd94c1afd2aec00a7c17d74b0d588f8d420000000000000000ec4814db8cb20b3e49556ca86883289fe6e993238124864c2944cf768aa4583200000000000000069e9e78e628c3075e898fcab2a2d372f67d49641656f3aca273925a6ff682dc5200000000000000015628f1eaf99c7dcb9962dae035fcf6a56ce63033c1a8243965173192f3f7386200000000000000099025494097dd5cabfbc150ce61ec11a4cf03720afd526e8a3dabf1b3cb1cfb3",
        "000000000000002004100000000000002000000000000000b2f9c7d5717285566bb9b7417eb1f6a4079cd0dfd1c70755f4dbcd00ec47929a200000000000000053a608459bc7e631fc6d471ee1bb60fa3efbe92642faffa487dd4699c5e4197e",
        "1e00000000000020261276cc9d1f8598ea4b6a74b15c2f00328000000000000020000000000000001b23d7c598f985703bd0ccb7cdf555faa05d41cd7fc005cf1442eefa822f9ee320000000000000004fb5e82cf2225a397d021d73b339afa8847d5df18791fa844099146360d4e2ce2000000000000000f4fcc7d905d37212293f8afb1eddf2b09c346ce6fde987900313ac96765f219a200000000000000063d0b44ac2b5679e2dac20ea58827fb89505dc4e89e1c39684d588af8dff0db4",
        "0000000000000020840000000000000020000000000000002b3f7ed7a98aba7f67bd5c4b2a263363255bcda18e7698b0a79d7dba39ae9c132000000000000000173a3f865a86e7109aa87ed500aca1521fe832665b7d7df97a54a3c4e299c807",
        "1e00000000000020857e7ea49e785c4e3e1f77a710cfc200ffff0000000000002000000000000000ff3f6bc15227e2d7e281cdae6954ef2a8fb971d94b38e8fc37bbc48722a902382000000000000000c94cc2b4383f8c124173673d78573fd920c2c6b343452eaeca079a19bc071f4c2000000000000000ce8f88cfee90c4c9640fd6bbe932bf92a01a93811b299dab40afbb6a7b97384e2000000000000000d30085b37574f5b9d1b71ed7559662b3d0f7fa098b746fe356302df6794792952000000000000000568759779393fdd0e294c5c64a9deb689ad348ec1e4fc39775706681977e205c20000000000000003073ef9bce8a02d51dff7388e9ac22762e5f8b418fdc7917824816c4efe4692c2000000000000000f3180d75da1828b05a40d3dd52e5ecc2f0dad69ee67106b52f9ed201dafe68622000000000000000d1254795a480f12e203dd92e6f3e84a7c79747cd98333197a8a1e3d72fc088c220000000000000007c31634fa0ae2336f240d3c6539f995f1e6600bc174f721385d56557e9cce62a2000000000000000d953250254cd65f43739ed97c1a1ffec60cc1bfb53007e401c8f5c2d3efaa5662000000000000000fa381e434e9e5a6c3d86b3da61a760e1d98bdecef5bf7296fc12b5ba25eda56f20000000000000008103c691b58643c68d490f40a6b2a1015f6059346b55fdd93302e2f59641f74c200000000000000016097a313cae31f37c1372044d800eb582f81f88d89f1a49ddecc7528f8b2da02000000000000000fce948a6242a430077f9c22e14d621ffec35c16fb31361cc55bee18bec24f5812000000000000000d37c70475d5465aedb9a587fd06c4b8519119bbc1250c7ed0164a8bba1c57dac20000000000000004abde2148bbf9cc9019ba0b79c8dfe6a993fcc138504dfd62cdbfcfd42ec6794",
        "0000000000000020ffff00000000000020000000000000005efab0128ac9c1cec4b10b8a5b556f91f613c54bd6db6a31e1de10090d561f1d200000000000000015321a48132b99236d537d4693a6e289cbd628d2402240e9964c06b8bf752cbb20000000000000006b213bba47fe1d5d3ba921a5871372b38e189d5749bbafb848bdc0402fda502420000000000000004a8400ba755ab0ec96da8a23840459af28f03783fb6d2b5b4020cb4d7a3d302e200000000000000099ae4b10a8a2a06e48e8e55711866cb5e2967914516402e3566b2ee4d1a7b91f2000000000000000fb3ee29e35a873fdd1d56b5e0363102aacc087a28981192f435cbc0364b9129e2000000000000000e0c8f5d7d85d8efaee80513af465cf7d2734723b90e9d8d961b8eb6e94b2919e20000000000000003231fab60339c6b014d1b3016ce62535446c967e811ab3306cfef3bc8357e840200000000000000096f22471db26195fe49e6bdc6e825363b3b5cc9ffce711a1a1462c2663ab2d17200000000000000092ab6d3e2eeb3eff816d5509dd4a73602de1518886d4933c2efc10ef57b389cd2000000000000000c05750b42ee439347b3a932bb98da6e0c5f279e148d406523a6ec110c08a698920000000000000006e14b8c37c4009e1a830dfe457f0aef311dc891ddb61b1033f77a0c7dc8dda4f200000000000000017b308ea4e6e63e54ce401dde40431e248d1526081b5cfa93050aaa0c51008d12000000000000000554e77da69d73292013d173a539b2259237377bfe32b89baf29031081437f70420000000000000006ecc08fdb718c6b994e802ce591cdfc892f3b93e2be65a2f5b0103019740d27c2000000000000000e5499118e1c36702a2a667e771a67b37cfb27231dd5379c1da1dc4f3b7b8bd0e",
        "000000000000002056c500000000000020000000000000004fe2e4380c764f183c4c7c13d4c9df8b0f49398a7c5bfe928ac4984511b3ec84200000000000000013d3f634a08f8852dce0e9059be876c585f7e8a12a722c7cd3c93be0a87f1976200000000000000015d2b7d94cff59ab4d96855b66750de3298bdef1664cc138fbd1eac657a3d34620000000000000007f2801d683a1774bda1c28d10bc51ba3c35c1e67c31727c78c9677e2a33d69b62000000000000000d2e2fb5e6140201f4b8e40c84885731845377b12ca62383316a430fc817057cd2000000000000000dc3472c1a2a99048fd2f1af258a6db860ba0aedc9c019307ca91a179c8bcfd322000000000000000e63ba9c1c3549115989b5d205edc3753f778cf56b26aea3cdf7d7d3ee535bf5020000000000000005240eba5fa34cb0cb269c8646d9aae7fcdf9449879e5ff8fb23f808b906ecd59",
        "3d0000000000003000016cef89dbe7aa730948c59bc6dabd8f52a75d27e156542c1e1723d7f1fb130000000000000000",
    ];
    pub const DEFAULT_STORAGE_PROOF_INDICIES: [usize; 8] = [848, 48, 240, 48, 320, 608, 528, 16];

    pub trait TestInputs {
        fn test_inputs() -> Self;
    }

    impl TestInputs for ProcessedStorageProof {
        fn test_inputs() -> Self {
            let proof = DEFAULT_STORAGE_PROOF
                .map(|node| hex::decode(node).unwrap())
                .to_vec();
            let indices = DEFAULT_STORAGE_PROOF_INDICIES.to_vec();
            Self::new(proof, indices).unwrap()
        }
    }

    impl TestInputs for LeafInputs {
        fn test_inputs() -> Self {
            let funding_account = BytesDigest::from(DEFAULT_FUNDING_ACCOUNT);
            let to_account = BytesDigest::from(DEFAULT_TO_ACCOUNT);
            LeafInputs::new(
                DEFAULT_TRANSFER_COUNT,
                funding_account,
                to_account,
                DEFAULT_FUNDING_AMOUNT,
            )
            .unwrap()
        }
    }

    impl TestInputs for StorageProof {
        fn test_inputs() -> Self {
            StorageProof::new(
                &ProcessedStorageProof::test_inputs(),
                default_root_hash(),
                LeafInputs::test_inputs(),
            )
        }
    }

    pub fn default_root_hash() -> [u8; 32] {
        hex::decode(DEFAULT_ROOT_HASH).unwrap().try_into().unwrap()
    }
}

pub mod nullifier {
    use crate::DEFAULT_TRANSFER_COUNT;

    use super::DEFAULT_SECRET;
    use wormhole_circuit::nullifier::Nullifier;

    pub trait TestInputs {
        fn test_inputs() -> Self;
    }

    impl TestInputs for Nullifier {
        fn test_inputs() -> Self {
            let secret = hex::decode(DEFAULT_SECRET).unwrap();
            Self::from_preimage(secret.as_slice(), DEFAULT_TRANSFER_COUNT)
        }
    }
}
