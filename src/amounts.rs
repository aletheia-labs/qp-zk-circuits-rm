use plonky2::{
    field::types::Field,
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::circuit_builder::CircuitBuilder,
};

use crate::{CircuitFragment, D, F};

pub struct Amounts {
    /// The amount that a wormhole deposit adress was funded with
    pub funding_tx_amount: F,
    /// Amount to be given to exit_account
    pub exit_amount: F,
    /// Amount to be given to miner
    pub fee_amount: F,
}

impl Amounts {
    pub fn new(funding_tx_amount: u64, exit_amount: u64, fee_amount: u64) -> Self {
        Self {
            funding_tx_amount: F::from_canonical_u64(funding_tx_amount),
            exit_amount: F::from_canonical_u64(exit_amount),
            fee_amount: F::from_canonical_u64(fee_amount),
        }
    }
}

pub struct AmountsTargets {
    pub funding_tx_amount: Target,
    pub exit_amount: Target,
    pub fee_amount: Target,
}

impl CircuitFragment for Amounts {
    type PrivateInputs = ();
    type Targets = AmountsTargets;

    /// Builds a circuit that asserts `funding_tx_amount = exit_amount + fee_amount`.
    fn circuit(&self, builder: &mut CircuitBuilder<F, D>) -> Self::Targets {
        let funding_tx_amount = builder.add_virtual_target();
        let exit_amount = builder.add_virtual_target();
        let fee_amount = builder.add_virtual_target();

        builder.register_public_input(funding_tx_amount);
        builder.register_public_input(exit_amount);
        builder.register_public_input(fee_amount);

        let sum = builder.add(exit_amount, fee_amount);
        builder.connect(sum, funding_tx_amount);

        AmountsTargets {
            funding_tx_amount,
            exit_amount,
            fee_amount,
        }
    }

    fn fill_targets(
        &self,
        pw: &mut PartialWitness<F>,
        targets: Self::Targets,
        _inputs: Self::PrivateInputs,
    ) -> anyhow::Result<()> {
        pw.set_target(targets.funding_tx_amount, self.funding_tx_amount)?;
        pw.set_target(targets.exit_amount, self.exit_amount)?;
        pw.set_target(targets.fee_amount, self.fee_amount)
    }
}
