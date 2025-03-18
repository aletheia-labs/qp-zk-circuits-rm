# zk-wormholes

## Prerequisites

For dependencies, can install them manually - or optionally, use the provided developer environment within the Nix flake.

### Manually

Ensure you have Rust installed. You can install Rust using [rustup](https://rustup.rs/):

```sh
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

### Nix flake

To use the Nix flake, first ensure that you have Nix installed. You can install Nix by running:

```sh
curl -L https://nixos.org/nix/install | sh -s -- --daemon
```

To enter a shell with all the dependencies pre-installed, run:

```sh
nix --experimental-features 'nix-command flakes' develop
```

## Setup

Clone the repository:

```sh
git clone https://github.com/Resonance-Network/wormhole-prover
cd wormhole-prover
```

## Testing

Run the tests with:

```sh
cargo test
```
