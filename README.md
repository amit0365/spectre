# Spectre

**Privacy-Preserving Sybil Resistance with ZK-Provable OPRF Nullifiers**

No party ever sees both the user's identity and their nullifier. The entire OPRF chain — SHA-256 hashing, map-to-curve, blinding, unblinding, and nullifier derivation — is proven in a single Noir ZK circuit on secp256k1 (non-native over BN254).

## How It Works

```
Client                              Server
  |                                   |
  |  1. blind(input)                  |
  |  h = hash_to_curve(input)         |
  |  blinded = h * r                  |
  |                                   |
  |-------- blinded_point ----------->|
  |                                   |
  |                   2. evaluate     |
  |                   eval = blinded^k|
  |                                   |
  |<------- evaluated_point ----------|
  |                                   |
  |  3. unblind + prove               |
  |  unblinded = evaluated * r^-1     |
  |  nullifier = SHA-256(input || unblinded)
  |  ZK proof of entire chain         |
```

- **Client** holds a private input (e.g., email). Server never sees it.
- **Server** holds OPRF key `k`. Client never learns it.
- **Same input + same server key = same nullifier** → sybil detection.
- **No party holds enough information to break privacy on its own.**

## Core Innovation

Standard SSWU hash-to-curve costs ~7,095 constraints inside a ZK circuit. We replace it with the **increment-and-check** construction from [Groth, Malvai, Miller & Zhang](https://eprint.iacr.org/2024/XXX), reducing map-to-curve to **~22 constraints** (~300x reduction).

The full circuit proves 5 relations in a single proof:

| Step | Relation | What it proves |
|------|----------|----------------|
| 1 | `m = SHA-256(input)` | Hash to field element |
| 2 | `h_x = m * 256 + k, h_y = z^2` | Map-to-curve witness |
| 3 | `h_y^2 = h_x^3 + 7` | Point is on secp256k1 |
| 4 | `blinded == h * r` | Correct blinding |
| 5 | `nullifier == SHA-256(input \|\| unblinded)` | Correct derivation |

## Circuit Stats

| Metric | Value |
|--------|-------|
| ACIR opcodes | 53,213 |
| UltraHonk gates | 197,599 |
| Proof system | Barretenberg UltraHonk |
| Curve | secp256k1 (non-native over BN254) |
| Map-to-curve constraints | ~22 (vs ~7,095 for SSWU) |

## Advantages Over Semaphore

| | Semaphore | Spectre |
|---|---|---|
| Key leak impact | All nullifiers compromised | Can't compute without OPRF server |
| Linkability | `H(sk, scope)` — leaked key links all scopes | Server sees only random blinded points |
| Multi-device | One key = one member | Input-based, key-independent |
| Key recovery | Lose key = lose membership | Nullifier decoupled from client key |
| Proof scope | Separate membership + nullifier proofs | Single proof covers full OPRF chain |

## Project Structure

```
oprf-nullifier/
├── src/
│   ├── lib.rs              # Library root
│   ├── client.rs           # OPRF client: blind, unblind, derive nullifier
│   ├── server.rs           # OPRF server: holds key, evaluates blinded points
│   ├── hash_to_curve.rs    # Increment-and-check map-to-curve (secp256k1)
│   ├── noir_prover.rs      # Noir circuit prover/verifier integration
│   ├── main.rs             # CLI demo
│   ├── web.rs              # Web demo (Axum server)
│   └── gen_witness.rs      # Witness generation utility
├── noir-circuit/
│   ├── src/main.nr         # Full nullifier Noir circuit
│   └── Nargo.toml          # noir_bigcurve, sha256 dependencies
├── tests/
│   └── full_nonnative_proof.rs  # End-to-end proof test
└── static/
    └── index.html          # Web demo frontend
```

## Prerequisites

- [Rust](https://rustup.rs/) (edition 2021)
- [Nargo](https://noir-lang.org/docs/getting_started/installation/) >= 0.37.0
- [Barretenberg](https://github.com/AztecProtocol/barretenberg) (`bb` binary)

## Quick Start

### Build

```bash
cargo build --release
```

### CLI Demo

```bash
cargo run --bin demo-cli
```

Runs the full OPRF protocol flow in the terminal: blinding, evaluation, unblinding, nullifier derivation, and sybil detection.

### Web Demo

```bash
cargo run --bin demo-web -- --port 3000
```

Open `http://localhost:3000` for an interactive walkthrough with live proof generation and verification.

### Run Tests

```bash
cargo test
```

### Compile Noir Circuit

```bash
cd noir-circuit
nargo compile
```

## Tech Stack

- **Rust** — k256 for secp256k1 arithmetic, Axum for the web server
- **Noir** (>= 0.37.0) — ZK circuit language targeting Barretenberg
- **noir_bigcurve** — non-native elliptic curve operations in Noir
- **Barretenberg** — UltraHonk proving backend

## References

- Groth, Malvai, Miller, Zhang — *Constraint-Friendly Map-to-Elliptic-Curve-Group Relations and Their Applications*
- [Semaphore Protocol](https://docs.semaphore.pse.dev)
