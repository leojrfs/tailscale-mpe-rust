# Portable core and forwarder fixes

This fork keeps the embedded `no_std + alloc` core and adds a Linux/desktop
`wireguard` feature that exposes BoringTun 0.7.1's complete WireGuard protocol
state machine. Adapters using it must drive its timers, drain queued output,
validate tunnel source addresses against the netmap, and keep peer state across
transport reconnects. The minimal embedded `wg` demo is retained for firmware
compatibility; the Linux forwarder uses `wireguard` instead.

`noise::start_with_version` binds the handshake header and prologue to the
advertised capability version. `noise::start` now defaults to version 130,
matching the updated example configuration. Noise frames enforce the 4096-byte
total limit, reject short records from their header, and advance receive nonces
only after authentication. HTTP/2 limits frame allocation, validates control
frame shapes and answers PING; STUN rejects truncated messages.

`filter` implements node/source binding, IPv4 CIDRs and ranges, destination
protocol/port checks, source capabilities and incremental named filter updates.
Absent initial policy denies access; clearing or deleting grants revokes them.

The native test harness is enabled. From the repository root, with a standard
Rust toolchain (override the firmware toolchain/target if needed):

```sh
RUSTUP_TOOLCHAIN=1.93.0 cargo test -p tailscale-core \
  --target aarch64-unknown-linux-gnu --features wireguard
RUSTUP_TOOLCHAIN=1.93.0 cargo clippy -p tailscale-core \
  --target aarch64-unknown-linux-gnu --all-targets --features wireguard -- -D warnings
```

Change the explicit native target for your host. The root `.cargo/config.toml`
defaults to ESP32, so native tests must override it. The test suite covers Noise
version negotiation and record boundaries, oversized H2 frames, STUN truncation,
ACL port/source checks and revocation, WireGuard MAC/timestamp/transport replay
rejection, forged counters, and cookie challenge/retry.
