# Rusp

Send a file to another machine with a short code you can read out loud.

```console
$ rusp send holiday-photos/
sending 214 files (1.8 GiB)

  on the other machine, run:

    rusp receive k7m2-cotton-harbor-tiger-pencil
```

```console
$ rusp receive k7m2-cotton-harbor-tiger-pencil
the sender is offering 214 files (1.8 GiB) into .
accept? [Y/n] y
⠋ [============>               ] 812 MiB/1.8 GiB  94.1 MiB/s  eta 11s  holiday-photos/IMG_2214.jpg
✓ received 214 files (1.8 GiB) into .
```

Rusp is a Rust file-transfer tool in the spirit of [croc]. The code is the
whole authentication story: it is turned into a strong shared key by a
password-authenticated key exchange, both sides prove they derived the same key
before any data moves, and everything after that is encrypted end to end. A
relay in the middle learns two IP addresses, a timestamp and a byte count —
not the file, not its name, and not the code.

[croc]: https://github.com/schollz/croc

## Contents

- [Features](#features)
- [Installation](#installation)
- [Quick start](#quick-start)
- [Sending](#sending) · [Receiving](#receiving) · [Directories](#directories)
- [Connectivity](#connectivity) · [Running a relay](#running-a-relay)
- [Configuration](#configuration)
- [Security](#security)
- [Architecture](#architecture)
- [Performance](#performance)
- [Development](#development) · [Testing](#testing)
- [Roadmap](#roadmap)
- [License](#license)

## Features

- **One short code.** Four words and a room tag: `k7m2-cotton-harbor-tiger-pencil`.
- **Encrypted end to end.** SPAKE2 for key agreement, ChaCha20-Poly1305 per
  frame, verified before any file data moves.
- **Zero configuration on a local network.** Two machines on the same network
  find each other by themselves.
- **Relay for everything else.** Both sides dial out, so it works from behind
  NAT. You run the relay; Rusp ships no default.
- **Files, directories, whole trees.** Nested directories, empty directories,
  unicode names, spaces, very large files, thousands of small ones.
- **Verified, not just transferred.** Every file is hashed with BLAKE3 and
  checked before it is moved into place. A transfer is only reported as
  successful after that check passes.
- **Progress, rate and ETA**, and a clean `Ctrl+C` that leaves nothing
  half-written.
- **Linux, macOS and Windows**, from one codebase with no platform-specific
  transfer logic.

## Installation

From source, with a Rust 1.85 or newer toolchain:

```console
$ cargo install --path .
```

Or build a release binary and put it somewhere on your `PATH`:

```console
$ cargo build --release
$ install -m755 target/release/rusp ~/.local/bin/
```

There is nothing to configure for local transfers, and no daemon to run.

## Quick start

Two machines on the same network need nothing at all:

```console
# on the machine with the file
$ rusp send report.pdf

# on the other machine
$ rusp receive k7m2-cotton-harbor-tiger-pencil
```

Across the internet, both sides need to agree on a relay. Run one somewhere
reachable, then point both machines at it:

```console
$ rusp relay --listen 0.0.0.0:9110 --token "a shared secret"     # on a server
$ export RUSP_RELAY=relay.example.com:9110                       # on both machines
$ export RUSP_RELAY_TOKEN="a shared secret"
```

## Sending

```console
$ rusp send file.txt
$ rusp send photo.jpg document.pdf notes.md
$ rusp send ./my-folder
```

| Option | What it does |
| --- | --- |
| `--code <CODE>` | Use a code you chose instead of a generated one |
| `-w, --words <N>` | Words in the generated code (3–12, default 4) |
| `--follow-symlinks` | Send what symlinks point at instead of skipping them |
| `--relay <ADDR>` | Relay to use, as `host` or `host:port` |
| `--relay-token <T>` | Token a private relay requires |
| `--no-relay` / `--no-lan` | Turn off one of the two paths |

Two files named `photo.jpg` from different directories arrive as `photo.jpg`
and `photo (2).jpg` rather than one overwriting the other.

Symlinks are skipped by default and reported, because following them can pull
in files from outside the directory you named.

## Receiving

```console
$ rusp receive                                    # prompts for the code
$ rusp receive k7m2-cotton-harbor-tiger-pencil
$ rusp receive -o ~/Downloads k7m2-cotton-harbor-tiger-pencil
```

| Option | What it does |
| --- | --- |
| `-o, --out <DIR>` | Where to write (default: the current directory) |
| `--on-conflict <P>` | `rename` (default), `overwrite`, `skip`, `fail` |
| `--overwrite` | Short for `--on-conflict overwrite` |
| `-y, --yes` | Accept without asking |

The offer is shown before anything is written, and nothing touches the disk
until you accept. With `skip`, files you already have are never even sent —
the receiver leaves them out of the request, so their bytes never cross the
network. With `fail`, a single collision refuses the whole transfer and
nothing is written.

When stdin is not a terminal the offer is accepted automatically; you already
supplied a code, and `--yes` makes that explicit in scripts.

## Directories

```console
$ rusp send ./project
```

The whole tree is sent, parents before children. Empty directories survive the
trip. On Unix the executable bit is carried across — and only the executable
bit, so a peer cannot hand you a setuid or world-writable file.

## Connectivity

Rusp tries two paths, and the **receiver decides** which one is used so the two
sides can never pick differently:

1. **Local network.** The receiver multicasts a query naming the room; a sender
   on the same segment answers with its port and the receiver connects
   directly. No relay, no configuration, and the data never leaves the network.
2. **Relay.** Both sides make outbound connections to a relay and meet in a
   room, which works from behind almost any NAT or firewall.

There is **no NAT hole punching**. Two peers behind separate NATs need a relay.
That is a real limitation rather than a detail — see the [roadmap](#roadmap).

Rusp ships **no default relay**. There is no public Rusp infrastructure, and
pointing your traffic at a stranger's server by default would be the wrong
default even though the traffic is encrypted. Local transfers work out of the
box; anything wider needs a relay you choose.

## Running a relay

```console
$ rusp relay --listen 0.0.0.0:9110 --token "a shared secret"
```

| Option | Default | What it does |
| --- | --- | --- |
| `-l, --listen <ADDR>` | `0.0.0.0:9110` | Address to listen on |
| `--token <TOKEN>` | none | Require this token from every client |
| `--max-rooms <N>` | 1024 | Most rooms held at once |
| `--room-timeout <SECS>` | 600 | How long a half-open room is kept |

A relay pairs two clients by room name and then copies bytes. It holds no keys,
never sees a code, and cannot decrypt anything it forwards. Set a token unless
you intend the relay to be public.

When a room is already in use, or the relay is at capacity, a new client is
**refused** rather than displacing anybody — otherwise a stranger could knock
over transfers in progress just by opening rooms.

## Configuration

Settings come from four places, each overriding the one before: built-in
defaults, the config file, `RUSP_*` environment variables, and command-line
flags.

```console
$ rusp config path     # where the file lives
$ rusp config init     # write a commented starter file
$ rusp config show     # what is actually in effect
```

```toml
# ~/.config/rusp/config.toml
relay = "relay.example.com:9110"
relay-token = "a shared secret"
lan-discovery = true
words = 4
output-dir = "~/Downloads"
on-conflict = "rename"
```

Environment variables: `RUSP_RELAY`, `RUSP_RELAY_TOKEN`, `RUSP_OUTPUT_DIR`,
`RUSP_CONFIG`.

## Security

### The threat model

Rusp assumes the network is hostile and the relay is untrusted. It protects
the confidentiality and integrity of what you send against anyone who is not
holding the code, including whoever runs the relay.

It does **not** protect against someone who learns the code before the
transfer completes. The code is the credential; treat it like one.

### How the code becomes a key

A code has two parts, split at the first `-`:

```
k7m2-cotton-harbor-tiger-pencil
^^^^ ^-------------------------
room           secret
```

The **room** is public routing information — the only part a relay or the
local network ever sees. The **secret** never leaves the machine.

1. **Key agreement.** The secret words are the password in a [SPAKE2] exchange
   (`spake2`, RustCrypto). SPAKE2 is a balanced PAKE: the wire carries only
   blinded group elements, so neither the relay nor an eavesdropper can mount
   an offline dictionary attack on the code. The blinding scalars are
   ephemeral, so learning the code afterwards does not reveal past sessions.
2. **Key schedule.** The SPAKE2 output is bound to a hash of the whole
   handshake — magic, negotiated version, both `Hello` messages, both SPAKE2
   elements, each absorbed with its length so no two different handshakes can
   produce the same transcript. HKDF-SHA256 expands it into four independent
   keys: one AEAD key per direction, one confirmation key per direction.
3. **Key confirmation.** Before any user data moves, each side proves it
   derived the same keys with an HMAC-SHA256 tag over the transcript,
   compared in constant time. A wrong code fails here.
4. **Record protection.** Every frame is sealed with ChaCha20-Poly1305 under a
   direction-specific key and a counter nonce.

[SPAKE2]: https://datatracker.ietf.org/doc/html/rfc9382

### Entropy and guessing

Each word is drawn uniformly from a 1024-word list, so a code is worth exactly
10 bits per word — 40 bits at the default of four words.

That is more than the threat model strictly needs, because **an attacker gets
exactly one guess**. A failed key confirmation ends the transfer; Rusp does not
retry with the same code, and a code is never reused. The extra margin covers
codes that leak after the fact.

A handshake that fails *before* the code is used — a port scanner, a version
mismatch, something that is not Rusp at all — costs nobody a guess, so the
sender keeps waiting for the real peer in that case.

### What each attacker sees

| Attacker | Sees | Can do |
| --- | --- | --- |
| Passive eavesdropper | Two IPs, timing, byte counts, the room tag | Nothing else |
| Relay operator | The same, plus that it paired two clients | Refuse or disrupt transfers; not read them |
| Active attacker on your LAN | The room tag in a discovery query | Impersonate the sender's address, spend their one guess, fail, and thereby stop the transfer |
| Someone who has the code | Everything | Everything — the code is the credential |

File names, sizes and the whole manifest travel inside the encrypted channel.
The integration suite records every byte a real transfer puts on the wire and
asserts that the payload, the code, each individual code word and even the file
name are all absent from it.

### Integrity

- Every frame is authenticated by ChaCha20-Poly1305.
- The nonce is a counter that is never transmitted, so a frame that is
  replayed, reordered, duplicated, dropped or truncated decrypts under the
  wrong counter and fails. One bad frame poisons the stream: the connection is
  abandoned rather than resynchronised.
- Every file is hashed with BLAKE3 as it is written and checked against the
  sender's hash before the file is moved into place. A mismatch deletes the
  partial file and fails the transfer.
- Data is written to a `.rusp-part` file and renamed into place only after it
  verifies, so a dead transfer never leaves a truncated file under a finished
  name. Cleanup is tied to the writer's lifetime, so no failure path — error,
  cancellation or panic — can skip it.

### Hostile paths and hostile peers

Every path in a manifest comes from the other machine and is treated as such.
The rule is **reject, do not repair** — a path that is not obviously safe is
refused and named rather than quietly rewritten:

- absolute paths, `C:\...`, `\\server\share`, `\\?\...`;
- any `..` component, in either slash direction (`/` and `\` are both
  separators on every platform, so a Windows-style path cannot hide a traversal
  from a Unix receiver);
- `.` and empty components;
- control characters, including NUL;
- names over 255 bytes, paths over 4096;
- Windows device names (`CON`, `NUL`, `COM1`…) on **every** platform;
- names with a trailing dot or space, which Windows silently rewrites.

Beyond paths:

- Directories are created one component at a time and never followed through a
  symlink, so a link planted in the destination cannot redirect a write.
- The receiver caps each file at the size it agreed to, so a sender that
  declares one byte cannot then stream four gigabytes onto your disk.
- Frame sizes are checked before anything is allocated, and negotiated limits
  can only ever shrink.
- The relay bounds concurrent handshakes, expires idle rooms, frees a room the
  moment a waiting client hangs up, and compares tokens through BLAKE3 so the
  check is constant time.

### Reporting a problem

Please open an issue. There is no public relay to compromise; the interesting
surface is the code in this repository.

## Architecture

```
              cli ──▶ app
                       │
                       ▼
                   transfer  ─────▶ files      paths, scanning, safe writes
                       │       └──▶ ui         progress events → a bar
                       ▼
                   protocol             versioned messages, framing
                       │
                       ▼
                    crypto              SPAKE2, HKDF, ChaCha20-Poly1305
                       │
                       ▼
                     net                LAN discovery, relay, TCP
```

Each layer knows only about the one beneath it:

| Module | Responsibility |
| --- | --- |
| `net` | Produces a byte stream. Knows nothing about files or messages. |
| `crypto` | Turns a byte stream into an authenticated, encrypted one. |
| `protocol` | The versioned messages that stream carries, and their framing. |
| `files` | The filesystem, including everything a hostile peer might put in a path. |
| `transfer` | Sender and receiver state machines; emits progress events. |
| `ui` | Renders those events. Nothing below it depends on a terminal. |
| `app` | The only module that combines configuration, terminal and engine. |

The transfer engine has no terminal dependency, which is why every test in this
repository drives the real library rather than a stub, and why the whole
protocol can be exercised over an in-memory pipe.

### The protocol

```
sender                                        receiver
  |  "RUSP" magic                                   |
  |<----------------------------------------------->|
  |  Hello { versions, role }                       |   in the clear
  |<----------------------------------------------->|
  |  SPAKE2 element                                 |
  |<----------------------------------------------->|
  |  key confirmation tag                           |   or both sides abort
  |<----------------------------------------------->|
  |============== encrypted from here ==============|
  |  Capabilities                                   |
  |<----------------------------------------------->|
  |  Offer { manifest }                             |
  |------------------------------------------------>|
  |<------------------------------------------------|  Accept / Decline
  |  FileStart, Data…, FileEnd { hash }             |
  |------------------------------------------------>|
  |  … repeated per file, with no reply in between   |
  |  Complete { files, bytes }                      |
  |<----------------------------------------------->|
```

Frames are length-prefixed, with the limit checked before anything is
allocated. Control messages are MessagePack with **named** fields, so optional
fields can be added within a version; file data never goes through serde at all
and travels as raw bytes behind a nine-byte header.

Version ranges are negotiated up front and both sides fail with a message
naming the versions rather than somewhere deep in a decode. `EntryKind`,
`FailureCode` and the capability feature set are open-ended, so compression,
resume or parallel streams can be added without a version bump.

There is deliberately **no per-file acknowledgement**: waiting for one would
cost a network round trip per file, which is what dominates a transfer of
several thousand small files.

## Performance

- File data is never buffered whole. A 100 GB file uses the same memory as a
  100 KB one.
- The data path performs **no copy of file bytes**: a chunk is read from the
  file straight into the frame buffer, encrypted in place, and written with a
  single `write_all`. Buffers are allocated once and reused, so a long transfer
  does no per-frame allocation.
- 256 KiB chunks, so per-frame overhead disappears against the payload while a
  few in-flight chunks stay a few megabytes rather than a few hundred.
- Backpressure comes from the socket: a slow receiver slows the reader rather
  than filling memory.
- Progress redraws are capped at 12 Hz. At a gigabit the engine emits thousands
  of events a second, and redrawing on each would cost more than the transfer.
- BLAKE3 for hashing, ChaCha20-Poly1305 for encryption — both fast in software
  on machines without AES instructions.

### Measured

On one Linux machine, a 500 MB file through a relay running on the same host —
so every byte is encrypted, decrypted, and copied twice:

| | |
| --- | --- |
| Peak RSS, sender | 5.0 MB |
| Peak RSS, receiver | 5.0 MB |
| Throughput | ~78 MB/s end to end |

Memory does not move with file size; that is the point of the number. Reproduce
it with `cargo build --release` and any large file. Build with `--release`
before measuring anything: a debug build is roughly an order of magnitude
slower at both hashing and encryption.

## Development

```console
$ cargo fmt
$ cargo clippy --all-targets -- -D warnings
$ cargo test
$ cargo build --release
```

The crate is a library plus a thin binary. `#![forbid(unsafe_code)]` — there is
no `unsafe` anywhere in Rusp.

## Testing

```console
$ cargo test                    # everything
$ cargo test --lib              # unit tests
$ cargo test --test transfer    # end-to-end transfers
$ cargo test --test security    # security properties
$ cargo test --test cli         # the real binary, two processes
```

Unit tests cover codec round-trips, the key schedule, nonce discipline, path
sanitisation, config layering and CLI parsing. The integration suites run real
peers over a real relay against real files: directory trees, unicode names,
empty files and directories, multi-megabyte files, hundreds of small files, and
every conflict policy.

Each test in `tests/security.rs` names an attack and asserts how it fails.
Nothing is stubbed and no test asserts on an implementation detail it could
pass by accident.

## Roadmap

Not implemented today, and the architecture leaves room for each:

- **Resume interrupted transfers.** The manifest and per-file offsets are
  already in the protocol; the capability set is where it would be announced.
- **NAT hole punching**, so two peers behind separate NATs need no relay. It
  becomes another `Route` and another arm in the connection race.
- **Compression**, negotiated through the capability feature set.
- **Parallel streams** for high-latency links.
- **IPv6 local discovery.** Discovery is IPv4 multicast and broadcast today;
  relayed and direct connections already work over IPv6.
- **Transfer history**, and shell completions.

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache 2.0](LICENSE-APACHE), at your
option.

The code word list is derived from the [EFF Long Wordlist][eff], by the
Electronic Frontier Foundation, licensed CC BY 3.0 US. The derivation is
documented in `src/code/wordlist.rs`.

[eff]: https://www.eff.org/dice
