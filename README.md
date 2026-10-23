# xmip-core-secret

The key home (ADR-0063 clause 4): where Xmip's keys come from. Created on the
owner's word of 2026-09-25, when he chose the platform's key store, pluggable,
over a vault only or PKCS#11 only.

## What it is

- **`KeyStore`** — wraps a data key under a named key-encryption key, creating
  that key when it is absent; unwraps it again; says which store it is. A
  missing key-encryption key on unwrap is `SecretError::MissingKek`, naming the
  key and the store, and is never answered by creating one: a new key cannot
  open what the old one sealed.
- **`DataKey`** — a 256-bit key, and the one place the estate seals data at
  rest: AES-256-GCM under a fresh random nonce with the value's place as
  associated data (`seal`, `open`), HKDF-SHA-256 for a key per purpose
  (`derive`), HMAC-SHA-256 for a name that can be looked up without saying
  what it names (`keyed_hash`). The cipher and the keyed hash are set up
  from the key once, at their first use, and kept with it: a Storage node
  seals, opens and hashes some sixty times a Message under one key, and set
  them up again each time until 2026-10-21. Through aws-lc-rs, the crypto
  `xmip-core-library-tls` already builds (rustls's default provider, with
  `prebuilt-nasm`, so a Windows build needs no NASM). The key and the nonce
  are drawn from `xmip-core-library-codec`'s `random`, the operating system's
  random source every key in the estate comes from. `handed` and `taken`
  are the one way a key leaves its node: a primary Storage node hands each
  database's key to its standby inside Xmip's mutual TLS, and the standby
  wraps it under its own key-encryption key (ADR-0063, amendment
  2026-10-22).
- **`KekHolder` and `Held`** — a technology that keeps a key-encryption key as
  bytes implements `KekHolder` (read, create, never replace); `Held` makes it a
  `KeyStore`, so the wrapping is here once and no technology carries it.
- **`private_file`** — how every key and identity the estate keeps on disk
  is written, once: the key-encryption keys here, a node's certificate and
  key and the cluster's authority (`xmip-core-provision` and its
  technologies), an ACME account key, and a person's operator key, which
  the .NET surfaces reach through the runtime's `xmip_operator_request_v1`.
  The bytes go to a file created beside the one they become, owner-only
  before the first byte — mode `0600` on Unix; on Windows an access list
  granting the user the process runs as and `SYSTEM` full control and no one
  else, protected from inheritance — then synced, then moved into place:
  `replace` by a rename, `create` by a link that refuses a file already
  there. On Unix the directory is synced after, so the switch survives a
  crash; Windows journals it. On Windows a file another process holds for a
  moment — a virus scanner reading what was just written — is replaced
  anyway where it is held with delete sharing (the standard library's
  rename with POSIX semantics), and a written file held so is waited out a
  millisecond at a time, five times at most; a switch that fails leaves no
  written file behind (open problem 49, resolved 2026-10-23). A directory it creates is owner-only too
  (`0700`, or the same list inherited by what is made inside); one already
  there keeps what it has. `replace_readable` keeps a file that is not
  secret — a chain, the anchors a surface trusts — whole and synced the same
  way, readable as its directory lets, and `create_readable` writes one
  never over a file already there — the chain a person's `--sign --out`
  names. A file written and never switched is
  named `.<name>.<16 hex>.new`; `sweep` removes exactly those, and whoever
  opens a folder of private files calls it first. `owner_only` and
  `described` say the Windows list wanted and the one a path has, for tests.
- **`KeyDirectory`** — the file rules a store that keeps its keys as files
  shares: a key is `<directory>/<name>.kek`, a new one a private file
  created for it — never over one already there — and a failure names the
  file. `file` and `dpapi` keep their keys through it and add only what is
  theirs: the modes and ownership `file` checks, the sealing `dpapi` does.
- **`KekName`** — one to sixty-four letters, digits, `.`, `_`, `-`: safe as a
  file name, a keychain account and a PKCS#11 label alike.
- **`fixture::Memory`**, behind the `test-support` feature — a holder in memory
  for the tests of what uses a key store. Never in a production build.

## Its technologies

Mounted beside `.src` (ADR-0049), one per platform:

| technology | platform | where the key-encryption key is |
| --- | --- | --- |
| `dpapi` | Windows | a file sealed by `CryptProtectData`, user scope, under the Service Identity |
| `file` | Linux, every Unix | a file `0600` in a directory `0700`, owned by the Service Identity; refused when either is wider |
| `keychain` | macOS | a generic password item of the Service Identity's keychain |

Reserved in `architecture.toml`, not built: `pkcs11`, `vault`,
`azure-key-vault`, `aws-kms` — a key that never leaves its module implements
`KeyStore` itself and seals inside the module — and `keyring`, the Linux
kernel keyring, which holds a key only until the machine restarts and so
cannot be where a key-encryption key lives.

## What it is not

Not rotation or recovery yet: a lost key-encryption key is lost data
(ADR-0063, Consequences), and both belong to this capability's next design.
Not the secrets a transport presents — the home phase D's secrets were
missing (`market-position.md` section 8) — though that is to be here too.

## The system call

The Windows access list is set and read through `windows-sys` in
`.src/private_file/dacl.rs`, the one file of this crate that allows unsafe
code (ADR-0050, amendment 2026-09-25); every block there says where its
pointers come from, how long they live and who frees them. `Cargo.toml` sets
`unsafe_code = "deny"`, and `test/Unsafe.Test.ps1` in the estate lists the
file. A file is created with no sharing and its list set on that handle
before a byte is written, so no other handle can be opened before the list is
there.

## Used by

`xmip-core-persist`, whose `EncryptedStore` seals every record with a
`DataKey` wrapped here; `xmip-core-provision`, `-acme` and `-internal-ca`,
and the runtime's section 19 export, through `private_file`.

## Verification

`cargo clippy --all-targets -- -D warnings` and `cargo test`: a private file
and the directories it creates are the owner's alone (the mode on Unix, the
access list on Windows); a file is replaced whole and created never over one,
no written file left beside it; a crash after the bytes are written and
before the switch leaves the file as it was. Run on Windows and on Linux.
The workflow is manual-only and calls the versioned shared workflow at
`IlleNilsson/.github@v1`.
