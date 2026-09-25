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
  what it names (`keyed_hash`). Through aws-lc-rs, the crypto
  `xmip-core-library-tls` already builds (rustls's default provider, with
  `prebuilt-nasm`, so a Windows build needs no NASM).
- **`KekHolder` and `Held`** — a technology that keeps a key-encryption key as
  bytes implements `KekHolder` (read, create, never replace); `Held` makes it a
  `KeyStore`, so the wrapping is here once and no technology carries it.
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

## Used by

`xmip-core-persist`, whose `EncryptedStore` seals every record with a
`DataKey` wrapped here.

## Verification

`cargo clippy --all-targets -- -D warnings` and `cargo test`. The workflow is
manual-only and calls the versioned shared workflow at `IlleNilsson/.github@v1`.
