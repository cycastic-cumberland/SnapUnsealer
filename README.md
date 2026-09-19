# SnapUnsealer

A small macOS app that holds a vault-backup OpenPGP private key encrypted at
rest behind the Secure Enclave + Touch ID, and decrypts `.snap.gpg` backup
files on demand — without the raw key ever touching disk.

## Why

Decrypting an off-cluster encrypted Vault backup normally means keeping the
backup's raw `.asc` private key importable in a GnuPG keyring, in plaintext,
indefinitely. Anyone with filesystem access to that machine at rest can
decrypt every past and future backup. SnapUnsealer closes that gap: the key
is wrapped under a non-exportable Secure Enclave key and only ever unwrapped
into locked, zeroed-after-use memory for the moment a decrypt actually runs.

## How it works

**Enroll (once):**
1. Pick the raw `.asc` file, and its passphrase if it has one.
2. A Secure Enclave P-256 key-agreement key is generated, gated by Touch ID
   (`.biometryCurrentSet`).
3. The `.asc` bytes + passphrase are envelope-encrypted (ephemeral ECDH →
   HKDF → AES-GCM) under that key and the wrapped blob is stored in
   Keychain. The original file and passphrase are never needed again.

**Decrypt (each drill):**
1. Pick a `.snap.gpg` input and a destination path.
2. Touch ID fires when the Secure Enclave key is reloaded to unwrap the
   envelope.
3. The unwrapped key lives only in an `mlock()`'d buffer, zeroed
   immediately after [ObjectivePGP](https://github.com/krzyzanowskim/ObjectivePGP)
   decrypts the snapshot — never written to a temp file or ramdisk.
4. Only the final decrypted `.snap` plaintext is written to disk.

No XPC helper split in this version — decrypt runs inline in the main
process. Single-machine, ad-hoc signed only; no multi-operator distribution.

## Building

Open `SnapUnsealer.xcodeproj` in Xcode and build the `SnapUnsealer` scheme
(macOS), or from the command line:

```bash
xcodebuild -project SnapUnsealer.xcodeproj -scheme SnapUnsealer -destination 'platform=macOS' build
```

Run the test suite (crypto round-trips, wrap/unwrap, ObjectivePGP fixture
decrypts — all against real fixtures, no mocks):

```bash
xcodebuild -project SnapUnsealer.xcodeproj -scheme SnapUnsealer -destination 'platform=macOS' test
```

## Installing locally

This is a single-machine, ad-hoc signed tool — not notarized, not meant for
distribution. Copy the built app straight into `/Applications` without
going through anything that adds a quarantine flag (a browser download,
AirDrop, Mail, etc.):

```bash
ditto path/to/SnapUnsealer.app /Applications/SnapUnsealer.app
```

If it ever does pick up a quarantine attribute (e.g. it was zipped and
re-downloaded), clear just that flag rather than disabling Gatekeeper
system-wide:

```bash
xattr -d com.apple.quarantine /Applications/SnapUnsealer.app
```

Note: the app is ad-hoc signed, and that signature is a hash of the binary
itself. Rebuilding changes it, and since the enrolled Secure Enclave key's
Keychain access is bound to that signature, a rebuild can orphan a
previously enrolled key — re-enroll if Keychain access breaks after
updating the installed copy.

## Security notes

- Passphrase is only ever asked for once, at enrollment — a real DR drill
  needs nothing but Touch ID.
- Keychain items (`net.cycastic.SnapUnsealer.wrappedKey`,
  `net.cycastic.SnapUnsealer.seKey`) are readable as raw bytes via Keychain
  Access — this is expected and harmless. One holds AES-GCM ciphertext, the
  other an opaque Secure Enclave token that isn't reconstitutable into a
  usable key without the specific physical Secure Enclave chip that created
  it. Touch ID is enforced by the Secure Enclave at actual key-use time, not
  by a Keychain-item ACL.
- No crash reporting/analytics SDK, core dumps disabled at launch
  (`setrlimit(RLIMIT_CORE, 0)`).
- `mlock()` failures are logged, not fatal — best-effort hardening, not a
  hard dependency the decrypt flow can be blocked by during a real DR event.
