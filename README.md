# tpm-fido2-unlock

Experimental TPM-policy **and** FIDO2 unlocking for LUKS2, with a NixOS systemd
initrd module. The normal path requires an approved measured boot, the current
TPM-backed security epoch, an open early-boot phase, and the FIDO2 authenticator.
A separate recovery passphrase remains essential.

The provider seals a random wrapping key, not a standalone disk key. That key
authenticates/decrypts an AES-256-GCM envelope containing the credential ID, salt,
RP and interaction settings. libfido2 derives the actual LUKS secret. No plaintext
FIDO2 parameters are added to LUKS token metadata or the Nix store.

## Status

The originating NixOS VM tested combined unlocking of its actual root, rejected
unapproved measurements, recovered by passphrase, and rejected unsealing after
phase closure. Its old independent FIDO2 slot was retired after validation.
That was unsigned systemd-boot with an emulated CanoKey, **not** proof of physical
Solo touch, a Secure Boot chain, or physical TPM antirollback.

Version 1 preserves the prototype's historical `nixos-trial` policy reference
and AES-GCM AAD for existing bundles. It defaults to PCR4/7/9 and requires
initially-zero PCR11 AFTER PolicyAuthorize. This legacy profile cannot be used
unchanged for a measured UKI.

Version 2 adds a distinct UKI policy reference, PCR4/7/11 approvals calculated
before boot, multiple approvals per epoch, and a mandatory zero-PCR15 early-phase
guard after PolicyAuthorize/NV. The originating VM has boot-tested two signed
systemd-stub UKIs, exact predicted PCRs, first-boot automatic unlock, rejection of
a changed UKI, and late-unseal denial. The consuming VM subsequently verified custom-key
firmware Secure Boot, rejection of a changed UKI before Linux ran, and signed
passphrase recovery. This is a VM integration result, not automatic physical
provisioning by this package. Hibernation and physical provisioning remain unvalidated.

## Package and module

With flakes, add this repository as an input and import
`inputs.combinedUnlock.nixosModules.default`. Make its nixpkgs input follow your
system's nixpkgs. Without flakes, import `./nix/module.nix` directly; the module
uses the caller's `pkgs`. No flake is required by the implementation.

Example (replace paths with the actual machine's values):

```nix
{
  imports = [ ./components/tpm-fido2-unlock/nix/module.nix ];

  boot.initrd.luks.devices.cryptroot.device = "/dev/disk/by-uuid/REPLACE-LUKS-UUID";
  boot.initrd.combinedUnlock = {
    enable = true;
    bundleMount = {
      device = "/dev/disk/by-uuid/REPLACE-ESP-UUID";
      mountPoint = "/run/combined-unlock-esp";
    };
    providers.cryptroot = {
      bundle = "/run/combined-unlock-esp/root/bundle.json";
      fido2Device = "auto"; # Exactly one token, or an explicit /dev/hidraw path.
    };
  };
}
```

`bundle` is a runtime STRING, not a Nix path literal containing secrets. The
bundle itself is public ciphertext plus public policy data. Keep authority
private keys, owner authorization and recovery material elsewhere.

The module wires a root-only socket into the named LUKS device with a generated
cryptsetup-unit **drop-in**, retains interactive password fallback, and closes
its phase before cleanup/switch-root. Remove old standalone token crypttab
options on selected devices; the module rejects those options. It does not
format disks, create signing keys, enroll slots, auto-approve boots or increment
epochs. Installing it alone cannot unlock a fresh installation.

For another consumer, set `providers.NAME.configureLuks = false` and use its
`/run/combined-unlock/NAME.sock`. Add that consumer to `phaseAfter` so closure
waits for it. Multiple configured volumes share the phase boundary. An optional
read-only bundle mount is unmounted after consumers finish.

Flake exports:

- `packages.SYSTEM.default` / `combined-unlock`: boot provider and phase closer.
- `packages.SYSTEM.management`: separate `combined-unlock-manage` command.
- `nixosModules.default` / `combinedUnlock`: reusable NixOS module.
- `checks.SYSTEM.policy`: isolated software-TPM test.

x86_64-linux is the tested platform; aarch64-linux exports are provided but have
not been built or boot-tested.

## Explicit provisioning and enrollment

The management package is separate and excluded from initrd. Review the target
device/slot and preserve a tested recovery path before enrollment. Begin on a
disposable volume. `enroll` never formats a device or deletes an existing slot.

1. Establish a protected TPM owner authorization separately and retain its file
   securely. `provision` uses EXISTING owner authorization; it never changes the
   hierarchy password. Do not clear an existing TPM to make provisioning succeed.
2. Choose unused handles (defaults: counter `0x01500020`, parent `0x81010020`), then:

   ```sh
   sudo combined-unlock-manage provision --owner-auth-file /secure/owner.auth
   ```

3. Generate an approval key outside the Nix store:

   ```sh
   combined-unlock-manage keygen --authority /secure/approval.pem
   ```

4. Mount/create the public bundle directory, then enroll a FREE slot explicitly:

   ```sh
   sudo combined-unlock-manage enroll \
     --device /dev/disk/by-uuid/REPLACE-LUKS-UUID --slot 2 --recovery-slot 0 \
     --authority /secure/approval.pem --bundle /boot/root/bundle.json
   ```

   This verifies recovery, makes a nonresident FIDO2 hmac-secret credential,
   seals its encrypted parameters, adds/verifies the new slot and preserves
   previous slots/metadata. It requests presence with no PIN/UV; tokens requiring
   a different interaction profile are not supported yet. Parameters and derived
   keys are never printed. The high-entropy HMAC key uses base64 without newline,
   matching systemd's convention.

5. Boot the new initrd with recovery, inspect/trust its measured state, then
   EXPLICITLY approve it:

   ```sh
   sudo combined-unlock-manage approve --bundle /boot/root/bundle.json \
     --authority /secure/approval.pem
   ```

   Reboot the SAME entry to test automatic unlocking. Editing its initrd changes
   measurements again. A failed boot or recovery boot never auto-signs policies.

Only after successful boot and recovery tests should old standalone TPM/FIDO2
paths be retired separately. Merely adding a new slot does not enforce both
factors while an old independent slot remains. Old headers/backups can restore
retired slots; handle them as part of migration. Enrollment interrupted after
slot addition can leave a new slot without a final bundle: preserve recovery,
inspect the state and clean up explicitly, rather than overwrite/re-enroll.

The generic CLI does not commit epochs, delete TPM objects, or retire old slots.
It can prepare the next UKI epoch with the explicit flags described below. A
low-level management API and the consuming VM driver have tested a staged
transition; production/offline workflows and hardware-backed NV lifecycle
policies still need integration and validation. Epoch advancement revokes automatic unsealing, not EFI execution.
Python/subprocess memory is not guaranteed zeroized.

## Optional pinned-key verification (primary and backup)

The new opt-in path requires a fresh ES256 signature from an enrolled PUBLIC
bootstrap credential before it unseals the secret unlock credential ID/salt.
Solo and compatible YubiKey FIDO2 devices use the same protocol. It verifies
the subsequent unlock assertion too, using its public key inside the sealed
payload, on the same open HID connection. A proof is consumed once; failed
proofs never fall back to the legacy path. This does not authenticate a CTAP
tunnel against a live relay involving your enrolled key.

First establish TPM handles, approval authority and tested recovery as above.
For each key separately, create and prove a public bootstrap identity:

```sh
combined-unlock-manage identity-enroll --output primary-public.json
# Disconnect the primary; attach the backup, then:
combined-unlock-manage identity-enroll --output backup-public.json
```

The default proof is silent (`up=false`, `uv=false`); credential creation still
requires touch. Use `--proof-touch` if the device requires/you want touch for the
bootstrap assertion as well. There is no automatic policy downgrade. PIN/UV-
requiring profiles remain unsupported. Only the ES256 algorithm is accepted.
These public files contain bootstrap IDs and public keys, NOT unlock IDs/salts.
They pin possession of a key enrolled through a trusted setup; this implementation
does not yet verify manufacturer attestation or access factory device keys.

Enroll each key into its own **free** LUKS slot and separate bundle, adding
`--identity primary-public.json` or `--identity backup-public.json` to the
existing `enroll` command. Use the same device, TPM handles/authority and profile
for both; choose distinct bundle paths and slots. Keep the recovery slot.
These enrollments create authenticated parameter payload version 2 (distinct
from the unchanged TPM policy bundle versions). Guarded mode rejects legacy
payloads; adding a public identity alone does not migrate an old enrollment.

Build the one-of-N public allowlist (up to 16 keys):

```sh
combined-unlock-manage identity-policy --output identities.json \
  --key primary primary-public.json /run/combined-unlock-esp/root/primary.json \
  --key backup backup-public.json /run/combined-unlock-esp/root/backup.json
```

Embed that **public** JSON in the trusted signed initrd:

```nix
boot.initrd.combinedUnlock.providers.cryptroot.identityPolicy = ./identities.json;
```

The module copies it into an immutable Nix store file and includes it in initrd.
Its per-key runtime bundle paths replace the provider's legacy `bundle` path
when enabled. Never point the CLI's `--identity-policy` at a mutable ESP file:
that would let an attacker replace the trusted identities. The runtime bundles
remain public ciphertext, selected/unsealed only after a matching proof. An
identity fingerprint inside each authenticated envelope prevents mismatching
identities and bundles. Each entry can point to a single bundle or epoch set.

`auto` still requires exactly one connected token: either primary OR backup.
Both keys connected simultaneously require an explicit device path. Removing
or replacing a token requires a new proof, never continuation on a reopened
connection. Recovery remains available on any failure.

Enable only after disposable-volume and signed-boot tests. Old slots or old
approved boot images can still offer the legacy path until explicitly retired
through the existing migration/epoch workflow; this option alone does not
revoke them. No VM/physical root migration happens automatically. An independent
TPM contribution to the final disk key remains a separate, unimplemented design.

## Optional shared unlock key for several disks

The default is a separate enrollment/key for each volume. To opt into a shared
key, enroll ONE credential and its derived unlock key on all selected volumes,
then configure ONE provider with `shareWith`:

```nix
boot.initrd.luks.devices.diskA.device = "/dev/disk/by-uuid/REPLACE-FIRST-UUID";
boot.initrd.luks.devices.diskB.device = "/dev/disk/by-uuid/REPLACE-SECOND-UUID";
boot.initrd.combinedUnlock.providers.diskA = {
  bundle = "/run/combined-unlock-esp/group/primary.json";
  identityPolicy = ./identities.json;
  shareWith = [ "diskB" ];
};
```

Do not define another provider for `diskB`: its cryptsetup unit receives the key
from the `diskA` provider through its own root-only socket. Overlapping groups,
duplicates, invalid names and groups above 16 volumes are rejected. The phase
closer waits for all member cryptsetup units AND the provider process to finish.
Independent providers serialize token access, including when sharing is disabled.

For enrollment, add `--additional-volume DEVICE SLOT RECOVERY_SLOT RECOVERY_KEY_FILE`
to `enroll --identity ...`, repeated for each extra volume. Example using explicit
placeholder devices and protected recovery files outside the Nix store:

```sh
sudo combined-unlock-manage enroll --profile uki \
  --device /dev/disk/by-uuid/REPLACE-FIRST-UUID --slot 2 --recovery-slot 0 \
  --recovery-key-file /run/first-recovery \
  --additional-volume /dev/disk/by-uuid/REPLACE-SECOND-UUID 2 0 /run/second-recovery \
  --identity primary-public.json --authority /secure/approval.pem \
  --bundle /boot/group/primary.json
```

Every new slot must be free. Each volume's recovery key may differ. All targets,
UUID uniqueness, recovery keys and free slots are checked before credential
creation or slot writes. Metadata is rechecked after token interaction, then
the same derived key is added and verified on each volume. Existing slots and
public-token metadata are preserved. Enroll the backup token separately into
another free slot on each volume and a separate shared bundle; the public
allowlist selects primary OR backup for the whole group.

At boot the first member request triggers one identity proof/unseal/unlock
derivation. The provider keeps the derived key only in its process memory and
sends it once through each member's distinct socket, then exits. A retry on one
socket cannot consume a different member's delivery. No key cache file or
cross-run reuse is introduced: another invocation requires a new proof/touch.
A missing member expires at `keyTimeout`; missing-disk/degraded-root boot still
requires separate policy/integration. With silent identity proof this gives
one unlock touch per group; `--proof-touch` adds the identity touch.

Each volume keeps its independent LUKS master key and recovery slot. Sharing the
unlock secret links access to the volumes in that group. Multi-volume enrollment
is not atomic across disks: a write failure can leave a new slot on earlier
targets without a published bundle. It stops without deleting slots; inspect
and resolve explicitly using retained recovery. Existing enrollments are not
converted merely by setting `shareWith`.

The two-volume path has disposable CanoKey/LUKS/software-TPM tests and generated
NixOS unit checks. Two-disk UKI boot, RAID1/missing-member behavior and physical
Solo/YubiKey validation remain pending; it is not enabled on the installed VM root.

## UKI profile (version 2)

Enroll a distinct free slot with `enroll --profile uki`; the prior slots are
preserved. The new bundle initially has **no approvals**. Configure the consuming
initrd with `boot.initrd.combinedUnlock.phasePCR = 15`. It must start PCR15 at zero
and preserve the mandatory phase-close unit. The tested consumer suppresses
systemd-pcrphase-initrd and predicts raw stub PCR11, without `enter-initrd`.

Prepare expected SHA256 PCR values from trusted built artifacts and a reviewed
EFI/firmware baseline. Then approve before boot:

```sh
sudo combined-unlock-manage approve --bundle /boot/root/bundle.json \
  --authority /secure/approval.pem --expected-pcrs /secure/expected.json
```

The JSON maps exactly `"4"`, `"7"`, `"11"` to 64-character hex values. The tool
computes the TPM PolicyPCR digest from these expected values and signs the
profile/epoch-scoped approval. It verifies the authority and epoch, retains
existing approvals (up to 16), and refuses current-state approval for v2.
**The caller is responsible for deriving and reviewing expected values**; an
arbitrary JSON file is not evidence of a trustworthy boot. No generic UKI
builder/installer or production rebuild integration is included in this package.

The boot provider chooses the approval matching the actual policy digest, then
verifies its signature in the TPM. Epoch and phase checks remain outside
PolicyAuthorize. Switching the bundle's public version/PCR selection cannot
change the enrolled sealed object's policy. Deleting an approval is not durable
revocation while an attacker can restore it within the same epoch.

The VM-specific parent repository supplies a guarded UKI build/sign/predict/
verify/install workflow and its own baseline review. The management signing key
and EFI signing key stay outside the initrd/Nix store. No platform PK is needed
to sign a TPM approval or perform ordinary UKI builds.

## Staged epoch transition

For UKI enrollment, `enroll --profile uki --next-epoch` creates a new FIDO2
credential/LUKS slot and seals for exactly counter+1, without changing the counter
or prior slots. `approve --next-epoch --expected-pcrs ...` approves that immediately
next epoch; old/revoked epochs cannot be repaired by either approval mode.

`management.epoch_set(current, following)` validates two approved adjacent v2
bundles with matching authority/TPM handles and returns a public version-3 routing
container. The provider reads the real counter to choose one child, then enforces
that child's original epoch/phase TPM policy. The container does not replace the
cryptographic policy. Restoring an old-only container cannot roll back the TPM.
A selected public child cannot claim a different epoch or NV index.

`management.advance_epoch(tpm, index, previous, target, owner)` is a LOW-LEVEL
operation for callers that have already persisted and boot-verified their staged
artifacts. It validates one adjacent increment and requires the protected owner
secret. A retry after the counter reached target is a read-only no-op; it never
increments twice. This API alone is not a transactional installer. Callers must
serialize operations, validate recovery, signed boot artifacts, live approvals,
sealed-object policy/metadata, and their durable transaction journal BEFORE the
irreversible increment.

The parent NixOS VM driver has tested staging both epochs, automatic current-
epoch boot, commit, repeated commit, automatic next-epoch boot, old bundle and
old signed-boot rejection, and separate retirement of old slots with recovery
retained. An epoch revokes automatic secret release, not execution of EFI code
that still has a valid firmware signature. TPM clearing/owner/physical-presence
policies and physical token behavior still need hardware validation.

## Tests

```sh
nix flake check
# Or Python with cryptography + tpm2-pytss and swtpm on PATH:
python3 tests/test_provider.py
python3 tests/test_epoch_transition.py
python3 tests/test_identity.py
python3 tests/test_shared_keys.py
```

The test creates a fresh private swtpm, never opens a hardware TPM, and checks
repeat unsealing without global flushes, authenticated-envelope tampering,
revoked/new epochs, future UKI prediction approval and both phase profiles. VM boot validation belongs to the consuming
configuration; unit policy tests cannot establish a physical trust chain.
Identity tests use real ES256 signatures and a simulated CTAP peer for primary/
backup selection, replay, wrong key/RP/credential, changed signatures, single-use
proofs and no unlock requests on failed verification. The optional
`tests/smoke_identity_vm.py` is guarded to the disposable trial and creates a
temporary LUKS image/private swtpm plus two credential pairs on its CanoKey;
it does not access the installed root or system TPM. One emulator with two
credentials is not validation of two physical devices or vendor attestation.
`test_shared_keys.py` checks Unix-socket fanout, activation FDs, single-use
per-volume delivery, bounded lifetimes/locking and enrollment preflight/failure
handling without real devices. Optional `tests/smoke_shared_vm.py` tests two
disposable encrypted images with independent recovery keys, primary/backup
shared enrollment and one proof/derivation supplying both disk sockets.
