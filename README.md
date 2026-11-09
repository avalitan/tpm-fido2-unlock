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
```

The test creates a fresh private swtpm, never opens a hardware TPM, and checks
repeat unsealing without global flushes, authenticated-envelope tampering,
revoked/new epochs, future UKI prediction approval and both phase profiles. VM boot validation belongs to the consuming
configuration; unit policy tests cannot establish a physical trust chain.
