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

This version preserves the prototype's v1 policy reference and AES-GCM AAD for
existing sealed bundles. The policy reference still contains the historical
`nixos-trial` namespace. PCR4/7/9 are defaults, not a universally correct policy.
The phase profile specifically requires initially-zero SHA256 PCR11, checks it
AFTER PolicyAuthorize, and extends it before switch-root. It is not validated
for Lanzaboote/UKIs or hibernation. Do not treat enabling the module as secure
physical provisioning.

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

The generic tool does not advance epochs, rotate/reseal enrollments, delete TPM
objects, or retire old slots. Transactional epoch activation, offline approval
workflows and hardware-backed NV lifecycle policies still need implementation
and validation. Epoch advancement revokes automatic unsealing, not EFI execution.
Python/subprocess memory is not guaranteed zeroized.

## Tests

```sh
nix flake check
# Or Python with cryptography + tpm2-pytss and swtpm on PATH:
python3 tests/test_provider.py
```

The test creates a fresh private swtpm, never opens a hardware TPM, and checks
repeat unsealing without global flushes, authenticated-envelope tampering,
revoked/new epochs and phase closure. VM boot validation belongs to the consuming
configuration; unit policy tests cannot establish a physical trust chain.
