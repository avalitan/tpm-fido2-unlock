{ config, lib, pkgs, utils, ... }:
let
  cfg = config.boot.initrd.combinedUnlock;
  package = import ./package.nix { inherit pkgs; };
  names = builtins.attrNames cfg.providers;
  configured = lib.filterAttrs (_: value: value.configureLuks) cfg.providers;
  members = name: [ name ] ++ cfg.providers.${name}.shareWith;
  managedNames = lib.concatMap members (builtins.attrNames configured);
  ownerOf = volume: builtins.head (lib.filter (name: builtins.elem volume (members name)) names);
  keyPath = name: "/run/combined-unlock/${name}.sock";
  unitName = name: "combined-unlock-${name}";
  cryptUnits = map (name: "systemd-cryptsetup@${utils.escapeSystemdPath name}.service") managedNames;
  mount = cfg.bundleMount;
  phase = "combined-unlock-close-phase";
  identityPolicies = lib.mapAttrs (name: value:
    if value.identityPolicy == null then null else
      pkgs.writeText "combined-unlock-${name}-identities.json" (builtins.readFile value.identityPolicy)
  ) cfg.providers;
in {
  options.boot.initrd.combinedUnlock = {
    enable = lib.mkEnableOption "experimental combined TPM-policy and FIDO2 unlocking";
    providers = lib.mkOption {
      default = { };
      description = "Public sealed bundles and their root-only key sockets; no enrollment secrets.";
      type = lib.types.attrsOf (lib.types.submodule {
        options = {
          bundle = lib.mkOption {
            type = lib.types.strMatching "/.*";
            description = "Runtime path to a public JSON bundle; not a Nix path literal.";
          };
          configureLuks = lib.mkOption {
            type = lib.types.bool;
            default = true;
            description = "Configure the matching initrd LUKS device; false exposes only its socket.";
          };
          device = lib.mkOption {
            type = lib.types.nullOr lib.types.str;
            default = null;
            description = "LUKS device path; null uses an existing boot.initrd.luks declaration.";
          };
          fido2Device = lib.mkOption {
            type = lib.types.str;
            default = "auto";
            description = "FIDO2 device path, or auto when exactly one token is connected.";
          };
          identityPolicy = lib.mkOption {
            type = lib.types.nullOr lib.types.path;
            default = null;
            description = "PUBLIC identity allowlist copied into the Nix store/signed initrd. Entries map primary/backup verification keys to runtime bundles. Never include unlock salts or secret credential IDs.";
          };
          shareWith = lib.mkOption {
            type = lib.types.listOf lib.types.str;
            default = [ ];
            description = "Other declared initrd LUKS volume names enrolled with the SAME derived unlock key. One proof/touch supplies separate root-only sockets for this group; empty keeps per-volume keys. Each member retains its own LUKS master key and recovery slot.";
          };
        };
      });
    };
    bundleMount = lib.mkOption {
      default = null;
      description = "Optional public filesystem mounted read-only in initrd and released after unlocking.";
      type = lib.types.nullOr (lib.types.submodule {
        options = {
          device = lib.mkOption { type = lib.types.str; };
          mountPoint = lib.mkOption { type = lib.types.str; default = "/run/combined-unlock-esp"; };
          fsType = lib.mkOption { type = lib.types.str; default = "vfat"; };
          options = lib.mkOption { type = lib.types.str; default = "ro,umask=0077"; };
        };
      });
    };
    phasePCR = lib.mkOption {
      type = lib.types.enum [ 11 15 ];
      default = 11;
      description = "Mandatory phase guard: legacy zero PCR11, or dedicated zero PCR15 for UKI v2 bundles.";
    };
    phaseAfter = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      description = "Additional initrd consumers that must finish before closing the early-boot phase.";
    };
    keyTimeout = lib.mkOption {
      type = lib.types.ints.between 5 120;
      default = 40;
      description = "Seconds before systemd-cryptsetup falls back to passphrase recovery.";
    };
  };
  config = lib.mkIf cfg.enable {
    assertions = [
      { assertion = names != [ ]; message = "combinedUnlock requires at least one provider."; }
      { assertion = lib.all (name: builtins.match "[A-Za-z0-9_-]+" name != null) names;
        message = "combinedUnlock provider names may contain only letters, digits, underscores and hyphens."; }
      { assertion = builtins.length managedNames == builtins.length (lib.unique managedNames);
        message = "A LUKS volume must belong to exactly one combinedUnlock provider/group."; }
      { assertion = lib.all (name: lib.all (member:
          builtins.match "[A-Za-z0-9_-]+" member != null
          && !(builtins.elem member names)
          && builtins.hasAttr member config.boot.initrd.luks.devices
        ) cfg.providers.${name}.shareWith
          && builtins.length (members name) <= 16
          && (cfg.providers.${name}.shareWith == [ ] ||
            (cfg.providers.${name}.configureLuks && cfg.providers.${name}.identityPolicy != null))) names;
        message = "shareWith needs up to 15 distinct declared LUKS members without their own provider, configureLuks enabled, and a pinned identityPolicy."; }
    ] ++ map (name: {
      assertion = lib.all (option: !(lib.hasPrefix "fido2-" option || lib.hasPrefix "tpm2-" option || lib.hasPrefix "pkcs11-" option))
        config.boot.initrd.luks.devices.${name}.crypttabExtraOpts;
      message = "Remove standalone token crypttab options from combinedUnlock device ${name}.";
    }) managedNames;
    # From NixOS 26.11 onward all initrds use systemd and this option is removed.
    boot.initrd.systemd.enable = lib.mkIf (lib.versionOlder config.system.nixos.release "26.11") true;
    boot.initrd.availableKernelModules = [ "tpm_crb" "tpm_tis" "usbhid" "hid_generic" ]
      ++ lib.optionals (mount != null && mount.fsType == "vfat") [ "vfat" "nls_cp437" "nls_iso8859_1" ];
    boot.initrd.systemd.storePaths = [
      package package.python pkgs.python3 pkgs.libfido2 pkgs.cryptsetup
      "${../src/provider.py}" "${../src/phase.py}"
    ] ++ lib.optional (mount != null) pkgs.util-linux
      ++ lib.filter (value: value != null) (builtins.attrValues identityPolicies);
    boot.initrd.systemd.mounts = lib.optional (mount != null) {
      what = mount.device;
      where = mount.mountPoint;
      type = mount.fsType;
      options = mount.options;
      unitConfig.DefaultDependencies = false;
    };
    boot.initrd.luks.devices = lib.genAttrs managedNames (name: {
      keyFile = keyPath name;
      keyFileTimeout = cfg.keyTimeout;
    } // lib.optionalAttrs (builtins.hasAttr name configured && configured.${name}.device != null) {
      device = configured.${name}.device;
    });
    boot.initrd.systemd.sockets = lib.mapAttrs' (name: _: lib.nameValuePair (unitName name) {
      description = "Combined TPM and FIDO2 key socket for ${name}";
      unitConfig.DefaultDependencies = false;
      socketConfig = {
        ListenStream = map keyPath (members name);
        SocketMode = "0600";
        DirectoryMode = "0700";
        RemoveOnStop = true;
        TriggerLimitBurst = 1;
        TriggerLimitIntervalSec = 60;
      };
    }) cfg.providers;
    boot.initrd.systemd.services = lib.mkMerge [
      (lib.mapAttrs' (name: value: lib.nameValuePair (unitName name) {
        description = "Combined TPM and FIDO2 key provider for ${name}";
        unitConfig = { DefaultDependencies = false; }
          // lib.optionalAttrs (mount != null) { RequiresMountsFor = mount.mountPoint; };
        serviceConfig = {
          Type = "oneshot";
          ExecStart = lib.escapeShellArgs [ "${package}/bin/combined-unlock" value.bundle
            "--socket-activated" "--device" value.fido2Device
            "--client-timeout" (toString cfg.keyTimeout) ]
            + " " + lib.escapeShellArgs (lib.concatMap (member: [ "--socket-path" (keyPath member) ]) (members name))
            + lib.optionalString (value.identityPolicy != null)
              (" --identity-policy " + lib.escapeShellArg (toString identityPolicies.${name}));
          TimeoutStartSec = cfg.keyTimeout + 10;
          UMask = "0077";
          LimitCORE = 0;
        };
      }) cfg.providers)
      (lib.listToAttrs (map (name: lib.nameValuePair "systemd-cryptsetup@${utils.escapeSystemdPath name}" {
        # Generated by systemd-cryptsetup-generator: never replace the service.
        overrideStrategy = "asDropin";
        wants = [ "${unitName (ownerOf name)}.socket" ];
        after = [ "${unitName (ownerOf name)}.socket" ];
      }) managedNames))
      { ${phase} = {
        description = "Close experimental TPM unsealing before switch-root";
        requiredBy = [ "initrd-cleanup.service" "initrd-switch-root.service" ];
        before = [ "initrd-cleanup.service" "initrd-switch-root.service" "initrd-switch-root.target" ];
        # A shared provider may still hold its key while waiting for a member.
        # Finish/expire that process before closing the TPM phase or switch-root.
        after = cryptUnits ++ map (name: "${unitName name}.service") names ++ cfg.phaseAfter;
        unitConfig.DefaultDependencies = false;
        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
          ExecStart = "${package}/bin/combined-unlock-close-phase --pcr ${toString cfg.phasePCR}";
          TimeoutStartSec = 10;
        } // lib.optionalAttrs (mount != null) {
          ExecStartPost = "${pkgs.util-linux}/bin/umount ${lib.escapeShellArg mount.mountPoint}";
        };
      }; }
    ];
  };
}
