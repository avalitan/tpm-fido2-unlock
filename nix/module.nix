{ config, lib, pkgs, utils, ... }:
let
  cfg = config.boot.initrd.combinedUnlock;
  package = import ./package.nix { inherit pkgs; };
  names = builtins.attrNames cfg.providers;
  configured = lib.filterAttrs (_: value: value.configureLuks) cfg.providers;
  keyPath = name: "/run/combined-unlock/${name}.sock";
  unitName = name: "combined-unlock-${name}";
  cryptUnits = map (name: "systemd-cryptsetup@${utils.escapeSystemdPath name}.service") (builtins.attrNames configured);
  mount = cfg.bundleMount;
  phase = "combined-unlock-close-phase";
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
    phaseAfter = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      description = "Additional initrd consumers that must finish before closing the zero-PCR11 phase.";
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
    ] ++ lib.mapAttrsToList (name: _: {
      assertion = lib.all (option: !(lib.hasPrefix "fido2-" option || lib.hasPrefix "tpm2-" option || lib.hasPrefix "pkcs11-" option))
        config.boot.initrd.luks.devices.${name}.crypttabExtraOpts;
      message = "Remove standalone token crypttab options from combinedUnlock device ${name}.";
    }) configured;
    boot.initrd.systemd.enable = true;
    boot.initrd.availableKernelModules = [ "tpm_crb" "tpm_tis" "usbhid" "hid_generic" ]
      ++ lib.optionals (mount != null && mount.fsType == "vfat") [ "vfat" "nls_cp437" "nls_iso8859_1" ];
    boot.initrd.systemd.storePaths = [
      package package.python pkgs.python3 pkgs.libfido2 pkgs.cryptsetup
      "${../src/provider.py}" "${../src/phase.py}"
    ] ++ lib.optional (mount != null) pkgs.util-linux;
    boot.initrd.systemd.mounts = lib.optional (mount != null) {
      what = mount.device;
      where = mount.mountPoint;
      type = mount.fsType;
      options = mount.options;
      unitConfig.DefaultDependencies = false;
    };
    boot.initrd.luks.devices = lib.mapAttrs (name: value: {
      keyFile = keyPath name;
      keyFileTimeout = cfg.keyTimeout;
    } // lib.optionalAttrs (value.device != null) { inherit (value) device; }) configured;
    boot.initrd.systemd.sockets = lib.mapAttrs' (name: _: lib.nameValuePair (unitName name) {
      description = "Combined TPM and FIDO2 key socket for ${name}";
      unitConfig.DefaultDependencies = false;
      socketConfig = {
        ListenStream = keyPath name;
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
            "--socket-activated" "--device" value.fido2Device ];
          TimeoutStartSec = cfg.keyTimeout + 10;
          UMask = "0077";
          LimitCORE = 0;
        };
      }) cfg.providers)
      (lib.mapAttrs' (name: _: lib.nameValuePair "systemd-cryptsetup@${utils.escapeSystemdPath name}" {
        # Generated by systemd-cryptsetup-generator: never replace the service.
        overrideStrategy = "asDropin";
        wants = [ "${unitName name}.socket" ];
        after = [ "${unitName name}.socket" ];
      }) configured)
      { ${phase} = {
        description = "Close experimental TPM unsealing before switch-root";
        requiredBy = [ "initrd-cleanup.service" "initrd-switch-root.service" ];
        before = [ "initrd-cleanup.service" "initrd-switch-root.service" "initrd-switch-root.target" ];
        after = cryptUnits ++ cfg.phaseAfter;
        unitConfig.DefaultDependencies = false;
        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
          ExecStart = "${package}/bin/combined-unlock-close-phase";
          TimeoutStartSec = 10;
        } // lib.optionalAttrs (mount != null) {
          ExecStartPost = "${pkgs.util-linux}/bin/umount ${lib.escapeShellArg mount.mountPoint}";
        };
      }; }
    ];
  };
}
