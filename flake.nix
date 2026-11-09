{
  description = "Experimental TPM-policy + FIDO2 LUKS key provider and NixOS initrd module";
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";
  outputs = { self, nixpkgs }: let
    systems = [ "x86_64-linux" "aarch64-linux" ];
    forSystems = nixpkgs.lib.genAttrs systems;
  in {
    nixosModules.default = import ./nix/module.nix;
    nixosModules.combinedUnlock = self.nixosModules.default;
    packages = forSystems (system: let pkgs = nixpkgs.legacyPackages.${system}; in {
      default = import ./nix/package.nix { inherit pkgs; };
      combined-unlock = self.packages.${system}.default;
      management = import ./nix/management-package.nix { inherit pkgs; };
    });
    checks = forSystems (system: let
      pkgs = nixpkgs.legacyPackages.${system};
      python = pkgs.python3.withPackages (ps: [ ps.cryptography ps.tpm2-pytss ps.fido2 ]);
      source = nixpkgs.lib.fileset.toSource {
        root = ./.;
        fileset = nixpkgs.lib.fileset.unions [ ./src ./tests ];
      };
    in {
      policy = pkgs.runCommand "combined-unlock-policy-test" {
        nativeBuildInputs = [ python pkgs.swtpm ];
      } ''
        export PYTHONDONTWRITEBYTECODE=1
        python3 ${source}/tests/test_provider.py
        python3 ${source}/tests/test_epoch_transition.py
        python3 ${source}/tests/test_identity.py
        touch $out
      '';
    });
    formatter = forSystems (system: nixpkgs.legacyPackages.${system}.nixfmt);
  };
}
