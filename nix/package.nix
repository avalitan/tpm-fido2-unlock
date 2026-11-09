{ pkgs }:
let
  python = pkgs.python3.withPackages (ps: [ ps.cryptography ps.tpm2-pytss ps.fido2 ]);
  source = pkgs.runCommand "combined-unlock-provider-source" { } ''
    mkdir -p $out/lib
    cp ${../src/provider.py} $out/lib/provider.py
    cp ${../src/identity.py} $out/lib/identity.py
    cp ${../src/key_sockets.py} $out/lib/key_sockets.py
  '';
  provider = pkgs.writeShellApplication {
    name = "combined-unlock";
    runtimeInputs = [ pkgs.libfido2 pkgs.cryptsetup ];
    text = ''exec ${python}/bin/python3 ${source}/lib/provider.py "$@"'';
  };
  phase = pkgs.writeShellApplication {
    name = "combined-unlock-close-phase";
    text = ''exec ${python}/bin/python3 ${../src/phase.py} "$@"'';
  };
in pkgs.symlinkJoin {
  name = "tpm-fido2-unlock";
  paths = [ provider phase ];
  passthru = { inherit python; };
  meta.description = "Experimental TPM-policy and FIDO2 initrd key provider";
}
