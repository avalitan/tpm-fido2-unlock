{ pkgs }:
let
  python = pkgs.python3.withPackages (ps: [ ps.cryptography ps.tpm2-pytss ps.fido2 ]);
  source = pkgs.runCommand "combined-unlock-management-source" { } ''
    mkdir -p $out/lib
    cp ${../src/manage.py} $out/lib/manage.py
    cp ${../src/management.py} $out/lib/management.py
    cp ${../src/provider.py} $out/lib/provider.py
    cp ${../src/identity.py} $out/lib/identity.py
    cp ${../src/key_sockets.py} $out/lib/key_sockets.py
    cp ${../src/enrollment.py} $out/lib/enrollment.py
  '';
in pkgs.writeShellApplication {
  name = "combined-unlock-manage";
  runtimeInputs = [ pkgs.libfido2 pkgs.cryptsetup ];
  text = ''exec ${python}/bin/python3 ${source}/lib/manage.py "$@"'';
}
