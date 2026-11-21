{ pkgs, networkTools, openssl, cargo ? null }:
pkgs.runCommand ("ladyshell-network-tools-tls" + pkgs.lib.optionalString (cargo != null) "-cargo-${cargo.version}") {
  nativeBuildInputs = [ pkgs.python3 ];
} ''
  python3 -I ${./network-tools-tls.py} \
    --git ${pkgs.lib.getBin networkTools.git}/bin/git \
    --curl ${pkgs.lib.getBin networkTools.curl}/bin/curl \
    --curl-lib ${pkgs.lib.getLib networkTools.curl}/lib \
    --openssl ${pkgs.lib.getBin openssl}/bin/openssl \
    --openssl-lib ${pkgs.lib.getLib openssl}/lib --output $out \
    ${pkgs.lib.optionalString (cargo != null) "--cargo ${pkgs.lib.getBin cargo}/bin/cargo"}
''
