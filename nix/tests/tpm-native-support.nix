{ pkgs, tpm2Tss, openssl }:
let
  support = tpm2Tss.ladyshellNativeDependencies;
in {
  tpm-curl-tls = pkgs.runCommand "ladyshell-tpm-curl-tls" {
    nativeBuildInputs = [ pkgs.python3 ];
  } ''
    python3 -I ${./tpm-curl-tls.py} \
      --curl ${pkgs.lib.getBin support.curl}/bin/curl \
      --openssl ${pkgs.lib.getBin openssl}/bin/openssl \
      --openssl-lib ${pkgs.lib.getLib openssl}/lib --output $out
  '';
  tpm-installed-tests = pkgs.runCommand "ladyshell-swtpm-installed-tests" {
    nativeBuildInputs = [ support.swtpm openssl pkgs.which pkgs.gawk
      pkgs.socat pkgs.procps pkgs.unixtools.netstat ];
  } ''
    test ! -e ${support.swtpm}/libexec/installed-tests
    test -x ${support.swtpm.installedTests}/libexec/installed-tests/swtpm/test_clientfds.py
    test -x ${support.swtpm.installedTests}/libexec/installed-tests/swtpm/test_setdatafd.py
    export HOME="$TMPDIR/home"
    mkdir -p "$HOME" $out
    for name in test_commandline test_ctrlchannel3 test_tpm2_ctrlchannel3; do
      timeout 180 ${support.swtpm.installedTests}/libexec/installed-tests/swtpm/"$name" \
        > "$out/$name.log" 2>&1
    done
  '';
}
