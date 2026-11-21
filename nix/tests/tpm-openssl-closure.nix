{ pkgs, roots, openssl }:
let
  closure = pkgs.closureInfo { rootPaths = roots; };
in
pkgs.runCommand "ladyshell-tpm-openssl-closure" { } ''
  mkdir -p $out
  cp ${closure}/store-paths $out/store-paths
  grep -E '/[a-z0-9]{32}-openssl-[0-9]' $out/store-paths > $out/openssl-paths
  while IFS= read -r path; do
    case "$path" in
      "${pkgs.lib.getLib openssl}"|"${pkgs.lib.getBin openssl}") ;;
      *) echo "Unexpected OpenSSL runtime dependency: $path" >&2; exit 1 ;;
    esac
  done < $out/openssl-paths
''
