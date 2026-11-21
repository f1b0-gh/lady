{ pkgs, roots, curl }:
let
  closure = pkgs.closureInfo { rootPaths = roots; };
in
pkgs.runCommand "ladyshell-network-curl-closure" { } ''
  mkdir -p $out
  cp ${closure}/store-paths $out/store-paths
  grep -E '/[a-z0-9]{32}-curl-[0-9]' $out/store-paths > $out/curl-paths
  while IFS= read -r path; do
    case "$path" in
      "${pkgs.lib.getLib curl}"|"${pkgs.lib.getBin curl}") ;;
      *) echo "Unexpected curl runtime dependency: $path" >&2; exit 1 ;;
    esac
  done < $out/curl-paths
''
