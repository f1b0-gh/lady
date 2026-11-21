{ pkgs, networkTools, openssl, rustPackages, rustVersion, cargoVersion }:
let
  toolchain = pkgs.buildEnv {
    name = "ladyshell-network-rust-${rustVersion}";
    paths = rustPackages;
    pathsToLink = [ "/bin" ];
  };
in pkgs.runCommand "ladyshell-network-rust-tools-${rustVersion}" {
  nativeBuildInputs = [ toolchain pkgs.stdenv.cc pkgs.python3 ];
} ''
  mkdir -p $out home project/src
  export HOME=$PWD/home CARGO_HOME=$PWD/home/cargo RUSTUP_HOME=$PWD/home/rustup
  export CARGO_TARGET_DIR=$PWD/target CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=2
  export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=${pkgs.stdenv.cc}/bin/cc
  export RUSTFLAGS="-Clinker-features=-lld -Clink-self-contained=-linker"
  ${toolchain}/bin/rustc --version > $out/rustc-version.txt
  test "$(cut -d ' ' -f 2 < $out/rustc-version.txt)" = ${rustVersion}
  LD_DEBUG=libs ${toolchain}/bin/cargo -vV > $out/cargo-version.txt 2> $out/cargo-loader.log
  grep -Fx 'release: ${cargoVersion}' $out/cargo-version.txt
  if ! grep -E '^libcurl: 8[.]23[.]0 .*system ssl:OpenSSL/3[.]5[.]9' $out/cargo-version.txt; then
    cat $out/cargo-version.txt >&2
    echo 'Unexpected Cargo native libraries' >&2
    exit 1
  fi
  python3 -I - "$out/cargo-loader.log" <<'PY'
  from pathlib import Path
  import re
  import sys
  expected = {
      str(Path("${pkgs.lib.getLib networkTools.curl}/lib/libcurl.so.4").resolve()),
      str(Path("${pkgs.lib.getLib openssl}/lib/libssl.so.3").resolve()),
      str(Path("${pkgs.lib.getLib openssl}/lib/libcrypto.so.3").resolve()),
  }
  actual = {str(Path(p).resolve()) for p in re.findall(
      r"calling init:\s+(\S+)", Path(sys.argv[1]).read_text())
      if Path(p).name in ("libcurl.so.4", "libssl.so.3", "libcrypto.so.3")}
  assert actual == expected, (actual, expected)
  PY
  ${toolchain}/bin/rustfmt --version > $out/rustfmt-version.txt
  ${toolchain}/bin/clippy-driver --version > $out/clippy-version.txt
  cat > project/Cargo.toml <<'EOF'
  [package]
  name = "lady-network-toolchain-fixture"
  version = "0.0.0"
  edition = "2021"
  EOF
  cat > project/src/lib.rs <<'EOF'
  pub fn checked_successor(value: u32) -> Option<u32> {
      value.checked_add(1)
  }

  #[cfg(test)]
  mod tests {
      use super::checked_successor;

      #[test]
      fn ordinary_input() {
          assert_eq!(checked_successor(41), Some(42));
      }

      #[test]
      fn boundary_input() {
          assert_eq!(checked_successor(u32::MAX), None);
      }
  }
  EOF
  cd project
  cargo generate-lockfile --offline > $out/lock.stdout 2> $out/lock.stderr
  cargo metadata --locked --offline --no-deps --format-version 1 > $out/metadata.json
  cargo test --locked --offline > $out/test.log 2>&1
  cargo fmt --all -- --check > $out/fmt.log 2>&1
  cargo clippy --locked --offline --all-targets -- -D warnings > $out/clippy.log 2>&1
  cp Cargo.lock $out/Cargo.lock
''
