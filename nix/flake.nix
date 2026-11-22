{
  description = "Trusted Nickel evaluator and Nix backend for OpenShell development environments";
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
  outputs = { self, nixpkgs }: let
    system = "x86_64-linux";
    pkgs = import nixpkgs { inherit system; };
    openssl = import ./openssl.nix { inherit pkgs; };
    networkTools = import ./network-tools.nix { inherit pkgs openssl; };
    tpm2Tss = import ./tpm2-tss.nix { inherit pkgs openssl networkTools; };
    opensslEnvironment = {
      OPENSSL_NO_VENDOR = "1";
      OPENSSL_STATIC = "0";
      OPENSSL_LIBS = "ssl:crypto";
      OPENSSL_LIB_DIR = "${pkgs.lib.getLib openssl}/lib";
      OPENSSL_INCLUDE_DIR = "${pkgs.lib.getDev openssl}/include";
    };
    rust199 = pkgs.stdenv.mkDerivation {
      pname = "ladyshell-rust-toolchain";
      version = "1.99.1";
      # Official channel-rust-1.99.1.toml, dated 2026-10-15.
      # Manifest SHA-256: fb152be80975c194aa5fc684b2aec3a6e14e2b855efe2faa4e5f8ae6e590f463.
      srcs = map (component: pkgs.fetchurl {
        url = "https://static.rust-lang.org/dist/2026-10-15/${component.name}-1.99.1-x86_64-unknown-linux-gnu.tar.xz";
        inherit (component) sha256;
      }) [
        { name = "rustc"; sha256 = "2ff05ff9c08a90861e7f6e4065b40a8b87463b4576186fd613871c3e37f2091f"; }
        { name = "cargo"; sha256 = "53f3521949404d595efb06a55c12c5658d4ed1c75566f33d3d514eaebe70bd8a"; }
        { name = "rust-std"; sha256 = "109b074225bf5b9ea3820890876bfdf4ed161adbfaf94b2b4b5984c85ee5d958"; }
        { name = "rustfmt"; sha256 = "e3b36c4c7ec3486c059d8067ff48787676612007123aad7a4e8ec12c48ee9ba2"; }
        { name = "clippy"; sha256 = "458339712a058e52cc4522ff9ef8b59cd1ea1340312216cd94194c464a3f6dc5"; }
      ];
      sourceRoot = ".";
      nativeBuildInputs = [ pkgs.autoPatchelfHook ];
      buildInputs = [ pkgs.stdenv.cc.cc.lib pkgs.zlib ];
      dontConfigure = true;
      dontBuild = true;
      dontStrip = true;
      installPhase = ''
        runHook preInstall
        for component in */install.sh; do
          bash "$component" --prefix="$out" --disable-ldconfig
        done
        runHook postInstall
      '';
      doInstallCheck = true;
      installCheckPhase = ''
        test "$($out/bin/rustc --version | cut -d ' ' -f 2)" = 1.99.1
        test "$($out/bin/cargo --version | cut -d ' ' -f 2)" = 1.99.1
        $out/bin/rustfmt --version
        $out/bin/clippy-driver --version
      '';
    };
    imageRust199 = networkTools.rust199Image rust199;
    nativeRustPackages = [ pkgs.rustc networkTools.cargo networkTools.rustfmt pkgs.clippy ];
    rustToolchains = {
      "${pkgs.rustc.version}" = nativeRustPackages;
    } // {
      # Keep the explicit compiler archives and reconstructed Cargo selected
      # when the Nixpkgs compiler reaches the same version.
      "1.99.1" = imageRust199.packages;
    };
  in {
    packages.${system} = {
      nickel = pkgs.nickel;
      default = pkgs.nickel;
      ladybugdb = import ./ladybug.nix { inherit pkgs; };
      rust199 = rust199;
      inherit openssl;
      inherit (networkTools) curl git cargo rustfmt;
      cargo199 = imageRust199.cargo;
      tpm2-tss = tpm2Tss;
    };
    devShells.${system} = {
      ci = pkgs.mkShell {
        packages = [
          rust199 pkgs.bubblewrap pkgs.util-linux pkgs.python3 pkgs.pkg-config
        ];
      };
      openssl = pkgs.mkShell {
        packages = [ rust199 pkgs.pkg-config openssl ];
        # Structured derivations export only entries in env to child processes.
        env = opensslEnvironment // pkgs.lib.mapAttrs' (name: value:
          # openssl-sys gives target-prefixed variables priority over generic ones.
          pkgs.lib.nameValuePair "X86_64_UNKNOWN_LINUX_GNU_${name}" value
        ) opensslEnvironment // {
          LD_LIBRARY_PATH = "${pkgs.lib.getLib openssl}/lib";
        };
      };
      tpm = pkgs.mkShell {
        packages = [ rust199 pkgs.pkg-config ];
        buildInputs = [ tpm2Tss openssl ];
        env = opensslEnvironment // pkgs.lib.mapAttrs' (name: value:
          pkgs.lib.nameValuePair "X86_64_UNKNOWN_LINUX_GNU_${name}" value
        ) opensslEnvironment // {
          PKG_CONFIG_PATH = pkgs.lib.makeSearchPath "lib/pkgconfig"
            (map pkgs.lib.getDev [ tpm2Tss openssl ]);
          LD_LIBRARY_PATH = pkgs.lib.makeLibraryPath [ tpm2Tss openssl ];
        };
      };
    };
    checks.${system} = (import ./tests/tpm-native-support.nix {
      inherit pkgs tpm2Tss openssl;
    }) // {
      minimal-git = import ./tests/minimal-git.nix {
        inherit pkgs;
        inherit (networkTools) git;
      };
      network-curl-closure = import ./tests/network-curl-closure.nix {
        inherit pkgs;
        inherit (networkTools) curl;
        roots = [ networkTools.curl networkTools.git ];
      };
      network-tools-tls = import ./tests/network-tools-tls.nix {
        inherit pkgs networkTools openssl;
      };
      network-rust-native = import ./tests/network-rust-tools.nix {
        inherit pkgs networkTools openssl;
        rustPackages = nativeRustPackages;
        rustVersion = pkgs.rustc.version;
        # Nixpkgs metadata follows rustc; the Cargo executable reports 1.99.0.
        cargoVersion = "1.99.0";
      };
      network-rust199 = import ./tests/network-rust-tools.nix {
        inherit pkgs networkTools openssl;
        rustPackages = imageRust199.packages;
        rustVersion = "1.99.1";
        cargoVersion = "1.99.1";
      };
      network-cargo-native-tls = import ./tests/network-tools-tls.nix {
        inherit pkgs networkTools openssl;
        cargo = networkTools.cargo;
      };
      network-cargo199-tls = import ./tests/network-tools-tls.nix {
        inherit pkgs networkTools openssl;
        cargo = imageRust199.cargo;
      };
      network-rust-curl-closure = import ./tests/network-curl-closure.nix {
        inherit pkgs;
        inherit (networkTools) curl;
        roots = nativeRustPackages ++ imageRust199.packages;
      };
      tpm2-tss = import ./tests/tpm2-tss.nix { inherit pkgs tpm2Tss openssl; };
      tpm-openssl-closure = import ./tests/tpm-openssl-closure.nix {
        inherit pkgs openssl;
        roots = [ tpm2Tss tpm2Tss.ladyshellNativeDependencies.curl
          tpm2Tss.ladyshellNativeDependencies.swtpm ];
      };
      openssl = pkgs.runCommandCC "ladyshell-openssl-linkage" {
        nativeBuildInputs = [ pkgs.pkg-config ];
        buildInputs = [ openssl ];
      } ''
        test "$(pkg-config --modversion openssl)" = 3.5.9
        cat > probe.c <<'EOF'
        #include <openssl/crypto.h>
        #include <openssl/opensslv.h>
        #include <stdio.h>
        int main(void) {
          printf("headers=%s runtime=%s\n", OPENSSL_VERSION_TEXT, OpenSSL_version(OPENSSL_VERSION));
          return OPENSSL_VERSION_NUMBER != 0x30500090L || OpenSSL_version_num() != 0x30500090L;
        }
        EOF
        $CC probe.c $(pkg-config --cflags --libs openssl) -o probe
        mkdir -p $out
        ./probe > $out/linkage.txt
        ${pkgs.lib.getBin openssl}/bin/openssl version >> $out/linkage.txt
      '';
    };
    lib.mkImage = args: import ./image.nix ({ inherit pkgs rustToolchains openssl tpm2Tss networkTools; } // args);
    lib.packageVersions = {
      nickel = pkgs.nickel.version;
      node = pkgs.nodejs.version;
      rust = pkgs.rustc.version;
      rust199 = rust199.version;
      python = pkgs.python3.version;
      python311 = pkgs.python311.version;
      python312 = pkgs.python312.version;
      python313 = pkgs.python313.version;
      python314 = pkgs.python314.version;
      uv = pkgs.uv.version;
      zig = pkgs.zig.version;
      cmake = pkgs.cmake.version;
      make = pkgs.gnumake.version;
      perl = pkgs.perl.version;
      pkg-config = pkgs.pkg-config.version;
      openssl = openssl.version;
      tpm2-tss = tpm2Tss.version;
      maturin = pkgs.maturin.version;
    };
  };
}
