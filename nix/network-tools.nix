# Shared by TPM and both image builders. Preserve upstream sources and patches.
# Packaging owners: review by 2026-12-07 and remove the scoped overrides when
# locked nixpkgs satisfies the same checks; OpenSSL retains its own earlier date.
{ pkgs, openssl ? import ./openssl.nix { inherit pkgs; } }:
let
  libssh2 = pkgs.libssh2.override { inherit openssl; };
  libkrb5 = pkgs.libkrb5.override { inherit openssl; };
  ngtcp2 = pkgs.ngtcp2.override { inherit openssl; };
  curl = (pkgs.curl.override {
    inherit openssl libssh2 libkrb5 ngtcp2;
  }).overrideAttrs (_: {
    # Official archive signature verified on 2026-11-07 against publisher key
    # 27EDEAF22F3ABCEB50DB9A125CC908FDB71E12C2. All protocol options are retained.
    version = "8.23.0";
    src = pkgs.fetchurl {
      url = "https://curl.se/download/curl-8.23.0.tar.xz";
      sha256 = "8dadd7d2536a314f982ad05a651b713f426bf7d02cc2c76cffb9796f2218e6c5";
    };
  });
  git = pkgs.git.override {
    inherit curl openssl;
    # Ordinary Git operations do not require the optional script tools.
    perlSupport = false;
    pythonSupport = false;
    sendEmailSupport = false;
  };
  cargo = pkgs.cargo.override {
    inherit curl openssl;
    # Cargo's recipe also reads the host curl pkg-config files explicitly.
    pkgsHostHost = pkgs.pkgsHostHost // { inherit curl; };
  };
  rustfmt = pkgs.rustfmt.override { inherit cargo; };
  rust199Image = official:
    assert official.version == "1.99.1";
    let
      compiler = official.overrideAttrs (old:
        let components = builtins.filter (src: !(pkgs.lib.hasPrefix "cargo-" src.name)) old.srcs;
        in assert builtins.length old.srcs == 5 && builtins.length components == 4;
        {
          pname = "ladyshell-rust-compiler-tools";
          srcs = components;
          installCheckPhase = ''
            test "$($out/bin/rustc --version | cut -d ' ' -f 2)" = 1.99.1
            test ! -e $out/bin/cargo
            $out/bin/rustfmt --version
            $out/bin/clippy-driver --version
          '';
        });
      source = pkgs.fetchurl {
        # Official source archive checked against the publisher checksum.
        # Cargo commit: 5f94df4789f005f9a352888e8355ffc645b7ed0e.
        url = "https://static.rust-lang.org/dist/2026-10-15/rustc-1.99.1-src.tar.xz";
        sha256 = "6451598a99e77f07571960f6b21d577399d3a30f33e80cbd2e3a4aae6535d265";
      };
      cargo = (pkgs.cargo.override {
        inherit curl openssl;
        pkgsHostHost = pkgs.pkgsHostHost // { inherit curl; };
        rustc = compiler // {
          unwrapped = { version = "1.99.1"; src = source; tests = {}; };
        };
      }).overrideAttrs (old: {
        # Use Cargo's upstream distribution-version mechanism; retain its
        # source commit and identify this native-library reconstruction.
        env = old.env // {
          CFG_RELEASE = "1.99.1";
          CFG_RELEASE_CHANNEL = "stable";
          CFG_VER_DESCRIPTION = "Ladyshell native curl/OpenSSL";
        };
        postInstall = assert pkgs.lib.hasInfix "src/tools/cargo/src/etc/man/*" old.postInstall;
          builtins.replaceStrings [ "src/tools/cargo/src/etc/man/*" ]
            [ "src/tools/cargo/etc/man/*" ] old.postInstall;
        installCheckPhase = old.installCheckPhase + ''
          $out/bin/cargo -vV > cargo-version.txt
          grep -Fx 'release: 1.99.1' cargo-version.txt
          grep -Fx 'commit-hash: 5f94df4789f005f9a352888e8355ffc645b7ed0e' cargo-version.txt
          grep -E '^libcurl: 8[.]23[.]0 .*system ssl:OpenSSL/3[.]5[.]9' cargo-version.txt
        '';
      });
    in { inherit compiler cargo; packages = [ compiler cargo ]; };
in { inherit curl git libssh2 libkrb5 ngtcp2 cargo rustfmt rust199Image; }
