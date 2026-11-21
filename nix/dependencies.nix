# Only fixed-output fetchers may access the network. All package operations run in
# ordinary Nix sandboxed derivations against the verified, explicitly selected tree.
{ pkgs, sourcePath, preparation, python, rust ? null }:
let
  lib = pkgs.lib;
  sources = builtins.path { path = sourcePath; name = "dependency-project-sources"; };
  fetch = args:
    let
      matched = builtins.match "https://([^/:@?#]+)(:443)?/[^?#]*" args.url;
      authorized = matched != null && builtins.elem (builtins.elemAt matched 0) preparation.allowed_hosts;
    in if !authorized then throw "Dependency fetch host not authorized"
    else pkgs.fetchurl (args // {
      curlOptsList = [ "--max-redirs" "0" "--proto" "=https" "--proto-redir" "=https" ];
    });
  artifact = item: fetch ({ url = item.url; } //
    (if lib.hasPrefix "sha256:" item.hash then { sha256 = lib.removePrefix "sha256:" item.hash; }
    else { hash = item.hash; }));
  importCargoLock = pkgs.callPackage (pkgs.path + "/pkgs/build-support/rust/import-cargo-lock.nix") { fetchurl = fetch; };
  npmModuleTrees = project: [ "node_modules" ]
    ++ map (member: member + "/node_modules") (if project.workspace == null then [] else project.workspace);
  mkProject = index: project:
    let
      root = if project.root == "." then "" else project.root;
      projectDir = lib.escapeShellArg ("project/" + root);
      label = "ladyshell-dependencies-${toString index}-${project.ecosystem}";
      artifacts = lib.concatMap (component: component.artifacts) project.components;
      wheels = builtins.filter (item: lib.hasSuffix ".whl" item.url) artifacts;
      wheelhouse = pkgs.linkFarm "${label}-wheels" (map (item: { name = builtins.baseNameOf item.url; path = artifact item; }) wheels);
      vendor = importCargoLock { lockFile = sources + "/${project.lockfile}"; };
      cargoConfig = pkgs.writeText "${label}-cargo-config.toml" ''
        [source.crates-io]
        replace-with = "ladyshell-vendored"
        [source.ladyshell-vendored]
        directory = "${vendor}"
        [net]
        offline = true
      '';
      npmRequirements = pkgs.writeText "${label}-npm-requirements.json" (builtins.toJSON (map (t: t.constraint) (builtins.filter (t: t.name == "npm") project.tools)));
      npmCheck = pkgs.writeText "${label}-check-npm.cjs" ''
        const fs = require("fs");
        const semver = require("${pkgs.nodejs}/lib/node_modules/npm/node_modules/semver");
        const version = require("${pkgs.nodejs}/lib/node_modules/npm/package.json").version;
        for (const constraint of JSON.parse(fs.readFileSync(process.argv[2], "utf8"))) {
          if (!semver.satisfies(version, constraint)) throw Error("Pinned npm " + version + " does not satisfy " + constraint);
        }
      '';
      environment = pkgs.runCommand label {
        nativeBuildInputs = [ pkgs.coreutils ]
          ++ lib.optionals (project.ecosystem == "python") [ pkgs.uv python ]
          ++ lib.optionals (project.ecosystem == "rust") (if rust == null then [ pkgs.cargo pkgs.rustc pkgs.stdenv.cc ] else [ rust ])
          ++ lib.optionals (project.ecosystem == "npm") [ pkgs.nodejs ];
      } (''
        export HOME="$TMPDIR/home"
        mkdir -p "$HOME" "$out"
        cp -r ${sources} project
        chmod -R u+w project
        cd ${projectDir}
      '' + (if project.ecosystem == "python" then ''
        export UV_OFFLINE=1 UV_PYTHON_DOWNLOADS=never UV_NO_CONFIG=1 UV_CACHE_DIR="$TMPDIR/uv-cache"
        uv export --locked --offline --no-build --all-extras --all-groups --no-emit-project \
          --python ${python}/bin/python3 --output-file "$TMPDIR/requirements.txt"
        uv venv --no-project --python ${python}/bin/python3 "$out/venv"
        uv pip install --python "$out/venv/bin/python" --offline --no-index --no-build \
          --find-links ${wheelhouse} --require-hashes --requirement "$TMPDIR/requirements.txt"
        cp "$TMPDIR/requirements.txt" "$out/requirements.txt"
      '' else if project.ecosystem == "rust" then ''
        export CARGO_HOME="$TMPDIR/cargo"
        mkdir -p "$CARGO_HOME"
        cp ${cargoConfig} "$CARGO_HOME/config.toml"
        cargo metadata --frozen --offline --format-version 1 > /dev/null
        cp ${cargoConfig} "$out/config.toml"
      '' else if project.ecosystem == "npm" then ''
        export npm_config_cache="$TMPDIR/npm-cache" npm_config_offline=true
        node ${npmCheck} ${npmRequirements}
        ${lib.concatMapStringsSep "\n" (item: "npm cache add ${artifact item} --ignore-scripts --offline") artifacts}
        npm ci --offline --ignore-scripts --include=dev --include=optional --include=peer --engine-strict --no-audit --no-fund
        mkdir -p node_modules
        ${lib.concatMapStringsSep "\n" (directory: let source = lib.escapeShellArg directory; in ''
          if test -d ${source}; then
            mkdir -p -- "$out"/${lib.escapeShellArg (builtins.dirOf directory)}
            cp -r -- ${source} "$out"/${source}
          fi
        '') (npmModuleTrees project)}
      '' else throw "Unsupported dependency ecosystem"));
    in { inherit project environment; vendor = if project.ecosystem == "rust" then vendor else null; };
  environments = lib.imap0 mkProject preparation.projects;
  rustEnvironments = builtins.filter (item: item.project.ecosystem == "rust") environments;
  cargoVendor = pkgs.runCommand "ladyshell-cargo-vendor" {} ''
    mkdir -p "$out"
    for vendor in ${lib.concatMapStringsSep " " (item: toString item.vendor) rustEnvironments}; do
      for crate in "$vendor"/*; do
        test "$(basename "$crate")" != Cargo.lock || continue
        target="$out/$(basename "$crate")"
        resolved="$(readlink -f "$crate")"
        if test -e "$target"; then
          test "$(readlink -f "$target")" = "$resolved"
        else
          ln -s "$resolved" "$target"
        fi
      done
    done
  '';
  cargoConfig = pkgs.writeText "ladyshell-cargo-offline.toml" ''
    [source.crates-io]
    replace-with = "ladyshell-vendored"
    [source.ladyshell-vendored]
    directory = "${cargoVendor}"
    [net]
    offline = true
  '';
  bundle = pkgs.linkFarm "ladyshell-prepared-dependencies" (lib.imap0 (index: item: { name = "share/ladyshell/dependencies/${toString index}"; path = item.environment; }) environments);
in {
  inherit bundle;
  install = lib.optionalString (rustEnvironments != []) ''
    mkdir -p sandbox/workspace/cache/cargo
    cp ${cargoConfig} sandbox/workspace/cache/cargo/config.toml
  '' + lib.concatMapStringsSep "\n" (item:
    let
      destination = "sandbox/workspace/project" + lib.optionalString (item.project.root != ".") ("/" + item.project.root);
    in if item.project.ecosystem == "python" then ''
      ln -s ${item.environment}/venv ${lib.escapeShellArg (destination + "/.venv")}
    '' else if item.project.ecosystem == "rust" then "" else
      lib.concatMapStringsSep "\n" (directory:
        let
          source = lib.escapeShellArg (toString item.environment + "/" + directory);
          target = lib.escapeShellArg (destination + "/" + directory);
          parent = lib.escapeShellArg (builtins.dirOf (destination + "/" + directory));
        in ''
          if test -d ${source}; then
            mkdir -p -- ${parent}
            cp -r -- ${source} ${target}
          fi
        ''
      ) (npmModuleTrees item.project)
  ) environments;
}
