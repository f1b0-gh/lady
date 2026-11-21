{ pkgs, git }:
let
  closure = pkgs.closureInfo { rootPaths = [ git ]; };
in
assert pkgs.lib.assertMsg (builtins.elem "NO_PERL=1" git.makeFlags)
  "Ladyshell Git must disable Perl support";
assert pkgs.lib.assertMsg (builtins.elem "NO_PYTHON=1" git.makeFlags)
  "Ladyshell Git must disable Python helpers";
assert pkgs.lib.assertMsg (!(builtins.elem (toString pkgs.perl)
  (map toString git.buildInputs)))
  "Ladyshell Git must not request a runtime Perl input";
pkgs.runCommand "ladyshell-minimal-git" {
  nativeBuildInputs = [ git pkgs.coreutils pkgs.gnugrep ];
} ''
  set -eu
  mkdir -p "$out"
  printf '%s\n' 'minimal Git recipe guards passed' > "$out/recipe-guards"

  cp ${closure}/store-paths "$out/runtime-store-paths"
  if grep -E '/nix/store/[0-9a-z]{32}-(perl(-|[0-9])|python[0-9])' \
      "$out/runtime-store-paths" > "$out/unexpected-interpreter-paths"; then
    cat "$out/unexpected-interpreter-paths" >&2
    echo 'Git still retains a Perl/Python runtime package' >&2
    exit 1
  fi
  test ! -e ${git}/libexec/git-core/git-send-email
  test ! -e ${git}/libexec/git-core/git-credential-netrc
  test ! -e ${git}/bin/git-jump
  test ! -e ${git}/share/gitweb/gitweb.cgi
  test "$(git --version)" = 'git version ${git.version}'

  export GIT_CONFIG_NOSYSTEM=1
  export GIT_CONFIG_SYSTEM=/dev/null
  export GIT_CONFIG_GLOBAL=/dev/null
  export GIT_AUTHOR_DATE='2001-01-01T00:00:00+00:00'
  export GIT_COMMITTER_DATE="$GIT_AUTHOR_DATE"
  repo="$TMPDIR/source with spaces"
  clone="$TMPDIR/clone with spaces"
  git init --quiet --initial-branch=main "$repo"
  git -C "$repo" config user.name 'Ladyshell qualification'
  git -C "$repo" config user.email qualification@example.invalid
  printf '%s\n' base > "$repo/base.txt"
  git -C "$repo" add base.txt
  git -C "$repo" commit --quiet -m initial
  git -C "$repo" switch --quiet --create feature
  printf '%s\n' feature > "$repo/feature.txt"
  git -C "$repo" add feature.txt
  git -C "$repo" commit --quiet -m feature
  git -C "$repo" diff HEAD^ HEAD -- feature.txt > "$out/diff"
  grep -Fx '+feature' "$out/diff"
  git -C "$repo" switch --quiet main
  git -C "$repo" merge --quiet --no-ff --no-edit feature
  git clone --quiet --no-local "$repo" "$clone"
  test "$(cat "$clone/feature.txt")" = feature
  printf '%s\n' next > "$repo/next.txt"
  git -C "$repo" add next.txt
  git -C "$repo" commit --quiet -m next
  git -C "$clone" fetch --quiet origin main
  test "$(git -C "$clone" rev-parse FETCH_HEAD)" = "$(git -C "$repo" rev-parse HEAD)"

  printf '%s\n' \
    '{"schema_version":1,"git_version":"${git.version}","operations":["init","commit","diff","branch","merge","clone","fetch"],"status":"passed"}' \
    > "$out/operations.json"
''
