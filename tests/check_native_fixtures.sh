#!/usr/bin/env bash
set -euo pipefail

test_output=$(mktemp)
trap 'rm -f -- "$test_output"' EXIT

run_ignored_test() {
  local package=$1 target=$2 test_name=$3
  cargo test --locked -p "$package" --test "$target" "$test_name" \
    -- --exact --ignored --color never | tee "$test_output"
  if ! grep -q '^test result: ok\. 1 passed; 0 failed; 0 ignored;' "$test_output"; then
    printf 'Expected one passing test in %s/%s: %s\n' "$package" "$target" "$test_name" >&2
    exit 1
  fi
}

case "${1:-}" in
  graph)
    run_ignored_test ladybom-graph deps_alignment_explain \
      native_explanation_preserves_paths_across_npm_scopes_and_marks_output_truncation
    run_ignored_test ladybom-graph deps_prune \
      native_removal_keeps_shared_dependencies_and_frees_orphaned_cycles
    run_ignored_test ladybom-graph deps_prune \
      native_removal_distinguishes_contexts_and_refuses_gain_on_truncation
    run_ignored_test ladybom-cli alignment \
      native_alignment_explains_nested_contexts_and_query_budget
    run_ignored_test ladybom-cli deps_graph \
      native_traversal_matches_bfs_and_filters_before_traversal
    run_ignored_test ladybom-cli deps_graph \
      native_diamond_depth_conditions_contexts_and_timeout
    ;;
  dependencies)
    run_ignored_test ladyshell-cli deps_cargo_image \
      nix_vendoring_coexists_with_legacy_cargo_aliases_without_running_project_code
    run_ignored_test ladyshell-cli deps_image \
      nix_workspace_preserves_nested_dependencies_and_local_links_without_scripts
    run_ignored_test ladyshell-cli deps_image \
      nix_refuses_dependency_bytes_with_a_corrupted_lock_hash
    ;;
  *)
    echo "Usage: bash tests/check_native_fixtures.sh {graph|dependencies}" >&2
    exit 2
    ;;
esac
