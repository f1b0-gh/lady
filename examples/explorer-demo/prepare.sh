#!/bin/sh
# Materialize synthetic manifests outside the repository without running npm.
set -eu
if [ "$#" -ne 1 ]; then
  echo 'usage: sh prepare.sh NEW_INPUT_DIRECTORY' >&2
  exit 1
fi
fixture_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
mkdir -- "$1"
for stage in before after; do
  mkdir -- "$1/$stage"
  for name in package.json package-lock.json; do
    cp -- "$fixture_dir/$stage/$name.fixture" "$1/$stage/$name"
  done
done
