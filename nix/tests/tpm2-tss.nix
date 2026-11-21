{ pkgs, tpm2Tss, openssl }:
pkgs.runCommandCC "ladyshell-tpm2-tss-qualification" {
  nativeBuildInputs = [ pkgs.pkg-config ];
  buildInputs = [ tpm2Tss openssl ];
} ''
  mkdir -p $out
  for module in tss2-esys tss2-sys tss2-mu tss2-rc tss2-tctildr; do
    test "$(pkg-config --modversion "$module")" = 4.2.1
  done
  test "$(pkg-config --modversion openssl)" = 3.5.9

  # Compile the exact upstream receive implementation without modifying the
  # installed library. Unused entry points are discarded at link time; no
  # replacement receive/check function is provided by the regression harness.
  tar xf ${tpm2Tss.src}
  source_dir=tpm2-tss-4.2.1
  for bus in spi i2c; do
    flags=()
    if test "$bus" = spi; then flags=(-DTEST_SPI); fi
    $CC -O2 -DMAXLOGLEVEL=0 -ffunction-sections -fdata-sections \
      -Wl,--gc-sections "''${flags[@]}" \
      -I"$source_dir/include/tss2" -I"$source_dir/src" -I"$source_dir/src/tss2-tcti" \
      ${./tpm-short-response.c} "$source_dir/src/tss2-tcti/tcti-$bus-helper.c" \
      "$source_dir/src/tss2-tcti/tcti-common.c" -o "regression-$bus"
    timeout 10 "./regression-$bus" >> $out/short-response.txt
  done

  $CC -Wall -Wextra -Werror ${./tpm-linkage.c} \
    -DEXPECTED_TSS_LIBDIR='"${pkgs.lib.getLib tpm2Tss}/lib"' \
    -DEXPECTED_OPENSSL_LIBDIR='"${pkgs.lib.getLib openssl}/lib"' \
    $(pkg-config --cflags --libs tss2-esys tss2-mu tss2-tctildr openssl) \
    -ldl -o probe
  timeout 30 ./probe > $out/linkage.txt
  ldd ./probe > $out/linked-libraries.txt
''
