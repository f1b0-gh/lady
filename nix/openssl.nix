# Scoped native package: do not replace OpenSSL throughout the nixpkgs closure.
# Keep the locked nixpkgs library options and patches. The test-only addition
# below reports the unavailable Linux IPv6 capability without changing the library.
# Release signature checked against the official primary key
# B146647E45A7B33947AB226B2A2C87D161692D40 on 2026-11-05.
# Remove this override when the reviewed nixpkgs lock supplies the fixed release.
{ pkgs }:
pkgs.openssl.overrideAttrs (old: {
  version = "3.5.9";
  # The upstream runner supports HARNESS_JOBS; retain every test recipe.
  # Pass it through make: structured Nix attributes are not process env vars.
  # Explicit checkFlags also avoids the default VERBOSE=y, which disables jobs.
  checkFlags = [ "HARNESS_JOBS=4" ];
  # Linux kernels booted with ipv6.disable=1 return EAFNOSUPPORT at socket(),
  # before upstream's existing bind() availability check. Only that exact
  # capability gap is skipped; IPv4 and permission failures still fail.
  # SDK/TLS and Ladyshell packaging owners: review by 2026-12-05 and remove
  # when upstream handles this case (related OpenSSL issue #22013).
  patches = old.patches ++ [ (builtins.toFile "openssl-test-ipv6-unavailable.patch" ''
    --- a/test/bio_dgram_test.c
    +++ b/test/bio_dgram_test.c
    @@ -115,6 +115,16 @@
         BIO_MSG tx_msg[128], rx_msg[128];
         char tx_buf[128];
         size_t num_processed = 0;
    +
    +#if OPENSSL_USE_IPV6 && defined(__linux__)
    +    if (af == AF_INET6) {
    +        int probe_fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    +        if (probe_fd == -1 && get_last_socket_error() == EAFNOSUPPORT)
    +            return TEST_skip("IPv6 unavailable in this test kernel");
    +        if (probe_fd != -1)
    +            closesocket(probe_fd);
    +    }
    +#endif
 
         if (af == AF_INET) {
             TEST_info("# Testing with AF_INET, local=%d\n", use_local);
  '') ];
  src = pkgs.fetchurl {
    url = "https://github.com/openssl/openssl/releases/download/openssl-3.5.9/openssl-3.5.9.tar.gz";
    sha256 = "603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a";
  };
})
