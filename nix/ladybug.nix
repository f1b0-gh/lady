{ pkgs }:
# LadybugDB 0.17.1 from flake.lock. GCC 16 no longer supplies cstdint
# transitively to the bundled Thrift transport header.
pkgs.ladybugdb.overrideAttrs (old: {
  postPatch = (old.postPatch or "") + ''
    sed -i '1i#include <cstdint>' third_party/thrift/transport/TTransport.h
  '';
})
