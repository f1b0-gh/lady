{ flakePath, configPath, sourcePath, brokerPath, runtimePath }:
let flake = builtins.getFlake ("path:" + flakePath);
in flake.lib.mkBrokerImage {
  configPath = builtins.toPath configPath;
  sourcePath = builtins.toPath sourcePath;
  brokerPath = builtins.toPath brokerPath;
  runtimePath = builtins.toPath runtimePath;
}
