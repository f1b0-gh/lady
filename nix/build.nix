{ flakePath, configPath, sourcePath, codexPath, codexHostPath, runtimePath, auditPath ? flakePath + "/../crates/ladyshell/resources/audit", preparationPath ? null }:
let flake = builtins.getFlake ("path:" + flakePath);
in flake.lib.mkImage {
  preparationPath = if preparationPath == null then null else builtins.toPath preparationPath;
  configPath = builtins.toPath configPath;
  sourcePath = builtins.toPath sourcePath;
  codexPath = builtins.toPath codexPath;
  codexHostPath = builtins.toPath codexHostPath;
  runtimePath = builtins.toPath runtimePath;
  auditPath = builtins.toPath auditPath;
}
