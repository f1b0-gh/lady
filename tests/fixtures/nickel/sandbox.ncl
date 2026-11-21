# Fixture synthétique : héritage des missions et verrouillage des outils.
{
  schema_version = 1,
  name = "fixture-project",
  image = { backend = "nix", profile = "openshell-native", platform = "x86_64-linux" },
  sources = { include = ["README.md", "src"], exclude = ["generated"] },
  tools = {
    zig = { version = "0.17.0", phase = "runtime" },
    node = { version = "24.21.0", phase = "runtime" },
  },
  missions = {
    dev = {
      tools = ["zig"], include = [], depends_on = [],
      checks = [["bash", "scripts/check.sh", "--container"]],
    },
    audit = {
      tools = ["node"], include = ["audit"], depends_on = ["dev"],
      checks = [["node", "--test", "audit/validator.test.cjs"]],
    },
  },
  permissions = { network = [], filesystem = [] },
  sandbox = { gateway = "openshell", workspace = "default", provider = "fixture-provider" },
  sync = { mode = "files", destination = "exports" },
}
