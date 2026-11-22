let Tool = { version | String, phase | String | default = "runtime" } in
let Mission = {
  tools | Array String,
  include | Array String,
  depends_on | Array String,
  checks | Array (Array String),
} in
let StorageLimit = { bytes | Number, inodes | Number } in
{
  storage | optional | {
    control | StorageLimit,
    artifacts | StorageLimit,
    incoming | StorageLimit,
  },
  dependencies | optional | {
    projects | Array String,
    allowed_hosts | Array String,
  },
  audit | optional | {
    profile | String,
    scope_paths | Array String,
    exclude_paths | Array String,
    tools | { _ : Tool },
    checks | Array (Array String),
    budget | { invocations | Number, seconds | Number },
    limits | { cpu_seconds | Number, memory_bytes | Number, processes | Number, files | Number, disk_bytes | Number },
  },
  permissions | {
    network | Array { tool | String, host | String, port | Number, justification | String },
    filesystem | Array { path | String, access | String, justification | String },
  } | default = {
    network = [], filesystem = [],
  },
  image | { backend | String, profile | String, platform | String } | default = {
    backend = "nix", profile = "openshell-native", platform = "x86_64-linux",
  },
  sync | { mode | String, destination | String } | default = { mode = "files", destination = "exports" },
  schema_version | Number,
  name | String,
  sources | { include | Array String, exclude | Array String },
  tools | { _ : Tool },
  missions | { _ : Mission },
  sandbox | { gateway | String, workspace | String, provider | String },
}
