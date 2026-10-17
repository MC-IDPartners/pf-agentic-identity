-- Config for the coaz-pep Kong plugin: where coaz-pep's HTTP check API is, and the PEP settings for the route.
local typedefs = require "kong.db.schema.typedefs"

return {
  name = "coaz-pep",
  fields = {
    { protocols = typedefs.protocols_http },
    { config = {
        type = "record",
        fields = {
          -- coaz-pep's HTTP check API base, e.g. http://coaz-pep:9192.
          { coaz_url = { type = "string", required = true } },
          -- Passed to coaz-pep as the check's `config`: the same keys as an ext_authz route context.
          { route_config = { type = "map", keys = { type = "string" }, values = { type = "string" }, default = {} } },
          { timeout_ms = { type = "integer", default = 15000 } },
        },
      },
    },
  },
}
