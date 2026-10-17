-- coaz-pep: Kong's policy enforcement is coaz-pep's. Every request on the route goes to coaz-pep's HTTP check API
-- (POST /v1/mcp/check) with the headers that matter and the raw body; a permit lets it through with the upstream
-- headers coaz-pep sets, anything else is answered with coaz-pep's response verbatim. No check is made here: the
-- upstream demo's plugin decoded tokens without verifying them, checked DPoP without the proof's signature, and only
-- delegated tools/call - this delegates everything, so one implementation holds every rule.
local http = require "resty.http"
local cjson = require "cjson.safe"

local CoazPep = { PRIORITY = 900, VERSION = "1.0.0" }

-- The request headers the PEP decides on. A repeated header is joined with ",", which the PEP refuses for DPoP.
local FORWARDED = { "authorization", "dpop", "x-user-token" }

local function unavailable(reason)
  kong.log.err("coaz-pep: ", reason)
  return kong.response.exit(503, { error = "authorization_unavailable",
                                   error_description = "The authorization service is unavailable; denying (fail closed)." })
end

function CoazPep:access(conf)
  local headers = {}
  for _, name in ipairs(FORWARDED) do
    local value = kong.request.get_header(name)
    local all = ngx.req.get_headers()[name]
    if type(all) == "table" then value = table.concat(all, ",") end
    if value then headers[name] = value end
  end
  local body, err = kong.request.get_raw_body()
  if err then return unavailable("request body unreadable: " .. err) end

  local httpc = http.new()
  httpc:set_timeout(conf.timeout_ms)
  local res, req_err = httpc:request_uri(conf.coaz_url .. "/v1/mcp/check", {
    method = "POST",
    headers = { ["Content-Type"] = "application/json" },
    body = cjson.encode({ config = conf.route_config, method = kong.request.get_method(),
                          path = kong.request.get_path(), headers = headers, body = body or "" }),
  })
  if not res then return unavailable(req_err) end
  if res.status ~= 200 then return unavailable("check API answered " .. res.status) end
  local verdict = cjson.decode(res.body)
  if type(verdict) ~= "table" then return unavailable("unreadable verdict") end

  if verdict.decision == true then
    for k, v in pairs(verdict.upstream_headers or {}) do kong.service.request.set_header(k, v) end
    for k, v in pairs(verdict.response_headers or {}) do kong.response.set_header(k, v) end
    return
  end
  local refusal = verdict.response or {}
  return kong.response.exit(refusal.status or 403, refusal.body or "", refusal.headers)
end

return CoazPep
