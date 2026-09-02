-- Fluent Bit lua filter: resolve Docker container name from the tailed log path.
--
-- Docker json-file logs live at /var/lib/docker/containers/<id>/<id>-json.log, so
-- the record's `filepath` (tail Path_Key) carries only the container ID. The
-- container's /var/lib/docker/containers/<id>/config.v2.json (mounted ro) holds
-- "Name":"/<name>"; we read it once per ID and cache it for the process lifetime.
--
-- Adds:   container_name, container_id
-- Drops:  filepath (internal), and every record from the fluent-bit container
--         itself (recursion guard — shipping its own "HTTP status=200" lines
--         would otherwise feed back at 1 line/sec forever).

local cache = {}
local SELF = "ircfiber-fluent-bit"

local function lookup(id)
  local name = cache[id]
  if name ~= nil then return name end
  name = id
  local f = io.open("/var/lib/docker/containers/" .. id .. "/config.v2.json", "r")
  if f ~= nil then
    local s = f:read("*a")
    f:close()
    if s ~= nil then
      local n = string.match(s, '"Name":"/([^"]+)"')
      if n ~= nil then name = n end
    end
  end
  cache[id] = name
  return name
end

function add_container_name(tag, ts, record)
  local path = record["filepath"]
  if path == nil then return 0, ts, record end
  local id = string.match(path, "/containers/([0-9a-f]+)/")
  record["filepath"] = nil
  if id == nil then return 2, ts, record end
  local name = lookup(id)
  if name == SELF then return -1, ts, record end
  record["container_name"] = name
  record["container_id"] = string.sub(id, 1, 12)
  return 2, ts, record
end
