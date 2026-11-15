package.path = './lua/?.lua;./lua/?/init.lua;' .. package.path
local health, plugin, audit = vim.health, package.loaded.straps_classifier, package.loaded['straps_classifier.audit']
local status, reports
before_each(function()
  reports = {}
  vim.health = setmetatable({}, { __index = function(_, key)
    return function(message) reports[#reports + 1] = key .. ':' .. message end
  end })
  package.loaded.straps_classifier = { status = function() return status end }
  package.loaded['straps_classifier.audit'] = { counts = function() return { allow = 0, deny = 0 }, {} end }
end)
after_each(function()
  vim.health, package.loaded.straps_classifier, package.loaded['straps_classifier.audit'] = health, plugin, audit
end)
local function check()
  local path = './lua/straps_classifier/health.lua'
  local source = table.concat(vim.fn.readfile(path), '\n')
  local mutant = vim.env.STRAPS_HEALTH_MUTANT
  if mutant then
    local changes = {
      mode = { 'if s.contextual then', 'if false then' },
      installed = { 's.contextual and "contextual core integration installed; legacy classifier chain bypassed" or "guard installed"', '"guard installed"' },
      disclosure = { 'if s.contextual.disclosure_approved then', 'if not s.contextual.disclosure_approved then' },
      missing = { 'ipairs(s.contextual.missing or {})', 'ipairs({})' },
      failed = { 's.contextual and "contextual core integration not installed: " or "guard not installed: "', '"guard not installed: "' },
      unavailable = { 'if s.contextual.unavailable then health.warn', 'if false then health.warn' },
    }
    local change = assert(changes[mutant])
    local first, last = assert(source:find(change[1], 1, true))
    source = source:sub(1, first - 1) .. change[2] .. source:sub(last + 1)
  end
  assert(loadstring(source, '@' .. path))().check()
  return table.concat(reports, '\n')
end
it('reports contextual installation and unavailable dependencies without legacy key claims', function()
  status = { setup_ran = true, installed = true, contextual = {
    disclosure_approved = false, missing = { 'provider adapter' }, unavailable = 'route unsupported',
  } }
  local result = check()
  assert.is_truthy(result:find('ok:contextual core integration installed; legacy classifier chain bypassed', 1, true))
  assert.is_nil(result:find('ok:guard installed', 1, true))
  assert.is_nil(result:find('warn:no key', 1, true))
  assert.is_truthy(result:find('warn:provider disclosure is not approved; contextual assessment unavailable', 1, true))
  assert.is_truthy(result:find('warn:unavailable dependency: provider adapter', 1, true))
  assert.is_truthy(result:find('warn:unassessed: route unsupported', 1, true))
end)
it('reports approved disclosure without claiming assessment readiness', function()
  status = { setup_ran = true, installed = true, contextual = { disclosure_approved = true, missing = {} } }
  local result = check()
  assert.is_truthy(result:find('info:provider disclosure approved; installation alone does not establish assessment readiness', 1, true))
  assert.is_nil(result:find('warn:no key', 1, true))
end)
it('reports failed contextual installation without claiming a legacy guard failure', function()
  status = { setup_ran = true, installed = false, install_error = 'setup failed', contextual = { missing = {} } }
  local result = check()
  assert.is_truthy(result:find('error:contextual core integration not installed: setup failed', 1, true))
  assert.is_nil(result:find('error:guard not installed:', 1, true))
end)
