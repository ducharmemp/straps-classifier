package.path = './lua/?.lua;./lua/?/init.lua;' .. package.path
local plugin = require('straps_classifier')

it('rejects invalid setup before changing config or installing guards', function()
  local before = vim.deepcopy(plugin.config)
  for _, opts in ipairs({ false, { typo = true }, { timeout_ms = 0 }, { retry = 0.5 }, { opaque_action = 'allow' },
    { cutoffs = { test = 'high' } }, { always_deny_patterns = { '[' } } }) do
    assert.is_false(pcall(plugin.setup, opts))
    assert.same(before, plugin.config)
    assert.is_false(plugin.installed)
  end
end)

describe('always_deny_patterns setup validation', function()
  local saved, current, registrations

  before_each(function()
    saved = {}
    for _, name in ipairs({ 'straps_classifier', 'straps_classifier.entries', 'straps.registry' }) do
      saved[name] = package.loaded[name]
    end
    registrations = 0
    package.loaded['straps.registry'] = { guards_frozen = function() return false end }
    package.loaded['straps_classifier.entries'] = {
      register = function() registrations = registrations + 1 end,
      register_guard = function() registrations = registrations + 1 end,
    }
    package.loaded['straps_classifier'] = nil
    current = require('straps_classifier')
  end)

  after_each(function()
    for _, name in ipairs({ 'straps_classifier', 'straps_classifier.entries', 'straps.registry' }) do
      package.loaded[name] = saved[name]
    end
  end)

  for _, case in ipairs({
    { name = 'string', rule = '^danger$', shown = '^danger$' },
    { name = 'named pattern and label', rule = { pattern = '^danger$', label = 'named rule' }, shown = 'named rule' },
    { name = 'indexed pattern and label', rule = { '^danger$', label = 'indexed rule' }, shown = 'indexed rule' },
    { name = 'indexed pattern', rule = { '^danger$' }, shown = '^danger$' },
    { name = 'named pattern', rule = { pattern = '^danger$' }, shown = '^danger$' },
    { name = 'empty label', rule = { pattern = '^danger$', label = '' }, shown = '^danger$' },
  }) do
    it('accepts ' .. case.name .. ' through setup and enforces it', function()
      local opts = { always_deny_patterns = { case.rule } }
      local before = vim.deepcopy(opts)
      assert.equals(current, current.setup(opts))
      assert.same(before, opts)
      assert.same(before.always_deny_patterns, current.config.always_deny_patterns)
      assert.same(before.always_deny_patterns, current.effective().always_deny_patterns)
      assert.is_true(current.installed)
      assert.equals(2, registrations)
      local rules = require('straps_classifier.local_rules')
      local action, reason = rules.check('bash', { command = 'danger' }, current.effective())
      assert.equals('deny', action)
      assert.equals(('local rule %q matched "danger"'):format(case.shown), reason)
      assert.is_nil(rules.check('bash', { command = 'safe' }, current.effective()))
    end)
  end

  for _, case in ipairs({
    { name = 'number rule', rule = 7, error = 'must be a string or a rule table' },
    { name = 'boolean rule', rule = false, error = 'must be a string or a rule table' },
    { name = 'empty table', rule = {}, error = '.pattern must be a string' },
    { name = 'label without pattern', rule = { label = 'missing' }, error = '.pattern must be a string' },
    { name = 'numeric named pattern', rule = { pattern = 7 }, error = '.pattern must be a string' },
    { name = 'numeric indexed pattern', rule = { 7 }, error = '.pattern must be a string' },
    { name = 'table pattern', rule = { pattern = {} }, error = '.pattern must be a string' },
    { name = 'malformed string', rule = '[', error = '.pattern must be a valid Lua pattern' },
    { name = 'malformed named pattern', rule = { pattern = '[', label = 'bad' }, error = '.pattern must be a valid Lua pattern' },
    { name = 'malformed indexed pattern', rule = { '%' }, error = '.pattern must be a valid Lua pattern' },
    { name = 'numeric label', rule = { pattern = 'danger', label = 7 }, error = '.label must be a string' },
    { name = 'boolean label', rule = { 'danger', label = false }, error = '.label must be a string' },
    { name = 'table label', rule = { pattern = 'danger', label = {} }, error = '.label must be a string' },
  }) do
    it('rejects ' .. case.name .. ' before changing setup state', function()
      current.setup({ always_deny_patterns = { '^old$' } })
      local config, effective = current.config, current.effective()
      local before = vim.deepcopy(config)
      local opts = { model = 'must-not-change', always_deny_patterns = { '^valid$', case.rule } }
      local original = vim.deepcopy(opts)
      local ok, err = pcall(current.setup, opts)
      assert.is_false(ok)
      assert.is_truthy(tostring(err):find('always_deny_patterns[2]', 1, true))
      assert.is_truthy(tostring(err):find(case.error, 1, true))
      assert.equals(config, current.config)
      assert.same(effective, current.effective())
      assert.same(before, current.config)
      assert.same(before, current.effective())
      assert.same(original, opts)
      assert.is_true(current.setup_ran)
      assert.is_true(current.installed)
      assert.is_nil(current.install_error)
      assert.equals(2, registrations)
    end)
  end
end)

it('health reports missing setup and key without installing guards', function()
  local health, status, audit = vim.health, plugin.status, package.loaded['straps_classifier.audit']
  local reports = {}
  vim.health = setmetatable({}, { __index = function(_, key) return function(msg) reports[#reports + 1] = key .. ':' .. msg end end })
  plugin.status = function() return { setup_ran = false, installed = false, api_key = false, api_key_error = 'missing' } end
  package.loaded['straps_classifier.audit'] = { counts = function() return { allow = 0, deny = 0 }, {} end }
  require('straps_classifier.health').check()
  assert.is_truthy(table.concat(reports):find('error:setup() has not run', 1, true))
  assert.is_truthy(table.concat(reports):find('warn:no key', 1, true))
  vim.health, plugin.status, package.loaded['straps_classifier.audit'] = health, status, audit
end)
