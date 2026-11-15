local here = debug.getinfo(1, "S").source:sub(2)
local root = vim.fn.fnamemodify(here, ":p:h:h")
local core = vim.fn.fnamemodify(os.getenv("STRAPS_ROOT") or root .. "/../straps", ":p")
package.path = root .. "/lua/?.lua;" .. root .. "/lua/?/init.lua;" .. core .. "/lua/?.lua;" .. core .. "/lua/?/init.lua;" .. package.path
vim.opt.rtp:prepend(core)

local plugin, installs, provider_calls, initial
local function options(limits)
  return { contextual = { enabled = true, limits = limits, disclosure = { approved = false } } }
end
local function valid_limits()
  return { max_bytes = 131072, max_depth = 40, max_items = 10000 }
end
before_each(function()
  for name in pairs(package.loaded) do
    if name == "straps" or name:match("^straps%.") or name:match("^straps_classifier") then package.loaded[name] = nil end
  end
  require("straps").setup({ session_dir = vim.fn.tempname(), layers = { editor = false } })
  installs, provider_calls = {}, 0
  for _, item in ipairs({ { "straps.loop", "install_human_operations" }, { "straps.provider", "install_prompt_receipts" },
      { "straps.contextual_human", "install" }, { "straps.contextual_children", "install" },
      { "straps.questions", "install_contextual" }, { "straps.loop", "install_contextual" },
      { "straps_classifier.synthesis", "install" }, { "straps_classifier.assessment", "install" } }) do
    local module, member = require(item[1]), item[2]
    local install, label = module[member], item[1] .. "." .. member
    module[member] = function(...)
      installs[#installs + 1] = label
      return install(...)
    end
  end
  package.loaded["straps.contextual_provider"] = { install = function(consumer)
    installs[#installs + 1] = "straps.contextual_provider.install"
    consumer(function() provider_calls = provider_calls + 1; return nil, "offline provider" end)
    return true
  end }
  plugin = require("straps_classifier")
  if vim.env.SETUP_VALIDATION_MUTANT == "early" then
    local source = table.concat(vim.fn.readfile(root .. "/lua/straps_classifier/init.lua"), "\n")
    local old = '    require("straps_classifier.bootstrap").validate(contextual)'
    local first, last = assert(source:find(old, 1, true))
    plugin = assert(loadstring(source:sub(1, first - 1) .. source:sub(last + 1)))()
  end
  initial = vim.deepcopy(plugin.effective())
end)

it("installs a valid production bootstrap without constructing an undisclosed provider", function()
  local ok, result = pcall(plugin.setup, options(valid_limits()))
  assert.is_true(ok, tostring(result))
  assert.is_true(plugin.installed)
  assert.is_true(plugin.status().contextual.dependencies_ready)
  assert.equals(0, provider_calls)
end)

local cases = { { name = "missing limits", make = function() return nil end },
  { name = "non-table limits", make = function() return false end } }
for _, field in ipairs({ "max_bytes", "max_depth", "max_items" }) do
  cases[#cases + 1] = { name = "missing " .. field, make = function()
    local limits = valid_limits()
    limits[field] = nil
    return limits
  end }
end
for _, field in ipairs({ "max_bytes", "max_depth", "max_items" }) do
  for _, value in ipairs({ { "zero", 0 }, { "negative", -1 }, { "fractional", 1.5 }, { "infinite", math.huge },
      { "negative infinite", -math.huge }, { "NaN", 0 / 0 }, { "string", "40" }, { "boolean", true } }) do
    cases[#cases + 1] = { name = value[1] .. " " .. field, make = function()
      local limits = valid_limits()
      limits[field] = value[2]
      return limits
    end }
  end
end

for _, case in ipairs(cases) do
  it("rejects " .. case.name .. " before setup state or dependency installation changes", function()
    local ok, reason = pcall(plugin.setup, options(case.make()))
    assert.is_false(ok, tostring(reason))
    assert.same({ config = initial, setup_ran = false, installed = false, install_error = false,
      installs = {}, provider_calls = 0, bootstrap_status = false }, {
      config = plugin.effective(), setup_ran = plugin.setup_ran == true, installed = plugin.installed,
      install_error = plugin.install_error or false, installs = installs, provider_calls = provider_calls,
      bootstrap_status = package.loaded["straps_classifier.bootstrap"] and require("straps_classifier.bootstrap").status() or false,
    })
  end)
  it("rejects repeated " .. case.name .. " instead of reporting setup success", function()
    local config = options(case.make())
    local first, first_reason = pcall(plugin.setup, config)
    assert.is_false(first, tostring(first_reason))
    local second, second_reason = pcall(plugin.setup, config)
    assert.is_false(second, tostring(second_reason))
    assert.equals(0, provider_calls)
  end)
  it("permits valid setup after rejecting " .. case.name, function()
    local invalid, invalid_reason = pcall(plugin.setup, options(case.make()))
    assert.is_false(invalid, tostring(invalid_reason))
    local valid, valid_reason = pcall(plugin.setup, options(valid_limits()))
    assert.is_true(valid, tostring(valid_reason))
    assert.is_true(plugin.installed)
    assert.is_true(plugin.status().contextual.dependencies_ready)
    assert.equals(0, provider_calls)
  end)
end
