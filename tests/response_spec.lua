local here = debug.getinfo(1, "S").source:sub(2)
local root = vim.fn.fnamemodify(vim.fn.fnamemodify(here, ":p"), ":h:h")
package.path = root .. "/lua/?.lua;" .. root .. "/lua/?/init.lua;" .. package.path

local response = require("straps_classifier.response")
local questions = {
  hazard = { type = "noul" },
  damage = { type = "score", criteria = { "none", "some", "severe" } },
  direction = { type = "choice", criteria = { left = "left", right = "right" } },
}
local function answers()
  return {
    hazard = { type = "noul", noul = 0.2 },
    damage = { type = "score", score = 0.5, confidence = 0.9, legend = { ["0"] = "none", ["1"] = "some", ["2"] = "severe" } },
    direction = { type = "choice", choice = "left", confidence = 0.8 },
  }
end
local invalid_units = {
  { "missing" }, { "string", "0.2" }, { "boolean", false }, { "table", {} },
  { "NaN", 0 / 0 }, { "infinity", math.huge }, { "negative infinity", -math.huge },
  { "negative", -0.01 }, { "above one", 1.01 },
}

describe("response answers", function()
  for id, question in pairs(questions) do
    for _, tag in ipairs({ "missing", "wrong" }) do
      it(id .. " rejects " .. tag .. " type", function()
        local answer = answers()[id]
        answer.type = tag == "wrong" and "unknown" or nil
        assert.is_false(response.answer(question, answer))
      end)
    end
    for _, value in ipairs({ false, "answer", 1, vim.NIL }) do
      it(id .. " rejects non-table " .. tostring(value), function()
        assert.is_false(response.answer(question, value))
      end)
    end
    it(id .. " rejects absent answer", function()
      assert.is_false(response.answer(question, nil))
    end)
    local field = id == "hazard" and "noul" or "confidence"
    for _, case in ipairs(invalid_units) do
      it(id .. " rejects " .. case[1] .. " " .. field, function()
        local answer = answers()[id]
        answer[field] = case[2]
        assert.is_false(response.answer(question, answer))
      end)
    end
    for _, value in ipairs({ 0, 0.5, 1 }) do
      it(id .. " accepts " .. field .. " " .. value, function()
        local answer = answers()[id]
        answer[field] = value
        assert.is_true(response.answer(question, answer))
      end)
    end
  end
  for _, case in ipairs({ { "missing" }, { "string", "0" }, { "NaN", 0 / 0 },
    { "infinity", math.huge }, { "negative infinity", -math.huge }, { "negative", -0.1 }, { "above rubric", 2.01 } }) do
    it("rejects " .. case[1] .. " score", function()
      local answer = answers().damage
      answer.score = case[2]
      assert.is_false(response.answer(questions.damage, answer))
    end)
  end
  for _, value in ipairs({ 0, 0.5, 2 }) do
    it("accepts score " .. value .. " within rubric", function()
      local answer = answers().damage
      answer.score = value
      assert.is_true(response.answer(questions.damage, answer))
    end)
  end
  for _, case in ipairs({ { "missing" }, { "non-table", "none" }, { "empty", {} },
    { "numeric keys", { "none", "some", "severe" } },
    { "changed", { ["0"] = "none", ["1"] = "changed", ["2"] = "severe" } },
    { "extra", { ["0"] = "none", ["1"] = "some", ["2"] = "severe", ["3"] = "extra" } } }) do
    it("rejects " .. case[1] .. " legend", function()
      local answer = answers().damage
      answer.legend = case[2]
      assert.is_false(response.answer(questions.damage, answer))
    end)
  end
  for _, case in ipairs({ { "missing" }, { "unknown", "up" }, { "empty", "" }, { "numeric", 1 } }) do
    it("rejects " .. case[1] .. " choice", function()
      local answer = answers().direction
      answer.choice = case[2]
      assert.is_false(response.answer(questions.direction, answer))
    end)
  end
  for _, choice in ipairs({ "left", "right" }) do
    it("accepts member " .. choice, function()
      local answer = answers().direction
      answer.choice = choice
      assert.is_true(response.answer(questions.direction, answer))
    end)
  end
  it("rejects unsupported question type", function()
    assert.is_false(response.answer({ type = "unknown" }, { type = "unknown", confidence = 1 }))
  end)
  it("accepts the complete answer identities", function()
    local supplied = answers()
    assert.equals(supplied, response.answers(questions, supplied))
  end)
  for id in pairs(questions) do
    it("rejects missing identity " .. id, function()
      local supplied = answers()
      supplied[id] = nil
      assert.is_nil(response.answers(questions, supplied))
    end)
  end
  it("rejects an unexpected identity", function()
    local supplied = answers()
    supplied.extra = supplied.hazard
    assert.is_nil(response.answers(questions, supplied))
  end)
  for _, value in ipairs({ false, "bad", {} }) do
    it("rejects invalid questions " .. tostring(value), function()
      assert.is_nil(response.answers(value, answers()))
    end)
    it("rejects invalid answers " .. tostring(value), function()
      assert.is_nil(response.answers(questions, value))
    end)
  end
  it("rejects absent questions", function() assert.is_nil(response.answers(nil, answers())) end)
  it("rejects absent answers", function() assert.is_nil(response.answers(questions, nil)) end)
end)

local rejected_metadata = {
  { "error", "failure" }, { "errors", {} }, { "refusal", "refused" }, { "refused", true },
  { "incomplete", true }, { "complete", false }, { "completed", false },
  { "status", "incomplete" }, { "status", "failed" }, { "status", "refused" }, { "status", "unknown" },
}
local accepted_metadata = {
  {}, { "error", false }, { "errors", false }, { "refusal", false }, { "refused", false },
  { "incomplete", false }, { "complete", true }, { "completed", true },
  { "status", "completed" }, { "status", "success" },
}
local function envelope(case)
  local value = { answers = answers(), usage = { input_tokens = 12, output_tokens = 4 } }
  if case[1] then value[case[1]] = case[2] end
  return value
end

describe("response envelope", function()
  for _, case in ipairs(rejected_metadata) do
    it("rejects " .. case[1] .. "=" .. tostring(case[2]), function()
      assert.is_nil(response.envelope(questions, envelope(case)))
    end)
  end
  for _, case in ipairs(accepted_metadata) do
    it("accepts " .. (case[1] or "absent metadata") .. "=" .. tostring(case[2]), function()
      local value = envelope(case)
      assert.equals(value.answers, response.envelope(questions, value))
    end)
  end
  for _, value in ipairs({ false, "bad", 1, {} }) do
    it("rejects invalid envelope " .. tostring(value), function()
      assert.is_nil(response.envelope(questions, value))
    end)
  end
  it("rejects absent envelope", function() assert.is_nil(response.envelope(questions, nil)) end)
end)

describe("fn.typesafe transport", function()
  local saved, system, typesafe, result, calls
  local ctx = { await = function(start)
    local value
    start(function(out) value = out end)
    return value
  end }
  before_each(function()
    saved = {}
    for _, name in ipairs({ "straps.registry", "straps_classifier", "straps_classifier.questions" }) do
      saved[name] = package.loaded[name]
    end
    local definitions = {}
    local registry = {
      define = function(entry) definitions[entry.name] = entry end,
      define_default = function(entry) definitions[entry.name] = entry end,
      call = function() return "isolated-test-key" end,
      bind = function() return nil end,
    }
    package.loaded["straps.registry"] = registry
    package.loaded["straps_classifier"] = { config = { retry = 0 } }
    package.loaded["straps_classifier.questions"] = { snapshot_ask_user = function() end }
    system = vim.system
    dofile(root .. "/lua/straps_classifier/entries.lua").register()
    typesafe = loadstring(definitions["fn.typesafe"].source)()
    calls = 0
    vim.system = function(_, _, callback)
      calls = calls + 1
      callback(result)
      return { kill = function() end }
    end
    result = { code = 0, signal = 0, stdout = vim.json.encode(envelope({})) .. "\n200", stderr = "" }
  end)
  after_each(function()
    vim.system = system
    for _, name in ipairs({ "straps.registry", "straps_classifier", "straps_classifier.questions" }) do
      package.loaded[name] = saved[name]
    end
  end)
  local function invoke() return typesafe({ questions = questions }, ctx) end
  for _, case in ipairs(rejected_metadata) do
    it("rejects HTTP 200 with " .. case[1] .. "=" .. tostring(case[2]), function()
      result.stdout = vim.json.encode(envelope(case)) .. "\n200"
      assert.is_nil(invoke())
    end)
  end
  for _, case in ipairs(accepted_metadata) do
    it("accepts HTTP 200 with " .. (case[1] or "absent metadata") .. "=" .. tostring(case[2]), function()
      result.stdout = vim.json.encode(envelope(case)) .. "\n200"
      assert.same(answers(), invoke())
    end)
  end
  it("preserves usage", function()
    local _, _, usage = invoke()
    assert.same({ input_tokens = 12, output_tokens = 4 }, usage)
  end)
  it("uses the isolated process stub", function()
    invoke()
    assert.equals(1, calls)
  end)
  for _, case in ipairs({ { 7, 0 }, { 28, 0 }, { 0, 9 }, { 0, 15 }, { 7, 9 } }) do
    it("rejects HTTP 200 with exit " .. case[1] .. " signal " .. case[2], function()
      result.code, result.signal = case[1], case[2]
      assert.is_nil(invoke())
    end)
  end
  for _, status in ipairs({ 400, 429, 500, 529 }) do
    it("rejects HTTP " .. status .. " despite valid answers", function()
      result.stdout = vim.json.encode(envelope({})) .. "\n" .. status
      assert.is_nil(invoke())
    end)
  end
  for _, text in ipairs({ "invalid JSON", "null", "{}", '{"answers":false}' }) do
    it("rejects malformed body " .. text, function()
      result.stdout = text .. "\n200"
      assert.is_nil(invoke())
    end)
  end
  for id in pairs(questions) do
    it("rejects malformed HTTP answer " .. id, function()
      local value = envelope({})
      value.answers[id].type = "wrong"
      result.stdout = vim.json.encode(value) .. "\n200"
      assert.is_nil(invoke())
    end)
  end
end)
