local M = {}

local function unit(value)
  return type(value) == "number" and value >= 0 and value <= 1
end

function M.answer(question, answer)
  if type(answer) ~= "table" or answer.type ~= question.type then return false end
  if question.type == "noul" then return unit(answer.noul) end
  if not unit(answer.confidence) then return false end
  if question.type == "choice" then
    return type(answer.choice) == "string" and question.criteria[answer.choice] ~= nil
  end
  if question.type ~= "score" or type(answer.score) ~= "number"
    or not (answer.score >= 0 and answer.score <= #question.criteria - 1) then return false end
  local legend = {}
  for i, text in ipairs(question.criteria) do legend[tostring(i - 1)] = text end
  return vim.deep_equal(legend, answer.legend)
end

function M.answers(questions, answers)
  if type(questions) ~= "table" or next(questions) == nil or type(answers) ~= "table" then
    return nil, "missing questions or answers"
  end
  for id, question in pairs(questions) do
    if not M.answer(question, answers[id]) then
      return nil, ("missing or malformed answer for %q"):format(id)
    end
  end
  for id in pairs(answers) do
    if questions[id] == nil then return nil, "unexpected answer identity" end
  end
  return answers
end

function M.envelope(questions, decoded)
  if type(decoded) ~= "table" then return nil, "unparseable response" end
  for _, field in ipairs({ "error", "errors", "refusal", "refused", "incomplete" }) do
    if decoded[field] ~= nil and decoded[field] ~= false then return nil, "response indicates " .. field end
  end
  for _, field in ipairs({ "complete", "completed" }) do
    if decoded[field] ~= nil and decoded[field] ~= true then return nil, "response is not complete" end
  end
  if decoded.status ~= nil and decoded.status ~= "completed" and decoded.status ~= "success" then
    return nil, "response status is not successful"
  end
  return M.answers(questions, decoded.answers)
end

return M
