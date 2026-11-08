local root = vim.fn.fnamemodify(debug.getinfo(1, "S").source:sub(2), ":p:h:h")
package.path = root .. "/lua/?.lua;" .. package.path

local entries = require("straps_classifier.entries")

describe("classification progress", function()
  local saved, timers, queued, echoes

  before_each(function()
    saved = { timer = vim.uv.new_timer, schedule = vim.schedule, echo = vim.api.nvim_echo }
    timers, queued, echoes = {}, {}, {}
    vim.uv.new_timer = function()
      local timer = { stopped = false, closed = false }
      function timer:start(_, _, callback) self.callback = callback end
      function timer:is_closing() return self.closed end
      function timer:stop() self.stopped = true end
      function timer:close() self.closed = true end
      timers[#timers + 1] = timer
      return timer
    end
    vim.schedule = function(callback) queued[#queued + 1] = callback end
    vim.api.nvim_echo = function(chunks) echoes[#echoes + 1] = chunks[1][1] end
  end)

  after_each(function()
    vim.uv.new_timer, vim.schedule, vim.api.nvim_echo = saved.timer, saved.schedule, saved.echo
  end)

  local function flush()
    while #queued > 0 do table.remove(queued, 1)() end
  end

  for _, newest_first in ipairs({ false, true }) do
    it("keeps overlapping sessions visible when " .. (newest_first and "newest" or "oldest") .. " completes first", function()
      local stop_old = entries.start_progress("old-session")
      timers[1].callback()
      flush()
      assert.equals("straps_classifier: classifying old-session…", echoes[#echoes])
      local stop_new = entries.start_progress("new-session")
      timers[2].callback()
      flush()
      assert.equals("straps_classifier: classifying new-session…", echoes[#echoes])
      if newest_first then stop_new() else stop_old() end
      flush()
      assert.equals("straps_classifier: classifying " .. (newest_first and "old-session…" or "new-session…"), echoes[#echoes])
      if newest_first then stop_old() else stop_new() end
      flush()
      assert.equals("", echoes[#echoes])
      for _, timer in ipairs(timers) do
        assert.is_true(timer.stopped)
        assert.is_true(timer.closed)
      end
      local count = #echoes
      stop_new()
      stop_old()
      for _, timer in ipairs(timers) do timer.callback() end
      flush()
      assert.equals(count, #echoes)
    end)
  end

  it("does not let an ineligible newer session hide eligible progress", function()
    local stop_old = entries.start_progress("eligible")
    timers[1].callback()
    local stop_new = entries.start_progress("waiting")
    flush()
    assert.equals("straps_classifier: classifying eligible…", echoes[#echoes])
    stop_new()
    flush()
    assert.equals("straps_classifier: classifying eligible…", echoes[#echoes])
    stop_old()
    flush()
    assert.equals("", echoes[#echoes])
  end)

  it("reads pending state when queued callbacks run after completion", function()
    local stop_old = entries.start_progress("finished")
    timers[1].callback()
    stop_old()
    local stop_new = entries.start_progress("current")
    timers[2].callback()
    flush()
    assert.same({ "straps_classifier: classifying current…" }, echoes)
    stop_new()
    flush()
    assert.same({ "straps_classifier: classifying current…", "" }, echoes)
    local stop_fast = entries.start_progress("fast")
    stop_fast()
    timers[3].callback()
    flush()
    assert.equals(2, #echoes)
    assert.is_true(timers[3].closed)
    assert.is_true(timers[3].stopped)
  end)
end)
