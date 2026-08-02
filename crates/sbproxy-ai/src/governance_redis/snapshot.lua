if #KEYS ~= 1 then
  return {'error', 'key_count'}
end

local window_millis = tonumber(ARGV[1])
local terminal_retention_millis = tonumber(ARGV[2])
local now_millis = redis_now_millis()

cleanup_expired(now_millis, terminal_retention_millis)
local _, window_reset = ensure_window(now_millis, window_millis)

return {
  'snapshot',
  tostring(now_millis),
  tostring(window_reset),
  tostring(read_number('window_used_requests')),
  tostring(read_number('window_reserved_requests')),
  tostring(read_number('window_used_tokens')),
  tostring(read_number('window_reserved_tokens')),
  tostring(read_number('total_used_tokens')),
  tostring(read_number('total_reserved_tokens')),
  tostring(read_number('total_used_micro_usd')),
  tostring(read_number('total_reserved_micro_usd'))
}
