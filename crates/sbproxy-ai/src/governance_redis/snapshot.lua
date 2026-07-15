if #KEYS ~= 3 then
  return {'error', 'key_count'}
end

local storage_type_error = validate_storage_types()
if storage_type_error then
  return {'invariant', storage_type_error}
end

local window_millis = tonumber(ARGV[1])
local terminal_retention_millis = tonumber(ARGV[2])
local now_millis = redis_now_millis()

cleanup_expired(now_millis, terminal_retention_millis)
local _, window_reset = ensure_window(now_millis, window_millis)
if not window_reset then
  return {'overflow', 'window_reset_at_millis'}
end

return {
  'snapshot',
  format_integer(now_millis),
  format_integer(window_reset),
  format_integer(read_number('window_used_requests')),
  format_integer(read_number('window_reserved_requests')),
  format_integer(read_number('window_used_tokens')),
  format_integer(read_number('window_reserved_tokens')),
  format_integer(read_number('total_used_tokens')),
  format_integer(read_number('total_reserved_tokens')),
  format_integer(read_number('total_used_micro_usd')),
  format_integer(read_number('total_reserved_micro_usd'))
}
