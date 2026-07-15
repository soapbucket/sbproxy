if #KEYS ~= 3 then
  return {'error', 'key_count'}
end

local storage_type_error = validate_storage_types()
if storage_type_error then
  return {'invariant', storage_type_error}
end

local reservation_prefix = ARGV[1]
local terminal_retention_millis = tonumber(ARGV[2])
local now_millis = redis_now_millis()

cleanup_expired(now_millis, terminal_retention_millis)

local state = redis.call('HGET', governance_key, reservation_prefix .. ':state')
if not state then
  return {'not_found'}
end
if state == 'released' then
  return {
    'released',
    format_integer(read_required_number(reservation_prefix .. ':policy_revision')),
    format_integer(read_required_number(reservation_prefix .. ':reserved_tokens')),
    format_integer(read_required_number(reservation_prefix .. ':reserved_micro_usd')),
    format_integer(read_required_number(reservation_prefix .. ':terminal_at'))
  }
end
if state ~= 'active' then
  return {'terminal', state}
end

local current_window_millis = read_number('window_millis')
if current_window_millis > 0 then
  local _, window_reset = ensure_window(now_millis, current_window_millis)
  if not window_reset then
    return {'overflow', 'window_reset_at_millis'}
  end
end

local reserved_tokens = read_required_number(reservation_prefix .. ':reserved_tokens')
local reserved_micro_usd = read_required_number(
  reservation_prefix .. ':reserved_micro_usd'
)
local window_reserved_requests = read_number('window_reserved_requests')
local window_reserved_tokens = read_number('window_reserved_tokens')
if same_reservation_window(reservation_prefix) then
  window_reserved_requests = checked_sub(window_reserved_requests, 1)
  if not window_reserved_requests then
    return {'invariant', 'window_reserved_requests'}
  end
  window_reserved_tokens = checked_sub(window_reserved_tokens, reserved_tokens)
  if not window_reserved_tokens then
    return {'invariant', 'window_reserved_tokens'}
  end
end
local total_reserved_tokens = checked_sub(
  read_number('total_reserved_tokens'),
  reserved_tokens
)
if not total_reserved_tokens then
  return {'invariant', 'total_reserved_tokens'}
end
local total_reserved_micro_usd = checked_sub(
  read_number('total_reserved_micro_usd'),
  reserved_micro_usd
)
if not total_reserved_micro_usd then
  return {'invariant', 'total_reserved_micro_usd'}
end
redis.call(
  'HSET',
  governance_key,
  'window_reserved_requests', format_integer(window_reserved_requests),
  'window_reserved_tokens', format_integer(window_reserved_tokens),
  'total_reserved_tokens', format_integer(total_reserved_tokens),
  'total_reserved_micro_usd', format_integer(total_reserved_micro_usd),
  reservation_prefix .. ':state', 'released',
  reservation_prefix .. ':terminal_at', format_integer(now_millis)
)
index_terminal_reservation(reservation_prefix, now_millis)

return {
  'released',
  format_integer(read_required_number(reservation_prefix .. ':policy_revision')),
  format_integer(reserved_tokens),
  format_integer(reserved_micro_usd),
  format_integer(now_millis)
}
