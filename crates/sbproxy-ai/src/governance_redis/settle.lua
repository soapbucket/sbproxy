if #KEYS ~= 3 then
  return {'error', 'key_count'}
end

local storage_type_error = validate_storage_types()
if storage_type_error then
  return {'invariant', storage_type_error}
end

local reservation_prefix = ARGV[1]
local actual_tokens = tonumber(ARGV[2])
local actual_micro_usd = tonumber(ARGV[3])
local terminal_retention_millis = tonumber(ARGV[4])
local now_millis = redis_now_millis()

cleanup_expired(now_millis, terminal_retention_millis)

local state = redis.call('HGET', governance_key, reservation_prefix .. ':state')
if not state then
  return {'not_found'}
end
if state == 'settled' then
  return {
    'settled',
    format_integer(read_required_number(reservation_prefix .. ':policy_revision')),
    format_integer(read_required_number(reservation_prefix .. ':reserved_tokens')),
    format_integer(read_required_number(reservation_prefix .. ':reserved_micro_usd')),
    format_integer(read_required_number(reservation_prefix .. ':actual_tokens')),
    format_integer(read_required_number(reservation_prefix .. ':actual_micro_usd')),
    format_integer(read_required_number(reservation_prefix .. ':tokens_exceeded')),
    format_integer(read_required_number(reservation_prefix .. ':micro_usd_exceeded')),
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
local tokens_exceeded = actual_tokens > reserved_tokens and 1 or 0
local micro_usd_exceeded = actual_micro_usd > reserved_micro_usd and 1 or 0

local window_reserved_requests = read_number('window_reserved_requests')
local window_reserved_tokens = read_number('window_reserved_tokens')
local window_used_requests = read_number('window_used_requests')
local window_used_tokens = read_number('window_used_tokens')
if same_reservation_window(reservation_prefix) then
  window_reserved_requests = checked_sub(window_reserved_requests, 1)
  if not window_reserved_requests then
    return {'invariant', 'window_reserved_requests'}
  end
  window_reserved_tokens = checked_sub(window_reserved_tokens, reserved_tokens)
  if not window_reserved_tokens then
    return {'invariant', 'window_reserved_tokens'}
  end
  window_used_requests = checked_add(window_used_requests, 1)
  if not window_used_requests then
    return {'overflow', 'window_used_requests'}
  end
  window_used_tokens = checked_add(window_used_tokens, actual_tokens)
  if not window_used_tokens then
    return {'overflow', 'window_used_tokens'}
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
local total_used_tokens = checked_add(
  read_number('total_used_tokens'),
  actual_tokens
)
if not total_used_tokens then
  return {'overflow', 'total_used_tokens'}
end
local total_used_micro_usd = checked_add(
  read_number('total_used_micro_usd'),
  actual_micro_usd
)
if not total_used_micro_usd then
  return {'overflow', 'total_used_micro_usd'}
end

redis.call(
  'HSET',
  governance_key,
  'window_reserved_requests', format_integer(window_reserved_requests),
  'window_reserved_tokens', format_integer(window_reserved_tokens),
  'window_used_requests', format_integer(window_used_requests),
  'window_used_tokens', format_integer(window_used_tokens),
  'total_reserved_tokens', format_integer(total_reserved_tokens),
  'total_reserved_micro_usd', format_integer(total_reserved_micro_usd),
  'total_used_tokens', format_integer(total_used_tokens),
  'total_used_micro_usd', format_integer(total_used_micro_usd),
  reservation_prefix .. ':state', 'settled',
  reservation_prefix .. ':actual_tokens', format_integer(actual_tokens),
  reservation_prefix .. ':actual_micro_usd', format_integer(actual_micro_usd),
  reservation_prefix .. ':tokens_exceeded', format_integer(tokens_exceeded),
  reservation_prefix .. ':micro_usd_exceeded', format_integer(micro_usd_exceeded),
  reservation_prefix .. ':terminal_at', format_integer(now_millis)
)
index_terminal_reservation(reservation_prefix, now_millis)

return {
  'settled',
  format_integer(read_required_number(reservation_prefix .. ':policy_revision')),
  format_integer(reserved_tokens),
  format_integer(reserved_micro_usd),
  format_integer(actual_tokens),
  format_integer(actual_micro_usd),
  format_integer(tokens_exceeded),
  format_integer(micro_usd_exceeded),
  format_integer(now_millis)
}
