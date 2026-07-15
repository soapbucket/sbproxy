if #KEYS ~= 3 then
  return {'error', 'key_count'}
end

local storage_type_error = validate_storage_types()
if storage_type_error then
  return {'invariant', storage_type_error}
end

local reservation_prefix = ARGV[1]
local fingerprint = ARGV[2]
local policy_revision = ARGV[3]
local window_millis = tonumber(ARGV[4])
local requests_limit = optional_number(ARGV[5])
local window_tokens_limit = optional_number(ARGV[6])
local total_tokens_limit = optional_number(ARGV[7])
local total_micro_usd_limit = optional_number(ARGV[8])
local token_ceiling = tonumber(ARGV[9])
local micro_usd_ceiling = tonumber(ARGV[10])
local reservation_ttl_millis = tonumber(ARGV[11])
local terminal_retention_millis = tonumber(ARGV[12])
local now_millis = redis_now_millis()

cleanup_expired(now_millis, terminal_retention_millis)

local expires_at = checked_add(now_millis, reservation_ttl_millis)
if not expires_at then
  return {'overflow', 'expires_at_millis'}
end

local existing_state = redis.call('HGET', governance_key, reservation_prefix .. ':state')
if existing_state then
  local existing_fingerprint = redis.call(
    'HGET',
    governance_key,
    reservation_prefix .. ':fingerprint'
  )
  if existing_fingerprint ~= fingerprint then
    return {'conflict'}
  end
  if existing_state ~= 'active' then
    return {'terminal', existing_state}
  end
  return {
    'reserved',
    format_integer(read_required_number(reservation_prefix .. ':created_at')),
    format_integer(read_required_number(reservation_prefix .. ':expires_at')),
    format_integer(read_required_number(reservation_prefix .. ':window_reset'))
  }
end

local window_start, window_reset = ensure_window(now_millis, window_millis)
if not window_reset then
  return {'overflow', 'window_reset_at_millis'}
end
local denied = denial(
  'requests_per_window',
  requests_limit,
  read_number('window_used_requests'),
  read_number('window_reserved_requests'),
  1,
  window_reset
)
if denied then
  return denied
end
denied = denial(
  'tokens_per_window',
  window_tokens_limit,
  read_number('window_used_tokens'),
  read_number('window_reserved_tokens'),
  token_ceiling,
  window_reset
)
if denied then
  return denied
end
denied = denial(
  'total_tokens',
  total_tokens_limit,
  read_number('total_used_tokens'),
  read_number('total_reserved_tokens'),
  token_ceiling,
  nil
)
if denied then
  return denied
end
denied = denial(
  'total_micro_usd',
  total_micro_usd_limit,
  read_number('total_used_micro_usd'),
  read_number('total_reserved_micro_usd'),
  micro_usd_ceiling,
  nil
)
if denied then
  return denied
end

local window_reserved_requests = checked_add(
  read_number('window_reserved_requests'),
  1
)
if not window_reserved_requests then
  return {'overflow', 'window_reserved_requests'}
end
local window_reserved_tokens = checked_add(
  read_number('window_reserved_tokens'),
  token_ceiling
)
if not window_reserved_tokens then
  return {'overflow', 'window_reserved_tokens'}
end
local total_reserved_tokens = checked_add(
  read_number('total_reserved_tokens'),
  token_ceiling
)
if not total_reserved_tokens then
  return {'overflow', 'total_reserved_tokens'}
end
local total_reserved_micro_usd = checked_add(
  read_number('total_reserved_micro_usd'),
  micro_usd_ceiling
)
if not total_reserved_micro_usd then
  return {'overflow', 'total_reserved_micro_usd'}
end

redis.call(
  'HSET',
  governance_key,
  'window_reserved_requests', format_integer(window_reserved_requests),
  'window_reserved_tokens', format_integer(window_reserved_tokens),
  'total_reserved_tokens', format_integer(total_reserved_tokens),
  'total_reserved_micro_usd', format_integer(total_reserved_micro_usd),
  reservation_prefix .. ':state', 'active',
  reservation_prefix .. ':fingerprint', fingerprint,
  reservation_prefix .. ':policy_revision', policy_revision,
  reservation_prefix .. ':reserved_tokens', format_integer(token_ceiling),
  reservation_prefix .. ':reserved_micro_usd', format_integer(micro_usd_ceiling),
  reservation_prefix .. ':created_at', format_integer(now_millis),
  reservation_prefix .. ':expires_at', format_integer(expires_at),
  reservation_prefix .. ':window_start', format_integer(window_start),
  reservation_prefix .. ':window_millis', format_integer(window_millis),
  reservation_prefix .. ':window_reset', format_integer(window_reset)
)
index_active_reservation(reservation_prefix, expires_at)

return {
  'reserved',
  format_integer(now_millis),
  format_integer(expires_at),
  format_integer(window_reset)
}
