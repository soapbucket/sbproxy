if #KEYS ~= 1 then
  return {'error', 'key_count'}
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
    redis.call('HGET', governance_key, reservation_prefix .. ':created_at'),
    redis.call('HGET', governance_key, reservation_prefix .. ':expires_at'),
    redis.call('HGET', governance_key, reservation_prefix .. ':window_reset')
  }
end

local window_start, window_reset = ensure_window(now_millis, window_millis)
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

local expires_at = now_millis + reservation_ttl_millis
redis.call(
  'HSET',
  governance_key,
  'window_reserved_requests', tostring(read_number('window_reserved_requests') + 1),
  'window_reserved_tokens', tostring(read_number('window_reserved_tokens') + token_ceiling),
  'total_reserved_tokens', tostring(read_number('total_reserved_tokens') + token_ceiling),
  'total_reserved_micro_usd', tostring(read_number('total_reserved_micro_usd') + micro_usd_ceiling),
  reservation_prefix .. ':state', 'active',
  reservation_prefix .. ':fingerprint', fingerprint,
  reservation_prefix .. ':policy_revision', policy_revision,
  reservation_prefix .. ':reserved_tokens', tostring(token_ceiling),
  reservation_prefix .. ':reserved_micro_usd', tostring(micro_usd_ceiling),
  reservation_prefix .. ':created_at', tostring(now_millis),
  reservation_prefix .. ':expires_at', tostring(expires_at),
  reservation_prefix .. ':window_start', tostring(window_start),
  reservation_prefix .. ':window_millis', tostring(window_millis),
  reservation_prefix .. ':window_reset', tostring(window_reset)
)

return {
  'reserved',
  tostring(now_millis),
  tostring(expires_at),
  tostring(window_reset)
}
