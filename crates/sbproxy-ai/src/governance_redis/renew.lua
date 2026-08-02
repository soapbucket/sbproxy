if #KEYS ~= 1 then
  return {'error', 'key_count'}
end

local reservation_prefix = ARGV[1]
local reservation_ttl_millis = tonumber(ARGV[2])
local terminal_retention_millis = tonumber(ARGV[3])
local now_millis = redis_now_millis()

cleanup_expired(now_millis, terminal_retention_millis)

local state = redis.call('HGET', governance_key, reservation_prefix .. ':state')
if not state then
  return {'not_found'}
end
if state ~= 'active' then
  return {'terminal', state}
end

local current_expiry = read_number(reservation_prefix .. ':expires_at')
local candidate_expiry = now_millis + reservation_ttl_millis
local expires_at = math.max(current_expiry, candidate_expiry)
redis.call(
  'HSET',
  governance_key,
  reservation_prefix .. ':expires_at', tostring(expires_at)
)

return {
  'renewed',
  redis.call('HGET', governance_key, reservation_prefix .. ':policy_revision'),
  redis.call('HGET', governance_key, reservation_prefix .. ':reserved_tokens'),
  redis.call('HGET', governance_key, reservation_prefix .. ':reserved_micro_usd'),
  redis.call('HGET', governance_key, reservation_prefix .. ':created_at'),
  tostring(expires_at),
  redis.call('HGET', governance_key, reservation_prefix .. ':window_reset')
}
