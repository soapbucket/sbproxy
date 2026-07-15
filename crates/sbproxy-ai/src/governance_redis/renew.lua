if #KEYS ~= 3 then
  return {'error', 'key_count'}
end

local storage_type_error = validate_storage_types()
if storage_type_error then
  return {'invariant', storage_type_error}
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

local current_expiry = read_required_number(reservation_prefix .. ':expires_at')
local candidate_expiry = checked_add(now_millis, reservation_ttl_millis)
if not candidate_expiry then
  return {'overflow', 'expires_at_millis'}
end
local expires_at = math.max(current_expiry, candidate_expiry)
redis.call(
  'HSET',
  governance_key,
  reservation_prefix .. ':expires_at', format_integer(expires_at)
)
index_active_reservation(reservation_prefix, expires_at)

return {
  'reserved',
  format_integer(read_required_number(reservation_prefix .. ':created_at')),
  format_integer(expires_at),
  format_integer(read_required_number(reservation_prefix .. ':window_reset')),
  format_integer(read_required_number(reservation_prefix .. ':policy_revision')),
  format_integer(read_required_number(reservation_prefix .. ':reserved_tokens')),
  format_integer(read_required_number(reservation_prefix .. ':reserved_micro_usd'))
}
