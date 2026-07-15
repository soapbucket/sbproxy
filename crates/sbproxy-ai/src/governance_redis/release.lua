if #KEYS ~= 1 then
  return {'error', 'key_count'}
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
    redis.call('HGET', governance_key, reservation_prefix .. ':policy_revision'),
    redis.call('HGET', governance_key, reservation_prefix .. ':reserved_tokens'),
    redis.call('HGET', governance_key, reservation_prefix .. ':reserved_micro_usd'),
    redis.call('HGET', governance_key, reservation_prefix .. ':terminal_at')
  }
end
if state ~= 'active' then
  return {'terminal', state}
end

local current_window_millis = read_number('window_millis')
if current_window_millis > 0 then
  ensure_window(now_millis, current_window_millis)
end

local reserved_tokens = read_number(reservation_prefix .. ':reserved_tokens')
local reserved_micro_usd = read_number(reservation_prefix .. ':reserved_micro_usd')
if same_reservation_window(reservation_prefix) then
  subtract_counter('window_reserved_requests', 1)
  subtract_counter('window_reserved_tokens', reserved_tokens)
end
subtract_counter('total_reserved_tokens', reserved_tokens)
subtract_counter('total_reserved_micro_usd', reserved_micro_usd)
redis.call(
  'HSET',
  governance_key,
  reservation_prefix .. ':state', 'released',
  reservation_prefix .. ':terminal_at', tostring(now_millis)
)

return {
  'released',
  redis.call('HGET', governance_key, reservation_prefix .. ':policy_revision'),
  tostring(reserved_tokens),
  tostring(reserved_micro_usd),
  tostring(now_millis)
}
