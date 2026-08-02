if #KEYS ~= 1 then
  return {'error', 'key_count'}
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
    redis.call('HGET', governance_key, reservation_prefix .. ':policy_revision'),
    redis.call('HGET', governance_key, reservation_prefix .. ':reserved_tokens'),
    redis.call('HGET', governance_key, reservation_prefix .. ':reserved_micro_usd'),
    redis.call('HGET', governance_key, reservation_prefix .. ':actual_tokens'),
    redis.call('HGET', governance_key, reservation_prefix .. ':actual_micro_usd'),
    redis.call('HGET', governance_key, reservation_prefix .. ':tokens_exceeded'),
    redis.call('HGET', governance_key, reservation_prefix .. ':micro_usd_exceeded'),
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
local tokens_exceeded = actual_tokens > reserved_tokens and 1 or 0
local micro_usd_exceeded = actual_micro_usd > reserved_micro_usd and 1 or 0

if same_reservation_window(reservation_prefix) then
  subtract_counter('window_reserved_requests', 1)
  subtract_counter('window_reserved_tokens', reserved_tokens)
  write_number('window_used_requests', read_number('window_used_requests') + 1)
  write_number('window_used_tokens', read_number('window_used_tokens') + actual_tokens)
end
subtract_counter('total_reserved_tokens', reserved_tokens)
subtract_counter('total_reserved_micro_usd', reserved_micro_usd)
write_number('total_used_tokens', read_number('total_used_tokens') + actual_tokens)
write_number(
  'total_used_micro_usd',
  read_number('total_used_micro_usd') + actual_micro_usd
)
redis.call(
  'HSET',
  governance_key,
  reservation_prefix .. ':state', 'settled',
  reservation_prefix .. ':actual_tokens', tostring(actual_tokens),
  reservation_prefix .. ':actual_micro_usd', tostring(actual_micro_usd),
  reservation_prefix .. ':tokens_exceeded', tostring(tokens_exceeded),
  reservation_prefix .. ':micro_usd_exceeded', tostring(micro_usd_exceeded),
  reservation_prefix .. ':terminal_at', tostring(now_millis)
)

return {
  'settled',
  redis.call('HGET', governance_key, reservation_prefix .. ':policy_revision'),
  tostring(reserved_tokens),
  tostring(reserved_micro_usd),
  tostring(actual_tokens),
  tostring(actual_micro_usd),
  tostring(tokens_exceeded),
  tostring(micro_usd_exceeded),
  tostring(now_millis)
}
