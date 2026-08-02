local governance_key = KEYS[1]

local reservation_suffixes = {
  ':state',
  ':fingerprint',
  ':policy_revision',
  ':reserved_tokens',
  ':reserved_micro_usd',
  ':created_at',
  ':expires_at',
  ':window_start',
  ':window_millis',
  ':window_reset',
  ':actual_tokens',
  ':actual_micro_usd',
  ':tokens_exceeded',
  ':micro_usd_exceeded',
  ':terminal_at'
}

local function read_number(field)
  local value = redis.call('HGET', governance_key, field)
  if not value then
    return 0
  end
  return tonumber(value) or 0
end

local function write_number(field, value)
  redis.call('HSET', governance_key, field, tostring(value))
end

local function optional_number(value)
  if value == '' then
    return nil
  end
  return tonumber(value)
end

local function redis_now_millis()
  local value = redis.call('TIME')
  return (tonumber(value[1]) * 1000) + math.floor(tonumber(value[2]) / 1000)
end

local function fixed_window(now_millis, window_millis)
  local window_start = now_millis - (now_millis % window_millis)
  return window_start, window_start + window_millis
end

local function ensure_window(now_millis, window_millis)
  local window_start, window_reset = fixed_window(now_millis, window_millis)
  if read_number('window_millis') ~= window_millis
      or read_number('window_start') ~= window_start then
    redis.call(
      'HSET',
      governance_key,
      'window_millis', tostring(window_millis),
      'window_start', tostring(window_start),
      'window_reset', tostring(window_reset),
      'window_used_requests', '0',
      'window_reserved_requests', '0',
      'window_used_tokens', '0',
      'window_reserved_tokens', '0'
    )
  end
  return window_start, window_reset
end

local function same_reservation_window(prefix)
  return read_number('window_millis') == read_number(prefix .. ':window_millis')
      and read_number('window_start') == read_number(prefix .. ':window_start')
end

local function subtract_counter(field, amount)
  local current = read_number(field)
  if amount >= current then
    write_number(field, 0)
  else
    write_number(field, current - amount)
  end
end

local function delete_reservation(prefix)
  local fields = {}
  for _, suffix in ipairs(reservation_suffixes) do
    fields[#fields + 1] = prefix .. suffix
  end
  redis.call('HDEL', governance_key, unpack(fields))
end

local function cleanup_expired(now_millis, terminal_retention_millis)
  local values = redis.call('HGETALL', governance_key)
  local delete_prefixes = {}
  for index = 1, #values, 2 do
    local field = values[index]
    if field:sub(1, 2) == 'r:' and field:sub(-6) == ':state' then
      local prefix = field:sub(1, #field - 6)
      local state = values[index + 1]
      if state == 'active' then
        local expires_at = read_number(prefix .. ':expires_at')
        if expires_at <= now_millis then
          local reserved_tokens = read_number(prefix .. ':reserved_tokens')
          local reserved_micro_usd = read_number(prefix .. ':reserved_micro_usd')
          if same_reservation_window(prefix) then
            subtract_counter('window_reserved_requests', 1)
            subtract_counter('window_reserved_tokens', reserved_tokens)
          end
          subtract_counter('total_reserved_tokens', reserved_tokens)
          subtract_counter('total_reserved_micro_usd', reserved_micro_usd)
          redis.call(
            'HSET',
            governance_key,
            prefix .. ':state', 'expired',
            prefix .. ':terminal_at', tostring(expires_at)
          )
          state = 'expired'
        end
      end
      if state ~= 'active' then
        local terminal_at = read_number(prefix .. ':terminal_at')
        if terminal_at > 0
            and terminal_at + terminal_retention_millis <= now_millis then
          delete_prefixes[#delete_prefixes + 1] = prefix
        end
      end
    end
  end
  for _, prefix in ipairs(delete_prefixes) do
    delete_reservation(prefix)
  end
end

local function denial(
  dimension,
  limit,
  used,
  reserved,
  requested,
  reset_at_millis
)
  if limit and used + reserved + requested > limit then
    local remaining = limit - used - reserved
    if remaining < 0 then
      remaining = 0
    end
    return {
      'denied',
      dimension,
      tostring(limit),
      tostring(used),
      tostring(reserved),
      tostring(requested),
      tostring(remaining),
      reset_at_millis and tostring(reset_at_millis) or ''
    }
  end
  return nil
end
