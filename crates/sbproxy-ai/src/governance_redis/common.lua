local governance_key = KEYS[1]
local active_expiry_key = KEYS[2]
local terminal_expiry_key = KEYS[3]
local max_exact_integer = 9007199254740991

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

local function format_integer(value)
  return string.format('%.0f', value)
end

local function checked_add(left, right)
  if left < 0 or right < 0 or left > max_exact_integer - right then
    return nil
  end
  return left + right
end

local function checked_sub(left, right)
  if left < 0 or right < 0 or right > left then
    return nil
  end
  return left - right
end

local function read_number(field)
  local value = redis.call('HGET', governance_key, field)
  if not value then
    return 0
  end
  local number = tonumber(value)
  if not number or number < 0 or number > max_exact_integer or number % 1 ~= 0 then
    error('invalid governance integer field')
  end
  return number
end

local function read_required_number(field)
  local value = redis.call('HGET', governance_key, field)
  if not value then
    error('missing governance reservation integer field')
  end
  local number = tonumber(value)
  if not number or number < 0 or number > max_exact_integer or number % 1 ~= 0 then
    error('invalid governance integer field')
  end
  return number
end

local function write_number(field, value)
  redis.call('HSET', governance_key, field, format_integer(value))
end

local function optional_number(value)
  if value == '' then
    return nil
  end
  local number = tonumber(value)
  if not number or number < 0 or number > max_exact_integer or number % 1 ~= 0 then
    error('invalid governance integer argument')
  end
  return number
end

local function redis_now_millis()
  local value = redis.call('TIME')
  return (tonumber(value[1]) * 1000) + math.floor(tonumber(value[2]) / 1000)
end

local function key_type(key)
  local reply = redis.call('TYPE', key)
  if type(reply) == 'table' then
    return reply.ok
  end
  return reply
end

local function validate_storage_types()
  local governance_type = key_type(governance_key)
  if governance_type ~= 'none' and governance_type ~= 'hash' then
    return 'governance_key_type'
  end
  local active_expiry_type = key_type(active_expiry_key)
  if active_expiry_type ~= 'none' and active_expiry_type ~= 'zset' then
    return 'active_expiry_key_type'
  end
  local terminal_expiry_type = key_type(terminal_expiry_key)
  if terminal_expiry_type ~= 'none' and terminal_expiry_type ~= 'zset' then
    return 'terminal_expiry_key_type'
  end
  return nil
end

local function fixed_window(now_millis, window_millis)
  local window_start = now_millis - (now_millis % window_millis)
  return window_start, checked_add(window_start, window_millis)
end

local function ensure_window(now_millis, window_millis)
  local window_start, window_reset = fixed_window(now_millis, window_millis)
  if not window_reset then
    return nil, nil
  end
  if read_number('window_millis') ~= window_millis
      or read_number('window_start') ~= window_start then
    redis.call(
      'HSET',
      governance_key,
      'window_millis', format_integer(window_millis),
      'window_start', format_integer(window_start),
      'window_reset', format_integer(window_reset),
      'window_used_requests', '0',
      'window_reserved_requests', '0',
      'window_used_tokens', '0',
      'window_reserved_tokens', '0'
    )
  end
  return window_start, window_reset
end

local function same_reservation_window(prefix)
  return read_number('window_millis')
        == read_required_number(prefix .. ':window_millis')
      and read_number('window_start')
        == read_required_number(prefix .. ':window_start')
end

local function index_active_reservation(prefix, expires_at)
  redis.call(
    'ZADD',
    active_expiry_key,
    format_integer(expires_at),
    prefix
  )
  redis.call('ZREM', terminal_expiry_key, prefix)
end

local function index_terminal_reservation(prefix, terminal_at)
  redis.call('ZREM', active_expiry_key, prefix)
  redis.call(
    'ZADD',
    terminal_expiry_key,
    format_integer(terminal_at),
    prefix
  )
end

local function delete_reservation(prefix)
  local fields = {}
  for _, suffix in ipairs(reservation_suffixes) do
    fields[#fields + 1] = prefix .. suffix
  end
  redis.call('HDEL', governance_key, unpack(fields))
  redis.call('ZREM', active_expiry_key, prefix)
  redis.call('ZREM', terminal_expiry_key, prefix)
end

local function cleanup_expired(now_millis, terminal_retention_millis)
  local due_active = redis.call(
    'ZRANGEBYSCORE',
    active_expiry_key,
    '-inf',
    format_integer(now_millis)
  )
  local retention_cutoff = nil
  local due_terminal = {}
  if now_millis >= terminal_retention_millis then
    retention_cutoff = now_millis - terminal_retention_millis
    due_terminal = redis.call(
      'ZRANGEBYSCORE',
      terminal_expiry_key,
      '-inf',
      format_integer(retention_cutoff)
    )
  end

  local expired = {}
  local active_repairs = {}
  local terminal_repairs = {}
  local terminal_deletes = {}
  local orphaned = {}
  local handled = {}
  local expired_window_requests = 0
  local expired_window_tokens = 0
  local expired_total_tokens = 0
  local expired_total_micro_usd = 0

  local function collect_expired(prefix, expires_at)
    local reserved_tokens = read_required_number(prefix .. ':reserved_tokens')
    local reserved_micro_usd = read_required_number(
      prefix .. ':reserved_micro_usd'
    )
    if same_reservation_window(prefix) then
      expired_window_requests = checked_add(expired_window_requests, 1)
      expired_window_tokens = checked_add(
        expired_window_tokens,
        reserved_tokens
      )
    end
    expired_total_tokens = checked_add(
      expired_total_tokens,
      reserved_tokens
    )
    expired_total_micro_usd = checked_add(
      expired_total_micro_usd,
      reserved_micro_usd
    )
    if not expired_window_requests
        or not expired_window_tokens
        or not expired_total_tokens
        or not expired_total_micro_usd then
      error('governance cleanup integer overflow')
    end
    expired[#expired + 1] = {
      prefix = prefix,
      terminal_at = expires_at,
      delete_immediately = retention_cutoff
          and expires_at <= retention_cutoff
    }
  end

  for _, prefix in ipairs(due_active) do
    handled[prefix] = true
    local state = redis.call('HGET', governance_key, prefix .. ':state')
    if not state then
      orphaned[#orphaned + 1] = prefix
    elseif state == 'active' then
      local expires_at = read_required_number(prefix .. ':expires_at')
      if expires_at <= now_millis then
        collect_expired(prefix, expires_at)
      else
        active_repairs[#active_repairs + 1] = {
          prefix = prefix,
          expires_at = expires_at
        }
      end
    else
      local terminal_at = read_required_number(prefix .. ':terminal_at')
      if terminal_at == 0 then
        error('governance terminal reservation has no timestamp')
      end
      if retention_cutoff and terminal_at <= retention_cutoff then
        terminal_deletes[#terminal_deletes + 1] = prefix
      else
        terminal_repairs[#terminal_repairs + 1] = {
          prefix = prefix,
          terminal_at = terminal_at
        }
      end
    end
  end

  for _, prefix in ipairs(due_terminal) do
    if not handled[prefix] then
      local state = redis.call('HGET', governance_key, prefix .. ':state')
      if not state then
        orphaned[#orphaned + 1] = prefix
      elseif state == 'active' then
        local expires_at = read_required_number(prefix .. ':expires_at')
        if expires_at <= now_millis then
          collect_expired(prefix, expires_at)
        else
          active_repairs[#active_repairs + 1] = {
            prefix = prefix,
            expires_at = expires_at
          }
        end
      else
        local terminal_at = read_required_number(prefix .. ':terminal_at')
        if terminal_at == 0 then
          error('governance terminal reservation has no timestamp')
        elseif terminal_at <= retention_cutoff then
          terminal_deletes[#terminal_deletes + 1] = prefix
        else
          terminal_repairs[#terminal_repairs + 1] = {
            prefix = prefix,
            terminal_at = terminal_at
          }
        end
      end
    end
  end

  if #expired > 0 then
    local window_reserved_requests = checked_sub(
      read_number('window_reserved_requests'),
      expired_window_requests
    )
    local window_reserved_tokens = checked_sub(
      read_number('window_reserved_tokens'),
      expired_window_tokens
    )
    local total_reserved_tokens = checked_sub(
      read_number('total_reserved_tokens'),
      expired_total_tokens
    )
    local total_reserved_micro_usd = checked_sub(
      read_number('total_reserved_micro_usd'),
      expired_total_micro_usd
    )
    if not window_reserved_requests
        or not window_reserved_tokens
        or not total_reserved_tokens
        or not total_reserved_micro_usd then
      error('governance cleanup counter invariant failed')
    end
    redis.call(
      'HSET',
      governance_key,
      'window_reserved_requests', format_integer(window_reserved_requests),
      'window_reserved_tokens', format_integer(window_reserved_tokens),
      'total_reserved_tokens', format_integer(total_reserved_tokens),
      'total_reserved_micro_usd', format_integer(total_reserved_micro_usd)
    )
    for _, record in ipairs(expired) do
      if record.delete_immediately then
        delete_reservation(record.prefix)
      else
        redis.call(
          'HSET',
          governance_key,
          record.prefix .. ':state', 'expired',
          record.prefix .. ':terminal_at', format_integer(record.terminal_at)
        )
        index_terminal_reservation(record.prefix, record.terminal_at)
      end
    end
  end

  for _, prefix in ipairs(orphaned) do
    redis.call('ZREM', active_expiry_key, prefix)
    redis.call('ZREM', terminal_expiry_key, prefix)
  end
  for _, record in ipairs(active_repairs) do
    index_active_reservation(record.prefix, record.expires_at)
  end
  for _, record in ipairs(terminal_repairs) do
    index_terminal_reservation(record.prefix, record.terminal_at)
  end
  for _, prefix in ipairs(terminal_deletes) do
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
  local occupied = checked_add(used, reserved)
  if not occupied then
    return {'overflow', 'used_and_reserved'}
  end
  local prospective = checked_add(occupied, requested)
  if not prospective then
    return {'overflow', 'prospective_usage'}
  end
  if limit and prospective > limit then
    local remaining = limit - occupied
    if remaining < 0 then
      remaining = 0
    end
    return {
      'denied',
      dimension,
      format_integer(limit),
      format_integer(used),
      format_integer(reserved),
      format_integer(requested),
      format_integer(remaining),
      reset_at_millis and format_integer(reset_at_millis) or ''
    }
  end
  return nil
end
