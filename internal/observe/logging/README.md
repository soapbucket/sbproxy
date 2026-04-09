# Logging Package

This package provides structured logging for the proxy application with consistent caller information, proper grouping, and routing to appropriate backends.

## Overview

The logging system outputs all logs to stderr with configurable format:
- **Request logs**: Flat JSON format (maintains compatibility with previous format)
- **Security logs**: Structured JSON with nested groups
- **Application logs**: Structured JSON with nested groups
- **Format control**: Set `LOG_FORMAT=dev` for human-readable colored output, otherwise JSON
- **Prometheus**: Metrics data (via metrics handler wrapper)

All loggers automatically include caller information in the format `package/file.go:line` to help identify the source of log entries.

## Log Types

### 1. Request Logging

**Destination**: stderr  
**Handler**: `StderrHandler` (with `FlatMode: true`) / `RequestHandler`  
**Format**: Flat JSON (nested groups are flattened)  
**Type Tag**: `"type": "req"`

Request logs capture HTTP request/response details for analytics and monitoring. These logs use a flat structure for easy parsing and analysis.

#### Features
- Automatic caller information (`caller` field)
- Flattened structure for easy parsing
- Handles slog-chi middleware groups (`http.request.*`, `http.response.*`)
- Maps nested groups to flat field names (e.g., `request.method` → `request_method`)

#### Initialization
```go
requestLogger := logging.InitRequestLoggerWithStderr(logLevel)
requestLogger = logging.WrapLoggerWithMetrics(requestLogger)
logging.SetRequestLogger(requestLogger)
```

#### Usage
Request logging is handled automatically by the `RequestLogger` middleware which uses `slog-chi` to capture request/response details. The middleware adds:

- **Request Group**: `request` (via `RequestAttrs`)
  - `request_id`, `method`, `path`, `host`, `remote_addr`, `user_agent`, `content_length`
  
- **Response Group**: `response` (via slog-chi)
  - `status_code`, `bytes`, `duration_ms`
  
- **Origin Group**: `origin` (via `AddOriginToRequestLog`)
  - `origin_id`, `hostname`, `type`
  
- **Session Group**: `session` (if available)
  - `session_id`
  
- **User Group**: `user` (if authenticated)
  - `user_id`, `email`, `roles`
  
- **Location Group**: `location` (if available)
  - `country`, `country_code`, `asn`, `as_name`, `source_ip`
  
- **Tracing**: `trace_id`, `span_id` (if OpenTelemetry is enabled)

#### Group Flattening
The `RequestHandler` and `StderrHandler` (in flat mode) automatically flatten nested groups:
- `request.method` → `request_method`
- `response.status_code` → `response_status_code`
- `origin.origin_id` → `origin_id`
- `http.request.method` → `request_method` (slog-chi prefix removed)

### 2. Security Event Logging

**Destination**: stderr  
**Handler**: `StderrHandler`  
**Format**: Structured JSON (preserves nested groups)  
**Type Tag**: `"type": "sec"`

Security events capture authentication, authorization, and other security-related activities.

#### Features
- Automatic caller information (`caller` field)
- Preserves nested group structure for Elasticsearch
- Standardized event types and severity levels
- Includes request context (request_id, tracing) automatically

#### Initialization
```go
securityLogger := logging.InitSecurityLoggerWithStderr(logLevel)
securityLogger = logging.WrapLoggerWithMetrics(securityLogger)
logging.SetSecurityLogger(securityLogger)
```

#### Usage
Use the provided helper functions to log security events:

```go
// Authentication attempts
logging.LogAuthenticationAttempt(ctx, success, authType, username, ip, reason)

// Authorization failures
logging.LogAuthorizationFailure(ctx, authType, username, resource, ip, reason)

// Rate limit violations
logging.LogRateLimitViolation(ctx, rateLimitType, ip, userID, limit, window)

// Custom security events
logging.LogSecurityEvent(ctx, eventType, severity, action, result, attrs...)
```

#### Security Event Types
- `authentication_success` / `authentication_failure`
- `authorization_denied`
- `rate_limit_exceeded`
- `configuration_change`
- `admin_action`
- `account_locked` / `account_unlocked`
- `csrf_validation_failure`
- `input_validation_failure`
- `geo_block_violation`
- `ip_blocked`

#### Severity Levels
- `low`: Informational events
- `medium`: Notable events requiring attention
- `high`: Important security events
- `critical`: Critical security incidents

#### Standard Fields
All security events automatically include:
- `event_type`: Type of security event
- `severity`: Severity level
- `action`: Action being performed
- `result`: Result of the action (success/failure/detected/etc.)
- `request_id`: Request ID from context (if available)
- `trace_id`, `span_id`: OpenTelemetry tracing (if available)
- `caller`: Source file and line number

#### Example Security Event Structure
```json
{
  "timestamp": "2024-01-15T10:30:45.123456789Z",
  "level": "WARN",
  "message": "security event",
  "type": "security",
  "caller": "internal/auth/integration.go:78",
  "event_type": "authentication_failure",
  "severity": "high",
  "action": "authenticate",
  "result": "failure",
  "request_id": "req-123",
  "trace_id": "abc123",
  "span_id": "def456",
  "auth": {
    "auth_type": "basic",
    "username": "user@example.com",
    "ip": "192.168.1.100"
  },
  "reason": "invalid_credentials"
}
```

### 3. Application Logging

**Destination**: stderr  
**Handler**: `StderrHandler` (with `FlatMode: false`)  
**Format**: Structured JSON (preserves nested groups)  
**Type Tag**: `"type": "application"`

Application logs capture general application events, errors, and informational messages.

#### Features
- Automatic caller information (`caller` field)
- Preserves nested group structure for Elasticsearch
- Used as the default logger (`slog.Default()`)

#### Initialization
```go
applicationLogger := logging.InitApplicationLoggerWithStderr(logLevel)
applicationLogger = logging.WrapLoggerWithMetrics(applicationLogger)
logging.SetApplicationLogger(applicationLogger)
slog.SetDefault(applicationLogger)
```

#### Usage
Use standard `slog` functions throughout the application:

```go
slog.Info("message", "key", "value")
slog.Error("error occurred", "error", err)
slog.Warn("warning message", slog.Group("details", ...))
```

The caller information is automatically added by the handler, so you don't need to manually include it.

#### Program Info Group
The application logger automatically includes a `program_info` group:
- `app_version`: Application version
- `build_hash`: Build hash
- `app_env`: Environment (development/production)

## Handlers

### RequestHandler

Flattens nested groups into flat key-value pairs for request logs.

**Key Features**:
- Flattens groups: `request.method` → `request_method`
- Handles slog-chi prefixes: `http.request.method` → `request_method`
- Maps common field patterns to flat field names
- Includes caller information when `AddSource: true`

**Field Mapping**:
The handler includes intelligent field mapping for common patterns:
- Request fields: `request_*`
- Response fields: `response_*`
- Origin fields: `origin_*`
- User fields: `user_*`
- Session fields: `session_*`
- Tracing fields: `trace_id`, `span_id`
- Location fields: `country`, `country_code`, `asn`, `as_name`, `source_ip`

### StderrHandler (structured mode)

Preserves nested group structure for security and application logs.

**Key Features**:
- Preserves nested groups for structured JSON output
- Includes caller information when `AddSource: true`
- Outputs structured JSON with `FlatMode: false`

**Group Structure**:
Groups are preserved as nested objects in the JSON output:
```json
{
  "request": {
    "method": "GET",
    "path": "/api/test"
  },
  "user": {
    "user_id": "123",
    "email": "user@example.com"
  }
}
```

## Caller Information

All loggers automatically include caller information in the format:
```
internal/package/file.go:123
```

The caller information:
- Uses relative paths from project root (`internal/`)
- Falls back to filename if path doesn't match known patterns
- Is automatically added by handlers when `AddSource: true`
- Helps identify the exact source of log entries

**Note**: You should NOT manually add `"caller"` fields to log calls. The handler automatically includes this information.

## Group Structures

### Request Log Groups

Request logs use the following group structure (flattened by RequestHandler):

- `request`: Request details
- `response`: Response details
- `origin`: Origin configuration
- `user`: Authenticated user info
- `session`: Session information
- `location`: Geographic location
- `tracing`: OpenTelemetry trace context

### Security Event Groups

Security events use semantic groups:

- `auth`: Authentication details
- `authz`: Authorization details
- `rate_limit`: Rate limiting information
- `pattern`: Suspicious pattern details
- `config`: Configuration change details
- `admin`: Admin action details
- `lockout`: Account lockout details
- `geo`: Geo-blocking details
- `ip_block`: IP blocking details

## Metrics Integration

All loggers are wrapped with `MetricsHandler` which:
- Tracks log volume by level and origin
- Sends metrics to Prometheus
- Extracts origin information from log attributes or context

Metrics are automatically recorded for:
- Log level (info, warn, error, etc.)
- Origin ID (if available)

## Log Format

Logs are output to stderr with format controlled by `LOG_FORMAT` environment variable:

1. **Request Logs** (`type: "req"`):
   - Flat JSON format (maintains compatibility with previous format)
   - Used for analytics and time-series queries

2. **Security Logs** (`type: "sec"`):
   - Structured JSON with nested groups
   - Used for security monitoring and alerting

3. **Application Logs** (`type: "app"`):
   - Structured JSON with nested groups
   - Used for application monitoring and debugging

**Format Control**:
- `LOG_FORMAT=dev`: Human-readable colored output
- Any other value (or unset): JSON format

## Best Practices

1. **Use Appropriate Logger**:
   - Request logs: Automatic via middleware
   - Security events: Use `logging.LogSecurityEvent()` or helper functions
   - Application logs: Use `slog.Info()`, `slog.Error()`, etc.

2. **Group Related Fields**:
   ```go
   slog.Info("message", 
     slog.Group("request",
       slog.String("method", "GET"),
       slog.String("path", "/api"),
     ),
   )
   ```

3. **Don't Add Caller Manually**:
   - The handler automatically includes caller information
   - Don't add `"caller"` fields to log calls

4. **Use Standard Field Names**:
   - Use constants from `fields.go` for consistency
   - Use helper functions like `RequestAttrs()`, `UserAttrs()`, etc.

5. **Include Context**:
   - Always pass `context.Context` to security event functions
   - Context provides request_id and tracing information automatically

## Implementation Details

### Handler Options

Both handlers support:
- `Level`: Minimum log level
- `AddSource`: Enable/disable caller information (default: `true`)
- `ReplaceAttr`: Custom attribute transformation function

### Logger Initialization Flow

1. Create handler with appropriate options
2. Create logger with handler
3. Add type tag (`"type": "request"|"security"|"application"`)
4. Wrap with metrics handler
5. Set as global logger (for application logger)

### slog-chi Integration

The `RequestLogger` middleware uses `slog-chi` which automatically:
- Logs request start and completion
- Adds `http.request.*` and `http.response.*` groups
- Captures status code, bytes, duration

The `RequestHandler` handles slog-chi's group structure by:
- Removing `http.` prefix
- Flattening nested groups
- Mapping to flat field names

## Troubleshooting

### Missing Caller Information
- Ensure `AddSource: true` in handler options
- Check that logger is initialized with the handler

### Groups Not Flattened (Request Logs)
- Verify you're using `RequestHandler` or `StderrHandler` with `FlatMode: true` for request logs
- Check that groups are properly structured

### Groups Not Preserved (Elasticsearch)
- Verify you're using `LogstashHandler` for security/application logs
- Check that groups are properly nested in log calls

### Missing Request Context
- Ensure context is passed to security event functions
- Check that request middleware is properly configured

## Related Files

- `stderr_handler.go`: Handler for structured output to stderr
- `loggers.go`: Logger initialization and management
- `security.go`: Security event logging functions
- `fields.go`: Standard field names and helper functions
- `request_logger.go`: Request logging middleware
- `metrics_handler.go`: Metrics integration wrapper
- `context.go`: Tracing context helpers

