// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"fmt"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/soapbucket/sbproxy/internal/request/reqctx"
)

// dayPatternValidate matches day units in duration strings (e.g., "1d", "7d", "1d12h")
var dayPatternValidate = regexp.MustCompile(`(\d+)d`)

// parseDurationWithDays parses a duration string, supporting "d" for days
// Go's time.ParseDuration doesn't support "d", so we convert it to hours
// Supports compound durations like "1d12h", "2d30m", etc.
func parseDurationWithDays(s string) (time.Duration, error) {
	// Expand day units to hours (e.g., "1d" -> "24h", "7d12h" -> "168h12h")
	expanded := dayPatternValidate.ReplaceAllStringFunc(s, func(match string) string {
		// Extract the number before "d"
		days, err := strconv.Atoi(match[:len(match)-1])
		if err != nil {
			return match // Return unchanged if parsing fails
		}
		hours := days * 24
		return strconv.Itoa(hours) + "h"
	})
	// Use standard time.ParseDuration for the expanded format
	return time.ParseDuration(expanded)
}

// validateTag holds parsed validation tag information
type validateTag struct {
	DefaultValue string
	MaxValue     string
	MinValue     string
}

// parseValidateTag parses the validate tag string
func parseValidateTag(tag string) *validateTag {
	if tag == "" {
		return nil
	}

	vt := &validateTag{}
	parts := strings.Split(tag, ",")

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			continue
		}

		key := strings.TrimSpace(kv[0])
		value := strings.TrimSpace(kv[1])

		switch key {
		case "default_value":
			vt.DefaultValue = value
		case "max_value":
			vt.MaxValue = value
		case "min_value":
			vt.MinValue = value
		}
	}

	return vt
}

// applyDefault applies the default value to a field if it's zero/empty
func applyDefault(field reflect.Value, tag *validateTag) error {
	if tag == nil || tag.DefaultValue == "" {
		return nil
	}

	// Only apply default if field is zero/empty
	if !isZero(field) {
		return nil
	}

	// Only apply default if field is settable
	if !field.CanSet() {
		// This is expected for embedded structs or unexported fields
		// Don't treat it as an error, just skip
		return nil
	}

	return setFieldValue(field, tag.DefaultValue)
}

// validateField validates a field against its validation tags
func validateField(field reflect.Value, fieldType reflect.Type, tag *validateTag, fieldPath string) []string {
	if tag == nil {
		return nil
	}

	// Check if field is zero - but don't skip if we have a value to validate
	isZeroVal := isZero(field)
	
	// Skip validation for zero/empty values (unless we're validating min_value)
	// Zero values will get defaults applied, then we validate
	if tag.MinValue == "" && isZeroVal {
		return nil
	}

	var errors []string

	// Validate max_value
	if tag.MaxValue != "" {
		if err := validateMaxValue(field, fieldType, tag.MaxValue, fieldPath); err != nil {
			errors = append(errors, err.Error())
		}
	}

	// Validate min_value
	if tag.MinValue != "" {
		if err := validateMinValue(field, fieldType, tag.MinValue, fieldPath); err != nil {
			errors = append(errors, err.Error())
		}
	}

	return errors
}

// validateMaxValue validates that a field value doesn't exceed max_value
func validateMaxValue(field reflect.Value, fieldType reflect.Type, maxStr string, fieldPath string) error {
	fieldValue := getFieldValue(field, fieldType)
	maxValue, err := parseValueForType(fieldType, maxStr)
	if err != nil {
		return fmt.Errorf("%s: invalid max_value format %q: %v", fieldPath, maxStr, err)
	}

	comparison := compareValues(fieldValue, maxValue)
	if comparison > 0 {
		return fmt.Errorf("%s: %v exceeds maximum of %v", fieldPath, formatValue(fieldValue), formatValue(maxValue))
	}

	return nil
}

// validateMinValue validates that a field value meets min_value
func validateMinValue(field reflect.Value, fieldType reflect.Type, minStr string, fieldPath string) error {
	fieldValue := getFieldValue(field, fieldType)
	minValue, err := parseValueForType(fieldType, minStr)
	if err != nil {
		return fmt.Errorf("%s: invalid min_value format %q: %v", fieldPath, minStr, err)
	}

	if compareValues(fieldValue, minValue) < 0 {
		return fmt.Errorf("%s: %v is less than minimum of %v", fieldPath, formatValue(fieldValue), formatValue(minValue))
	}

	return nil
}

// getFieldValue extracts the actual value from a field, handling Duration wrapper and string sizes
func getFieldValue(field reflect.Value, fieldType reflect.Type) interface{} {
	if fieldType == reflect.TypeOf(reqctx.Duration{}) {
		// For Duration type, get the underlying Duration
		if field.CanInterface() {
			if d, ok := field.Interface().(reqctx.Duration); ok {
				return d.Duration
			}
		}
	}
	
	// For string fields that might be size strings, try to parse as size
	// This allows comparing "20MB" > "10MB" correctly
	if fieldType.Kind() == reflect.String {
		if field.CanInterface() {
			if strVal, ok := field.Interface().(string); ok && strVal != "" {
				// Try parsing as size first
				if size, err := parseSizeToInt64WithError(strVal); err == nil {
					return size
				}
				// Try parsing as duration
				if d, err := time.ParseDuration(strVal); err == nil {
					return d
				}
				// Return as string
				return strVal
			}
		}
	}
	
	return field.Interface()
}

// parseValueForType parses a string value into the appropriate type
func parseValueForType(fieldType reflect.Type, valueStr string) (interface{}, error) {
	// Check for special types first (before checking Kind)
	if fieldType == reflect.TypeOf(time.Duration(0)) {
		d, err := parseDurationWithDays(valueStr)
		if err != nil {
			return nil, fmt.Errorf("cannot parse %q as duration: %v", valueStr, err)
		}
		return d, nil
	}

	if fieldType == reflect.TypeOf(reqctx.Duration{}) {
		d, err := parseDurationWithDays(valueStr)
		if err != nil {
			return nil, fmt.Errorf("cannot parse %q as duration: %v", valueStr, err)
		}
		return d, nil
	}

	switch fieldType.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		// Check if it's a size string (e.g., "10MB")
		if size, err := parseSizeToInt64WithError(valueStr); err == nil {
			return size, nil
		}
		// Check if it's a duration string for int64 (nanoseconds)
		if fieldType.Kind() == reflect.Int64 {
			if d, err := time.ParseDuration(valueStr); err == nil {
				return d.Nanoseconds(), nil
			}
		}
		// Try parsing as integer
		if val, err := strconv.ParseInt(valueStr, 10, 64); err == nil {
			return val, nil
		}
		return nil, fmt.Errorf("cannot parse %q as integer or size", valueStr)

	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		// Check if it's a size string
		if size, err := parseSizeToInt64WithError(valueStr); err == nil {
			return uint64(size), nil
		}
		// Try parsing as unsigned integer
		if val, err := strconv.ParseUint(valueStr, 10, 64); err == nil {
			return val, nil
		}
		return nil, fmt.Errorf("cannot parse %q as unsigned integer or size", valueStr)

	case reflect.Float32, reflect.Float64:
		if val, err := strconv.ParseFloat(valueStr, 64); err == nil {
			return val, nil
		}
		return nil, fmt.Errorf("cannot parse %q as float", valueStr)

	case reflect.String:
		// For string fields, check if it's a size string that needs parsing
		// If it looks like a size (contains MB, KB, GB, etc.), parse it
		if size, err := parseSizeToInt64WithError(valueStr); err == nil {
			// It's a valid size string, return as int64 for comparison
			return size, nil
		}
		// For duration strings, try parsing
		if d, err := time.ParseDuration(valueStr); err == nil {
			return d, nil
		}
		// Otherwise, return as string
		return valueStr, nil

	default:
		return nil, fmt.Errorf("unsupported type %v for validation", fieldType)
	}
}

// setFieldValue sets a field value from a string
func setFieldValue(field reflect.Value, valueStr string) error {
	if !field.CanSet() {
		return fmt.Errorf("field is not settable")
	}

	fieldType := field.Type()
	value, err := parseValueForType(fieldType, valueStr)
	if err != nil {
		return err
	}

	// Handle Duration wrapper type
	if fieldType == reflect.TypeOf(reqctx.Duration{}) {
		if d, ok := value.(time.Duration); ok {
			field.Set(reflect.ValueOf(reqctx.Duration{Duration: d}))
			return nil
		}
	}

	// Set the value
	val := reflect.ValueOf(value)
	if val.Type().AssignableTo(fieldType) {
		field.Set(val)
	} else if val.Type().ConvertibleTo(fieldType) {
		field.Set(val.Convert(fieldType))
	} else {
		return fmt.Errorf("cannot assign %v to %v", val.Type(), fieldType)
	}

	return nil
}

// compareValues compares two values, returning -1, 0, or 1
func compareValues(a, b interface{}) int {
	switch aVal := a.(type) {
	case int:
		// Try to convert b to int
		var bVal int
		switch bValTyped := b.(type) {
		case int:
			bVal = bValTyped
		case int64:
			bVal = int(bValTyped)
		case int32:
			bVal = int(bValTyped)
		case int16:
			bVal = int(bValTyped)
		case int8:
			bVal = int(bValTyped)
		default:
			return 0
		}
		if aVal < bVal {
			return -1
		}
		if aVal > bVal {
			return 1
		}
		return 0

	case int64:
		// Try to convert b to int64
		var bVal int64
		switch bValTyped := b.(type) {
		case int64:
			bVal = bValTyped
		case int:
			bVal = int64(bValTyped)
		case int32:
			bVal = int64(bValTyped)
		case int16:
			bVal = int64(bValTyped)
		case int8:
			bVal = int64(bValTyped)
		default:
			return 0
		}
		if aVal < bVal {
			return -1
		}
		if aVal > bVal {
			return 1
		}
		return 0

	case uint64:
		bVal, ok := b.(uint64)
		if !ok {
			return 0
		}
		if aVal < bVal {
			return -1
		}
		if aVal > bVal {
			return 1
		}
		return 0

	case float64:
		bVal, ok := b.(float64)
		if !ok {
			return 0
		}
		if aVal < bVal {
			return -1
		}
		if aVal > bVal {
			return 1
		}
		return 0

	case time.Duration:
		bVal, ok := b.(time.Duration)
		if !ok {
			return 0
		}
		if aVal < bVal {
			return -1
		}
		if aVal > bVal {
			return 1
		}
		return 0

	case string:
		// For string comparison, try to parse as sizes/durations first
		bValStr, ok := b.(string)
		if !ok {
			return 0
		}
		
		aSize, aErr := parseSizeToInt64WithError(aVal)
		bSize, bErr := parseSizeToInt64WithError(bValStr)
		if aErr == nil && bErr == nil {
			// Both are size strings, compare as sizes
			if aSize < bSize {
				return -1
			}
			if aSize > bSize {
				return 1
			}
			return 0
		}
		// Try duration comparison
		aDur, aErr := time.ParseDuration(aVal)
		bDur, bErr := time.ParseDuration(bValStr)
		if aErr == nil && bErr == nil {
			if aDur < bDur {
				return -1
			}
			if aDur > bDur {
				return 1
			}
			return 0
		}
		// Fall back to string comparison
		return strings.Compare(aVal, bValStr)

	default:
		return 0
	}
}

// formatValue formats a value for error messages
func formatValue(v interface{}) string {
	switch val := v.(type) {
	case time.Duration:
		return val.String()
	case int64:
		// Check if it's a size (multiple of 1024)
		if val%(1024*1024) == 0 && val >= 1024*1024 {
			return fmt.Sprintf("%dMB", val/(1024*1024))
		} else if val%1024 == 0 && val >= 1024 {
			return fmt.Sprintf("%dKB", val/1024)
		}
		return strconv.FormatInt(val, 10)
	case uint64:
		if val%(1024*1024) == 0 && val >= 1024*1024 {
			return fmt.Sprintf("%dMB", val/(1024*1024))
		} else if val%1024 == 0 && val >= 1024 {
			return fmt.Sprintf("%dKB", val/1024)
		}
		return strconv.FormatUint(val, 10)
	default:
		return fmt.Sprintf("%v", v)
	}
}

// isZero checks if a value is zero/empty
func isZero(v reflect.Value) bool {
	switch v.Kind() {
	case reflect.String:
		return v.Len() == 0
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return v.Int() == 0
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return v.Uint() == 0
	case reflect.Float32, reflect.Float64:
		return v.Float() == 0
	case reflect.Bool:
		return !v.Bool()
	case reflect.Slice, reflect.Map, reflect.Array:
		return v.Len() == 0
	case reflect.Interface, reflect.Ptr:
		return v.IsNil()
	case reflect.Struct:
		// For Duration wrapper, check the underlying Duration
		if v.Type() == reflect.TypeOf(reqctx.Duration{}) {
			if d, ok := v.Interface().(reqctx.Duration); ok {
				return d.Duration == 0
			}
		}
		// For time.Duration
		if v.Type() == reflect.TypeOf(time.Duration(0)) {
			return v.Interface().(time.Duration) == 0
		}
		// For other structs, check if all fields are zero
		for i := 0; i < v.NumField(); i++ {
			if !isZero(v.Field(i)) {
				return false
			}
		}
		return true
	default:
		return false
	}
}

// validateStruct validates a struct using reflection and validate tags
func validateStruct(v interface{}, pathPrefix string) []string {
	var errors []string
	val := reflect.ValueOf(v)
	typ := reflect.TypeOf(v)

	// Handle pointers
	if val.Kind() == reflect.Ptr {
		if val.IsNil() {
			return nil
		}
		val = val.Elem()
		typ = typ.Elem()
	}

	// Must be a struct
	if val.Kind() != reflect.Struct {
		return nil
	}

	// Iterate over all fields (including embedded struct fields)
	for i := 0; i < val.NumField(); i++ {
		field := val.Field(i)
		fieldType := typ.Field(i)

		// Skip unexported fields
		if !field.CanInterface() {
			continue
		}

		// Handle embedded/anonymous structs - validate their fields directly
		if fieldType.Anonymous && field.Kind() == reflect.Struct {
			// Recursively validate embedded struct
			nestedErrors := validateStruct(field.Interface(), pathPrefix)
			errors = append(errors, nestedErrors...)
			// Continue to next field (don't process embedded struct as a single field)
			continue
		}

		// Get field name for error messages
		fieldName := fieldType.Name
		fieldPath := pathPrefix
		if fieldPath != "" {
			fieldPath += "."
		}
		fieldPath += strings.ToLower(fieldName[0:1]) + fieldName[1:]

		// Get json tag name if available
		jsonTag := fieldType.Tag.Get("json")
		if jsonTag != "" && jsonTag != "-" {
			jsonParts := strings.Split(jsonTag, ",")
			if jsonParts[0] != "" {
				fieldPath = pathPrefix
				if fieldPath != "" {
					fieldPath += "."
				}
				fieldPath += jsonParts[0]
			}
		}

		// Parse validate tag
		validateTagStr := fieldType.Tag.Get("validate")
		tag := parseValidateTag(validateTagStr)

		// Apply default value if field is zero and default is specified
		if tag != nil && tag.DefaultValue != "" {
			if err := applyDefault(field, tag); err != nil {
				// Only report error if field was settable but setting failed
				// Non-settable fields (embedded structs) are expected and should be skipped
				if field.CanSet() {
					errors = append(errors, fmt.Sprintf("%s: failed to apply default: %v", fieldPath, err))
				}
			}
		}

		// Validate field value (only if tag exists and field is not an embedded struct)
		if tag != nil && !fieldType.Anonymous {
			fieldErrors := validateField(field, fieldType.Type, tag, fieldPath)
			errors = append(errors, fieldErrors...)
		}

		// Recursively validate nested structs (but skip if it's a pointer to avoid infinite recursion)
		if field.Kind() == reflect.Struct {
			if field.CanInterface() {
				nestedErrors := validateStruct(field.Interface(), fieldPath)
				errors = append(errors, nestedErrors...)
			}
		} else if field.Kind() == reflect.Ptr && !field.IsNil() {
			if field.Elem().Kind() == reflect.Struct {
				if field.CanInterface() {
					nestedErrors := validateStruct(field.Interface(), fieldPath)
					errors = append(errors, nestedErrors...)
				}
			}
		}
	}

	return errors
}

