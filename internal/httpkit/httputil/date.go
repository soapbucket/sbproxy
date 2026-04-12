// Package common provides shared HTTP utilities, helper functions, and type definitions used across packages.
package httputil

import "time"

// ParseHTTPDate parses and returns http date from the input.
func ParseHTTPDate(dateStr string) (time.Time, error) {
	d, err := time.Parse(time.RFC1123, dateStr)
	if err != nil {
		d, err = time.Parse(time.RFC822, dateStr)
		if err != nil {
			d, err = time.Parse(time.RFC850, dateStr)
			if err != nil {
				d, err = time.Parse(time.ANSIC, dateStr)
			}
		}
	}

	return d, err
}
