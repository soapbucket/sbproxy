// Package proxyerr defines structured error types for the proxy.
//
// Each error carries an HTTP status code and a machine-readable error
// code, enabling consistent error responses across all proxy components.
// Errors are categorized by domain: auth, cache, config, and general.
package proxyerr
