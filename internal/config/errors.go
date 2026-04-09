// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import "errors"

var (
	// ErrUnauthorizedAPIAccess is a sentinel error for unauthorized api access conditions.
	ErrUnauthorizedAPIAccess      = errors.New("config: unauthorized API access")
	// ErrProxyURLRequired is a sentinel error for proxy url required conditions.
	ErrProxyURLRequired           = errors.New("config: proxy URL is required")
	// ErrProxyInvalidURL is a sentinel error for proxy invalid url conditions.
	ErrProxyInvalidURL            = errors.New("config: proxy URL is invalid")
	// ErrStorageKindRequired is a sentinel error for storage kind required conditions.
	ErrStorageKindRequired        = errors.New("config: storage kind is required")
	// ErrStorageBucketRequired is a sentinel error for storage bucket required conditions.
	ErrStorageBucketRequired      = errors.New("config: storage bucket is required")
	// ErrInvalidStorageKind is a sentinel error for invalid storage kind conditions.
	ErrInvalidStorageKind         = errors.New("config: invalid storage kind")
	// ErrNoTargets is a sentinel error for no targets conditions.
	ErrNoTargets                  = errors.New("config: no load balancer targets configured")
	// ErrInvalidTargetURL is a sentinel error for invalid target url conditions.
	ErrInvalidTargetURL           = errors.New("config: invalid target URL")
	// ErrLoadBalancerTargetNotFound is a sentinel error for load balancer target not found conditions.
	ErrLoadBalancerTargetNotFound = errors.New("config: load balancer target not found")
	// ErrAllTargetsUnhealthy is a sentinel error returned when all load balancer targets are unhealthy.
	ErrAllTargetsUnhealthy        = errors.New("config: all load balancer targets are unhealthy")
)
