package transport_test

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/soapbucket/sbproxy/internal/engine/transport"
)

// Example_basicUsage demonstrates basic usage of storage transport with connection pooling
func Example_basicUsage() {
	// Create S3 storage transport with default global cache
	settings := transport.Settings{
		transport.StorageSettingBucket: "my-bucket",
		transport.StorageSettingKey:    "AWS_ACCESS_KEY",
		transport.StorageSettingSecret: "AWS_SECRET_KEY",
		transport.StorageSettingRegion: "us-east-1",
	}

	// Uses global connection pool automatically
	_ = transport.NewStorage("s3", settings, nil)

	// In production, use in HTTP client:
	// client := &http.Client{
	// 	Transport: storageTransport,
	// 	Timeout:   30 * time.Second,
	// }

	fmt.Println("Connection pooling enabled")
	// Output: Connection pooling enabled
}

// Example_customCache demonstrates using a custom location cache
func Example_customCache() {
	// Create custom cache with specific configuration
	cacheConfig := transport.LocationCacheConfig{
		TTL:               10 * time.Minute, // Keep connections for 10 minutes
		CleanupInterval:   2 * time.Minute,  // Clean up every 2 minutes
		MaxIdleLocations:  50,               // Cache up to 50 connections
		EnableHealthCheck: true,             // Enable health checking
	}

	cache := transport.NewLocationCache(cacheConfig)
	defer cache.Close()

	// Create storage transport with custom cache
	settings := transport.Settings{
		transport.StorageSettingBucket: "my-bucket",
		transport.StorageSettingKey:    "AWS_ACCESS_KEY",
		transport.StorageSettingSecret: "AWS_SECRET_KEY",
		transport.StorageSettingRegion: "us-east-1",
	}

	storageTransport := transport.NewStorageWithCache("s3", settings, nil, cache)

	client := &http.Client{Transport: storageTransport}

	resp, err := client.Get("s3://my-bucket/file.txt")
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	// Check cache statistics
	stats := cache.GetStats()
	fmt.Printf("Cache size: %d/%d\n", stats.Size, stats.MaxSize)
	fmt.Printf("Total uses: %d\n", stats.TotalUses)
}

// Example_monitoring demonstrates monitoring cache performance
func Example_monitoring() {
	cache := transport.GetGlobalLocationCache()

	// Check cache statistics
	stats := cache.GetStats()

	fmt.Printf("Cache Statistics:\n")
	fmt.Printf("  Size: %d/%d\n", stats.Size, stats.MaxSize)
	fmt.Printf("  TTL: %v\n", stats.TTL)

	// Print individual location stats
	for _, loc := range stats.Locations {
		fmt.Printf("\nLocation: %s\n", loc.Kind)
		fmt.Printf("  Age: %v\n", loc.Age)
		fmt.Printf("  Use count: %d\n", loc.UseCount)
		fmt.Printf("  Healthy: %v\n", loc.IsHealthy)
	}
}

// Example_gracefulShutdown demonstrates proper cleanup
func Example_gracefulShutdown() {
	// Create custom cache
	cache := transport.NewLocationCache(transport.DefaultLocationCacheConfig())

	// Use cache...
	settings := transport.Settings{
		transport.StorageSettingBucket: "my-bucket",
		transport.StorageSettingKey:    "AWS_ACCESS_KEY",
		transport.StorageSettingSecret: "AWS_SECRET_KEY",
		transport.StorageSettingRegion: "us-east-1",
	}

	transport.NewStorageWithCache("s3", settings, nil, cache)

	// Graceful shutdown
	if err := cache.Close(); err != nil {
		log.Printf("Error closing cache: %v", err)
	}

	fmt.Println("Cache closed gracefully")
	// Output: Cache closed gracefully
}
