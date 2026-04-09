// Package version exposes build version information for the proxy binary.
package version

import (
	"fmt"
	"os"
	"runtime"
)

// Details on this taken from https://medium.com/smsjunk/an-in-depth-look-at-our-docker-and-ecs-stack-for-golang-b89dfe7cff5c

const (
	// VersionMajor is build major version
	VersionMajor = 0
	// VersionMinor is build minor version
	VersionMinor = 1
	// VersionPatch is build patch version
	VersionPatch = 0
)

// Version is string representing current application version
var Version = fmt.Sprintf("%d.%d.%d", VersionMajor, VersionMinor, VersionPatch)

// BuildHash is the current hash from the git repo
var BuildHash = ""

// BuildNumber is current build number
var BuildNumber = ""

// BuildDate is current build date
var BuildDate = "1970-01-01T00:00:00Z"

// BuildPlatform is details related to the build platform and architecture
var BuildPlatform = fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH)

// GoVersion is runtime version details
var GoVersion = runtime.Version()

// AppEnv is the environment the application is running in
var AppEnv = defaultString(os.Getenv("APP_ENV"), "development")

// String performs the string operation.
func String() string {
	return Version
}

func defaultString(in, def string) string {
	if in == "" {
		return def
	}
	return in
}
