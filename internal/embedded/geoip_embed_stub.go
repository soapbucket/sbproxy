// geoip_embed_stub.go is a build stub that sets geoipCountryGz to nil when no GeoIP database is bundled.
package embedded

// geoipCountryGz is nil when no database is bundled. GeoIP features require the
// user to provide a database path via the geoip.params.path config option.
var geoipCountryGz []byte
