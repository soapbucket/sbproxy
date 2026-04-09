// Package uaparser parses User-Agent strings to extract browser, OS, and device information.
package uaparser

import (
	"log/slog"
	"os"

	"github.com/ua-parser/uap-go/uaparser"
	"gopkg.in/yaml.v3"
)

// NewUAParserManager creates and initializes a new UAParserManager.
func NewUAParserManager(settings Settings) (Manager, error) {
	regexFile, ok := settings.Params[ParamRegexFile]
	if !ok {
		return nil, ErrInvalidSettings
	}

	regexData, err := os.ReadFile(regexFile)
	if err != nil {
		return nil, err
	}

	var def uaparser.RegexDefinitions
	if err := yaml.Unmarshal(regexData, &def); err != nil {
		return nil, err
	}

	parser, err := uaparser.New(uaparser.WithRegexDefinitions(def))
	if err != nil {
		return nil, err
	}

	return &manager{parser: parser, driver: settings.Driver}, nil
}

type manager struct {
	parser *uaparser.Parser
	driver string
}

// Parse performs the parse operation on the manager.
func (m *manager) Parse(userAgent string) (*Result, error) {
	slog.Debug("parsing user agent", "user_agent", userAgent)
	client := m.parser.Parse(userAgent)

	result := &Result{
		UserAgent: client.UserAgent,
		OS:        client.Os,
		Device:    client.Device,
	}

	slog.Debug("user agent parsed", "user_agent", userAgent, "result", result)
	return result, nil
}

// Close releases resources held by the manager.
func (m *manager) Close() error {
	slog.Debug("closing uaparser manager")
	// uaparser.Parser doesn't have a Close method, so we just return nil
	return nil
}

// Driver performs the driver operation on the manager.
func (m *manager) Driver() string {
	return m.driver
}

func init() {
	Register(DriverUAParser, NewUAParserManager)
}
