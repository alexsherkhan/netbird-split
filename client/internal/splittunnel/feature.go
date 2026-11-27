package splittunnel

import (
	"os"
	"strconv"

	log "github.com/sirupsen/logrus"
)

// EnvEnabled is the environment variable that toggles the split-tunnel feature.
const EnvEnabled = "NB_SPLIT_TUNNEL"

// EnabledFromEnv reports whether NB_SPLIT_TUNNEL enables split tunneling. An
// unset or invalid value leaves the feature disabled.
func EnabledFromEnv() bool {
	val := os.Getenv(EnvEnabled)
	if val == "" {
		return false
	}

	enabled, err := strconv.ParseBool(val)
	if err != nil {
		log.Warnf("failed to parse %s: %v", EnvEnabled, err)
		return false
	}
	return enabled
}
