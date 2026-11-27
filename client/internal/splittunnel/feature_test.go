package splittunnel

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEnabledFromEnv(t *testing.T) {
	tests := []struct {
		name  string
		value string
		unset bool
		want  bool
	}{
		{
			name:  "unset is disabled",
			unset: true,
			want:  false,
		},
		{
			name:  "true is enabled",
			value: "true",
			want:  true,
		},
		{
			name:  "false is disabled",
			value: "false",
			want:  false,
		},
		{
			name:  "invalid is disabled",
			value: "definitely-not-a-bool",
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(EnvEnabled, tt.value)
			if tt.unset {
				os.Unsetenv(EnvEnabled)
			}

			assert.Equal(t, tt.want, EnabledFromEnv(), "EnabledFromEnv should match the configured value")
		})
	}
}
