package vault

import (
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/superplanehq/superplane/pkg/configuration"
	"github.com/superplanehq/superplane/pkg/core"
	"github.com/superplanehq/superplane/test/support/contexts"
)

func Test__OnSecretChange__Name(t *testing.T) {
	trigger := &OnSecretChange{}
	assert.Equal(t, "vault.onSecretChange", trigger.Name())
}

func Test__OnSecretChange__Label(t *testing.T) {
	trigger := &OnSecretChange{}
	assert.Equal(t, "On Secret Change", trigger.Label())
}

func Test__OnSecretChange__Description(t *testing.T) {
	trigger := &OnSecretChange{}
	assert.Equal(t, "Triggers when a secret version changes in HashiCorp Vault KV v2", trigger.Description())
}

func Test__OnSecretChange__Documentation(t *testing.T) {
	trigger := &OnSecretChange{}
	doc := trigger.Documentation()
	assert.Contains(t, doc, "On Secret Change trigger")
	assert.Contains(t, doc, "Use Cases")
	assert.Contains(t, doc, "Configuration")
	assert.Contains(t, doc, "Polling Interval")
}

func Test__OnSecretChange__Icon(t *testing.T) {
	trigger := &OnSecretChange{}
	assert.Equal(t, "activity", trigger.Icon())
}

func Test__OnSecretChange__Color(t *testing.T) {
	trigger := &OnSecretChange{}
	assert.Equal(t, "gray", trigger.Color())
}

func Test__OnSecretChange__ExampleData(t *testing.T) {
	trigger := &OnSecretChange{}
	data := trigger.ExampleData()

	assert.Equal(t, "apps/myapp/database", data["secretPath"])
	assert.Equal(t, "secret", data["mountPath"])
	assert.Equal(t, 2, data["previousVersion"])
	assert.Equal(t, 3, data["currentVersion"])

	// Metadata fields are at root level
	assert.Equal(t, false, data["cas_required"])
	assert.Equal(t, "2024-01-15T10:30:00Z", data["created_time"])
	assert.Equal(t, "2024-01-16T14:20:00Z", data["updated_time"])
	assert.Equal(t, "0s", data["delete_version_after"])
	assert.Equal(t, 0, data["max_versions"])
	assert.Equal(t, 1, data["oldest_version"])

	versions, ok := data["versions"].(map[string]any)
	require.True(t, ok)
	assert.Len(t, versions, 3)
}

func Test__OnSecretChange__Configuration(t *testing.T) {
	trigger := &OnSecretChange{}
	fields := trigger.Configuration()

	require.Len(t, fields, 3)

	t.Run("mountPath field", func(t *testing.T) {
		field := findField(fields, "mountPath")
		require.NotNil(t, field)
		assert.Equal(t, "Mount Path", field.Label)
		assert.Equal(t, configuration.FieldTypeString, field.Type)
		assert.True(t, field.Required)
	})

	t.Run("secretPath field", func(t *testing.T) {
		field := findField(fields, "secretPath")
		require.NotNil(t, field)
		assert.Equal(t, "Secret Path", field.Label)
		assert.Equal(t, configuration.FieldTypeString, field.Type)
		assert.True(t, field.Required)
	})

	t.Run("pollingInterval field", func(t *testing.T) {
		field := findField(fields, "pollingInterval")
		require.NotNil(t, field)
		assert.Equal(t, "Polling Interval", field.Label)
		assert.Equal(t, configuration.FieldTypeSelect, field.Type)
		assert.True(t, field.Required)
		assert.Equal(t, "5m", field.Default)
		require.NotNil(t, field.TypeOptions)
		require.NotNil(t, field.TypeOptions.Select)
		assert.Len(t, field.TypeOptions.Select.Options, 5)
	})
}

func Test__OnSecretChange__Actions(t *testing.T) {
	trigger := &OnSecretChange{}
	actions := trigger.Actions()

	require.Len(t, actions, 1)
	assert.Equal(t, OnSecretChangePollAction, actions[0].Name)
	assert.Equal(t, "Poll Vault for secret version changes", actions[0].Description)
	assert.False(t, actions[0].UserAccessible)
}

func Test__OnSecretChange__Setup(t *testing.T) {
	t.Run("validates mountPath is required", func(t *testing.T) {
		trigger := &OnSecretChange{}
		metadata := &contexts.MetadataContext{}

		err := trigger.Setup(core.TriggerContext{
			Configuration: map[string]any{
				"mountPath":       "",
				"secretPath":      "myapp/credentials",
				"pollingInterval": "5m",
			},
			Metadata: metadata,
		})

		require.Error(t, err)
		assert.Contains(t, err.Error(), "mountPath is required")
	})

	t.Run("validates secretPath is required", func(t *testing.T) {
		trigger := &OnSecretChange{}
		metadata := &contexts.MetadataContext{}

		err := trigger.Setup(core.TriggerContext{
			Configuration: map[string]any{
				"mountPath":       "secret",
				"secretPath":      "",
				"pollingInterval": "5m",
			},
			Metadata: metadata,
		})

		require.Error(t, err)
		assert.Contains(t, err.Error(), "secretPath is required")
	})

	t.Run("validates invalid polling interval", func(t *testing.T) {
		trigger := &OnSecretChange{}
		metadata := &contexts.MetadataContext{}

		err := trigger.Setup(core.TriggerContext{
			Configuration: map[string]any{
				"mountPath":       "secret",
				"secretPath":      "myapp/credentials",
				"pollingInterval": "invalid",
			},
			Metadata: metadata,
		})

		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid pollingInterval")
	})

	t.Run("requires integration context", func(t *testing.T) {
		trigger := &OnSecretChange{}
		metadata := &contexts.MetadataContext{}

		err := trigger.Setup(core.TriggerContext{
			Configuration: map[string]any{
				"mountPath":       "secret",
				"secretPath":      "myapp/credentials",
				"pollingInterval": "5m",
			},
			Metadata:    metadata,
			Integration: nil,
		})

		require.Error(t, err)
		assert.Contains(t, err.Error(), "missing integration context")
	})

	t.Run("requires metadata context", func(t *testing.T) {
		trigger := &OnSecretChange{}

		err := trigger.Setup(core.TriggerContext{
			Configuration: map[string]any{
				"mountPath":       "secret",
				"secretPath":      "myapp/credentials",
				"pollingInterval": "5m",
			},
			Metadata: nil,
			Integration: &contexts.IntegrationContext{
				Configuration: map[string]any{
					"baseUrl":    "https://vault.example.com",
					"authMethod": AuthTypeToken,
					"token":      "test-token",
				},
			},
		})

		require.Error(t, err)
		assert.Contains(t, err.Error(), "missing metadata context")
	})

	t.Run("initializes metadata and schedules polling on success", func(t *testing.T) {
		trigger := &OnSecretChange{}
		metadata := &contexts.MetadataContext{}
		requests := &contexts.RequestContext{}
		httpCtx := &contexts.HTTPContext{
			Responses: []*http.Response{
				triggerMockResponse(http.StatusOK, `{
					"data": {
						"current_version": 5,
						"updated_time": "2024-01-16T14:20:00Z",
						"created_time": "2024-01-15T10:30:00Z"
					}
				}`),
			},
		}

		err := trigger.Setup(core.TriggerContext{
			Configuration: map[string]any{
				"mountPath":       "secret",
				"secretPath":      "myapp/credentials",
				"pollingInterval": "5m",
			},
			Metadata: metadata,
			Requests: requests,
			HTTP:     httpCtx,
			Integration: &contexts.IntegrationContext{
				Configuration: map[string]any{
					"baseUrl":    "https://vault.example.com",
					"authMethod": AuthTypeToken,
					"token":      "test-token",
				},
			},
		})

		require.NoError(t, err)

		// Verify metadata was set
		storedMetadata, ok := metadata.Metadata.(OnSecretChangeMetadata)
		require.True(t, ok)
		assert.Equal(t, 5, storedMetadata.LastKnownVersion)
		assert.Equal(t, "2024-01-16T14:20:00Z", storedMetadata.LastUpdatedTime)

		// Verify polling was scheduled
		assert.Equal(t, OnSecretChangePollAction, requests.Action)
		assert.Equal(t, 5*time.Minute, requests.Duration)
	})

	t.Run("does not overwrite existing metadata", func(t *testing.T) {
		trigger := &OnSecretChange{}
		metadata := &contexts.MetadataContext{
			Metadata: OnSecretChangeMetadata{
				LastKnownVersion: 3,
				LastUpdatedTime:  "2024-01-10T00:00:00Z",
			},
		}
		requests := &contexts.RequestContext{}
		httpCtx := &contexts.HTTPContext{
			Responses: []*http.Response{
				triggerMockResponse(http.StatusOK, `{
					"data": {
						"current_version": 5,
						"updated_time": "2024-01-16T14:20:00Z",
						"created_time": "2024-01-15T10:30:00Z"
					}
				}`),
			},
		}

		err := trigger.Setup(core.TriggerContext{
			Configuration: map[string]any{
				"mountPath":       "secret",
				"secretPath":      "myapp/credentials",
				"pollingInterval": "5m",
			},
			Metadata: metadata,
			Requests: requests,
			HTTP:     httpCtx,
			Integration: &contexts.IntegrationContext{
				Configuration: map[string]any{
					"baseUrl":    "https://vault.example.com",
					"authMethod": AuthTypeToken,
					"token":      "test-token",
				},
			},
		})

		require.NoError(t, err)

		// Metadata should not be overwritten
		storedMetadata, ok := metadata.Metadata.(OnSecretChangeMetadata)
		require.True(t, ok)
		assert.Equal(t, 3, storedMetadata.LastKnownVersion)
		assert.Equal(t, "2024-01-10T00:00:00Z", storedMetadata.LastUpdatedTime)
	})

	t.Run("returns error when secret not found", func(t *testing.T) {
		trigger := &OnSecretChange{}
		metadata := &contexts.MetadataContext{}
		httpCtx := &contexts.HTTPContext{
			Responses: []*http.Response{
				triggerMockResponse(http.StatusNotFound, `{"errors": ["secret not found"]}`),
			},
		}

		err := trigger.Setup(core.TriggerContext{
			Configuration: map[string]any{
				"mountPath":       "secret",
				"secretPath":      "nonexistent/path",
				"pollingInterval": "5m",
			},
			Metadata: metadata,
			HTTP:     httpCtx,
			Integration: &contexts.IntegrationContext{
				Configuration: map[string]any{
					"baseUrl":    "https://vault.example.com",
					"authMethod": AuthTypeToken,
					"token":      "test-token",
				},
			},
		})

		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to read secret metadata")
	})
}

func Test__OnSecretChange__HandleAction(t *testing.T) {
	t.Run("returns error for unknown action", func(t *testing.T) {
		trigger := &OnSecretChange{}

		_, err := trigger.HandleAction(core.TriggerActionContext{
			Name: "unknown",
		})

		require.Error(t, err)
		assert.Contains(t, err.Error(), "unknown action")
	})

	t.Run("poll action emits event when version changes", func(t *testing.T) {
		trigger := &OnSecretChange{}
		metadata := &contexts.MetadataContext{
			Metadata: OnSecretChangeMetadata{
				LastKnownVersion: 2,
				LastUpdatedTime:  "2024-01-10T00:00:00Z",
			},
		}
		events := &contexts.EventContext{}
		requests := &contexts.RequestContext{}
		httpCtx := &contexts.HTTPContext{
			Responses: []*http.Response{
				triggerMockResponse(http.StatusOK, `{
					"data": {
						"current_version": 5,
						"updated_time": "2024-01-16T14:20:00Z",
						"created_time": "2024-01-15T10:30:00Z"
					}
				}`),
			},
		}

		_, err := trigger.HandleAction(core.TriggerActionContext{
			Name: OnSecretChangePollAction,
			Configuration: map[string]any{
				"mountPath":       "secret",
				"secretPath":      "myapp/credentials",
				"pollingInterval": "5m",
			},
			Metadata: metadata,
			Events:   events,
			Requests: requests,
			HTTP:     httpCtx,
			Integration: &contexts.IntegrationContext{
				Configuration: map[string]any{
					"baseUrl":    "https://vault.example.com",
					"authMethod": AuthTypeToken,
					"token":      "test-token",
				},
			},
		})

		require.NoError(t, err)

		// Verify event was emitted
		require.Equal(t, 1, events.Count())
		assert.Equal(t, OnSecretChangePayloadType, events.Payloads[0].Type)

		payload, ok := events.Payloads[0].Data.(map[string]any)
		require.True(t, ok)
		assert.Equal(t, "myapp/credentials", payload["secretPath"])
		assert.Equal(t, "secret", payload["mountPath"])
		assert.Equal(t, 2, payload["previousVersion"])
		assert.Equal(t, 5, payload["currentVersion"])

		// Metadata fields are at root level
		assert.Equal(t, "2024-01-15T10:30:00Z", payload["created_time"])
		assert.Equal(t, "2024-01-16T14:20:00Z", payload["updated_time"])

		// Verify metadata was updated
		storedMetadata, ok := metadata.Metadata.(OnSecretChangeMetadata)
		require.True(t, ok)
		assert.Equal(t, 5, storedMetadata.LastKnownVersion)
		assert.Equal(t, "2024-01-16T14:20:00Z", storedMetadata.LastUpdatedTime)

		// Verify polling was rescheduled
		assert.Equal(t, OnSecretChangePollAction, requests.Action)
		assert.Equal(t, 5*time.Minute, requests.Duration)
	})

	t.Run("poll action does not emit event when version unchanged", func(t *testing.T) {
		trigger := &OnSecretChange{}
		metadata := &contexts.MetadataContext{
			Metadata: OnSecretChangeMetadata{
				LastKnownVersion: 5,
				LastUpdatedTime:  "2024-01-16T14:20:00Z",
			},
		}
		events := &contexts.EventContext{}
		requests := &contexts.RequestContext{}
		httpCtx := &contexts.HTTPContext{
			Responses: []*http.Response{
				triggerMockResponse(http.StatusOK, `{
					"data": {
						"current_version": 5,
						"updated_time": "2024-01-16T14:20:00Z",
						"created_time": "2024-01-15T10:30:00Z"
					}
				}`),
			},
		}

		_, err := trigger.HandleAction(core.TriggerActionContext{
			Name: OnSecretChangePollAction,
			Configuration: map[string]any{
				"mountPath":       "secret",
				"secretPath":      "myapp/credentials",
				"pollingInterval": "5m",
			},
			Metadata: metadata,
			Events:   events,
			Requests: requests,
			HTTP:     httpCtx,
			Integration: &contexts.IntegrationContext{
				Configuration: map[string]any{
					"baseUrl":    "https://vault.example.com",
					"authMethod": AuthTypeToken,
					"token":      "test-token",
				},
			},
		})

		require.NoError(t, err)

		// No event should be emitted
		assert.Equal(t, 0, events.Count())

		// Polling should still be rescheduled
		assert.Equal(t, OnSecretChangePollAction, requests.Action)
	})

	t.Run("poll action continues polling on Vault error", func(t *testing.T) {
		trigger := &OnSecretChange{}
		metadata := &contexts.MetadataContext{
			Metadata: OnSecretChangeMetadata{
				LastKnownVersion: 2,
			},
		}
		events := &contexts.EventContext{}
		requests := &contexts.RequestContext{}
		httpCtx := &contexts.HTTPContext{
			Responses: []*http.Response{
				triggerMockResponse(http.StatusInternalServerError, `{"errors": ["internal error"]}`),
			},
		}

		_, err := trigger.HandleAction(core.TriggerActionContext{
			Name: OnSecretChangePollAction,
			Configuration: map[string]any{
				"mountPath":       "secret",
				"secretPath":      "myapp/credentials",
				"pollingInterval": "15m",
			},
			Metadata: metadata,
			Events:   events,
			Requests: requests,
			HTTP:     httpCtx,
			Integration: &contexts.IntegrationContext{
				Configuration: map[string]any{
					"baseUrl":    "https://vault.example.com",
					"authMethod": AuthTypeToken,
					"token":      "test-token",
				},
			},
		})

		require.NoError(t, err)

		// No event should be emitted
		assert.Equal(t, 0, events.Count())

		// Polling should be rescheduled even on error
		assert.Equal(t, OnSecretChangePollAction, requests.Action)
		assert.Equal(t, 15*time.Minute, requests.Duration)
	})

	t.Run("poll action requires metadata context", func(t *testing.T) {
		trigger := &OnSecretChange{}

		_, err := trigger.HandleAction(core.TriggerActionContext{
			Name: OnSecretChangePollAction,
			Configuration: map[string]any{
				"mountPath":       "secret",
				"secretPath":      "myapp/credentials",
				"pollingInterval": "5m",
			},
			Metadata: nil,
		})

		require.Error(t, err)
		assert.Contains(t, err.Error(), "missing metadata context")
	})

	t.Run("poll action with different intervals", func(t *testing.T) {
		testCases := []struct {
			interval string
			expected time.Duration
		}{
			{"1m", 1 * time.Minute},
			{"5m", 5 * time.Minute},
			{"15m", 15 * time.Minute},
			{"30m", 30 * time.Minute},
			{"1h", 1 * time.Hour},
		}

		for _, tc := range testCases {
			t.Run(tc.interval, func(t *testing.T) {
				trigger := &OnSecretChange{}
				metadata := &contexts.MetadataContext{
					Metadata: OnSecretChangeMetadata{LastKnownVersion: 1},
				}
				requests := &contexts.RequestContext{}
				httpCtx := &contexts.HTTPContext{
					Responses: []*http.Response{
						triggerMockResponse(http.StatusOK, `{"data": {"current_version": 1}}`),
					},
				}

				_, err := trigger.HandleAction(core.TriggerActionContext{
					Name: OnSecretChangePollAction,
					Configuration: map[string]any{
						"mountPath":       "secret",
						"secretPath":      "myapp/credentials",
						"pollingInterval": tc.interval,
					},
					Metadata: metadata,
					Events:   &contexts.EventContext{},
					Requests: requests,
					HTTP:     httpCtx,
					Integration: &contexts.IntegrationContext{
						Configuration: map[string]any{
							"baseUrl":    "https://vault.example.com",
							"authMethod": AuthTypeToken,
							"token":      "test-token",
						},
					},
				})

				require.NoError(t, err)
				assert.Equal(t, tc.expected, requests.Duration)
			})
		}
	})
}

func Test__OnSecretChange__HandleWebhook(t *testing.T) {
	trigger := &OnSecretChange{}
	status, body, err := trigger.HandleWebhook(core.WebhookRequestContext{})

	assert.NoError(t, err)
	assert.Equal(t, http.StatusNotFound, status)
	assert.Nil(t, body)
}

func Test__OnSecretChange__Cleanup(t *testing.T) {
	trigger := &OnSecretChange{}
	err := trigger.Cleanup(core.TriggerContext{})
	assert.NoError(t, err)
}

func Test__decodeOnSecretChangeConfiguration(t *testing.T) {
	t.Run("decodes valid configuration", func(t *testing.T) {
		config, err := decodeOnSecretChangeConfiguration(map[string]any{
			"mountPath":       "secret",
			"secretPath":      "myapp/credentials",
			"pollingInterval": "15m",
		})

		require.NoError(t, err)
		assert.Equal(t, "secret", config.MountPath)
		assert.Equal(t, "myapp/credentials", config.SecretPath)
		assert.Equal(t, "15m", config.PollingInterval)
	})

	t.Run("trims whitespace", func(t *testing.T) {
		config, err := decodeOnSecretChangeConfiguration(map[string]any{
			"mountPath":       "  secret  ",
			"secretPath":      "  myapp/credentials  ",
			"pollingInterval": "  5m  ",
		})

		require.NoError(t, err)
		assert.Equal(t, "secret", config.MountPath)
		assert.Equal(t, "myapp/credentials", config.SecretPath)
		assert.Equal(t, "5m", config.PollingInterval)
	})

	t.Run("defaults polling interval to 5m", func(t *testing.T) {
		config, err := decodeOnSecretChangeConfiguration(map[string]any{
			"mountPath":  "secret",
			"secretPath": "myapp/credentials",
		})

		require.NoError(t, err)
		assert.Equal(t, "5m", config.PollingInterval)
	})

	t.Run("rejects empty mountPath", func(t *testing.T) {
		_, err := decodeOnSecretChangeConfiguration(map[string]any{
			"mountPath":       "",
			"secretPath":      "myapp/credentials",
			"pollingInterval": "5m",
		})

		require.Error(t, err)
		assert.Contains(t, err.Error(), "mountPath is required")
	})

	t.Run("rejects empty secretPath", func(t *testing.T) {
		_, err := decodeOnSecretChangeConfiguration(map[string]any{
			"mountPath":       "secret",
			"secretPath":      "",
			"pollingInterval": "5m",
		})

		require.Error(t, err)
		assert.Contains(t, err.Error(), "secretPath is required")
	})

	t.Run("rejects invalid polling interval", func(t *testing.T) {
		_, err := decodeOnSecretChangeConfiguration(map[string]any{
			"mountPath":       "secret",
			"secretPath":      "myapp/credentials",
			"pollingInterval": "10m",
		})

		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid pollingInterval")
	})
}

func Test__decodeOnSecretChangeMetadata(t *testing.T) {
	t.Run("decodes valid metadata", func(t *testing.T) {
		metadata, err := decodeOnSecretChangeMetadata(map[string]any{
			"lastKnownVersion": 5,
			"lastUpdatedTime":  "2024-01-16T14:20:00Z",
		})

		require.NoError(t, err)
		assert.Equal(t, 5, metadata.LastKnownVersion)
		assert.Equal(t, "2024-01-16T14:20:00Z", metadata.LastUpdatedTime)
	})

	t.Run("handles nil input", func(t *testing.T) {
		metadata, err := decodeOnSecretChangeMetadata(nil)

		require.NoError(t, err)
		assert.Equal(t, 0, metadata.LastKnownVersion)
		assert.Equal(t, "", metadata.LastUpdatedTime)
	})

	t.Run("handles empty map", func(t *testing.T) {
		metadata, err := decodeOnSecretChangeMetadata(map[string]any{})

		require.NoError(t, err)
		assert.Equal(t, 0, metadata.LastKnownVersion)
		assert.Equal(t, "", metadata.LastUpdatedTime)
	})
}

func Test__getPollingInterval(t *testing.T) {
	tests := []struct {
		input    string
		expected time.Duration
	}{
		{"1m", 1 * time.Minute},
		{"5m", 5 * time.Minute},
		{"15m", 15 * time.Minute},
		{"30m", 30 * time.Minute},
		{"1h", 1 * time.Hour},
		{"invalid", 5 * time.Minute},
		{"", 5 * time.Minute},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			result := getPollingInterval(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}

// triggerMockResponse creates a mock HTTP response with the given status and body
func triggerMockResponse(statusCode int, body string) *http.Response {
	return &http.Response{
		StatusCode: statusCode,
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}
