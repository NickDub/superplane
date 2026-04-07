package vault

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/superplanehq/superplane/pkg/configuration"
	"github.com/superplanehq/superplane/pkg/core"
	"github.com/superplanehq/superplane/test/support/contexts"
)

func Test__GetSecret__Name(t *testing.T) {
	component := &GetSecret{}
	assert.Equal(t, "vault.getSecret", component.Name())
}

func Test__GetSecret__Label(t *testing.T) {
	component := &GetSecret{}
	assert.Equal(t, "Get Secret", component.Label())
}

func Test__GetSecret__Description(t *testing.T) {
	component := &GetSecret{}
	assert.Equal(t, "Retrieve a secret from HashiCorp Vault KV v2 engine", component.Description())
}

func Test__GetSecret__Icon(t *testing.T) {
	component := &GetSecret{}
	assert.Equal(t, "key", component.Icon())
}

func Test__GetSecret__Color(t *testing.T) {
	component := &GetSecret{}
	assert.Equal(t, "yellow", component.Color())
}

func Test__GetSecret__OutputChannels(t *testing.T) {
	component := &GetSecret{}
	channels := component.OutputChannels(nil)
	require.Len(t, channels, 1)
	assert.Equal(t, core.DefaultOutputChannel, channels[0])
}

func Test__GetSecret__Configuration(t *testing.T) {
	component := &GetSecret{}
	fields := component.Configuration()

	require.Len(t, fields, 2)

	t.Run("mountPath field", func(t *testing.T) {
		field := findField(fields, "mountPath")
		require.NotNil(t, field)
		assert.Equal(t, "Mount Path", field.Label)
		assert.Equal(t, configuration.FieldTypeString, field.Type)
		assert.True(t, field.Required)
		assert.Equal(t, "secret", field.Default)
	})

	t.Run("secretPath field", func(t *testing.T) {
		field := findField(fields, "secretPath")
		require.NotNil(t, field)
		assert.Equal(t, "Secret Path", field.Label)
		assert.Equal(t, configuration.FieldTypeExpression, field.Type)
		assert.True(t, field.Required)
	})
}

func Test__GetSecret__Setup(t *testing.T) {
	t.Run("validates mountPath is required", func(t *testing.T) {
		component := &GetSecret{}
		metadata := &contexts.MetadataContext{}

		err := component.Setup(core.SetupContext{
			Configuration: map[string]any{
				"mountPath":  "",
				"secretPath": "myapp/credentials",
			},
			Metadata: metadata,
		})

		require.Error(t, err)
		assert.Contains(t, err.Error(), "mountPath is required")
	})

	t.Run("validates secretPath is required", func(t *testing.T) {
		component := &GetSecret{}
		metadata := &contexts.MetadataContext{}

		err := component.Setup(core.SetupContext{
			Configuration: map[string]any{
				"mountPath":  "secret",
				"secretPath": "",
			},
			Metadata: metadata,
		})

		require.Error(t, err)
		assert.Contains(t, err.Error(), "secretPath is required")
	})

	t.Run("stores metadata on successful setup", func(t *testing.T) {
		component := &GetSecret{}
		metadata := &contexts.MetadataContext{}

		err := component.Setup(core.SetupContext{
			Configuration: map[string]any{
				"mountPath":  "secret",
				"secretPath": "myapp/credentials",
			},
			Metadata: metadata,
		})

		require.NoError(t, err)
		assert.Equal(t, GetSecretNodeMetadata{
			MountPath:  "secret",
			SecretPath: "myapp/credentials",
		}, metadata.Metadata)
	})

	t.Run("trims whitespace from configuration values", func(t *testing.T) {
		component := &GetSecret{}
		metadata := &contexts.MetadataContext{}

		err := component.Setup(core.SetupContext{
			Configuration: map[string]any{
				"mountPath":  "  secret  ",
				"secretPath": "  myapp/credentials  ",
			},
			Metadata: metadata,
		})

		require.NoError(t, err)
		assert.Equal(t, GetSecretNodeMetadata{
			MountPath:  "secret",
			SecretPath: "myapp/credentials",
		}, metadata.Metadata)
	})
}

func Test__GetSecret__Execute(t *testing.T) {
	t.Run("retrieves secret and emits payload", func(t *testing.T) {
		component := &GetSecret{}
		httpCtx := &contexts.HTTPContext{
			Responses: []*http.Response{
				vaultMockResponse(http.StatusOK, `{
					"data": {
						"data": {"username": "admin", "password": "s3cr3t"},
						"metadata": {"version": 3, "created_time": "2024-01-15T10:30:00Z"}
					}
				}`),
			},
		}
		executionState := &contexts.ExecutionStateContext{}

		err := component.Execute(core.ExecutionContext{
			Configuration: map[string]any{
				"mountPath":  "secret",
				"secretPath": "myapp/credentials",
			},
			HTTP: httpCtx,
			Integration: &contexts.IntegrationContext{
				Configuration: map[string]any{
					"baseUrl":    "https://vault.example.com",
					"authMethod": AuthTypeToken,
					"token":      "test-token",
				},
			},
			ExecutionState: executionState,
		})

		require.NoError(t, err)
		assert.True(t, executionState.Passed)
		assert.Equal(t, "vault.secret.retrieved", executionState.Type)
		assert.Equal(t, "default", executionState.Channel)
		require.Len(t, executionState.Payloads, 1)

		payload, ok := executionState.Payloads[0].(map[string]any)
		require.True(t, ok)
		output, ok := payload["data"].(*SecretResponse)
		require.True(t, ok)
		assert.Equal(t, map[string]any{"username": "admin", "password": "s3cr3t"}, output.Data)
		assert.Equal(t, 3, output.Metadata.Version)
		assert.Equal(t, "2024-01-15T10:30:00Z", output.Metadata.CreatedTime)
	})

	t.Run("returns error when mountPath is empty", func(t *testing.T) {
		component := &GetSecret{}

		err := component.Execute(core.ExecutionContext{
			Configuration: map[string]any{
				"mountPath":  "",
				"secretPath": "myapp/credentials",
			},
		})

		require.Error(t, err)
		assert.Contains(t, err.Error(), "mountPath is required")
	})

	t.Run("returns error when secretPath is empty", func(t *testing.T) {
		component := &GetSecret{}

		err := component.Execute(core.ExecutionContext{
			Configuration: map[string]any{
				"mountPath":  "secret",
				"secretPath": "",
			},
		})

		require.Error(t, err)
		assert.Contains(t, err.Error(), "secretPath is required")
	})

	t.Run("returns error when client creation fails", func(t *testing.T) {
		component := &GetSecret{}

		err := component.Execute(core.ExecutionContext{
			Configuration: map[string]any{
				"mountPath":  "secret",
				"secretPath": "myapp/credentials",
			},
			HTTP: &contexts.HTTPContext{},
			Integration: &contexts.IntegrationContext{
				Configuration: map[string]any{
					// Missing required fields
				},
			},
		})

		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to create Vault client")
	})

	t.Run("returns error when secret not found", func(t *testing.T) {
		component := &GetSecret{}
		httpCtx := &contexts.HTTPContext{
			Responses: []*http.Response{
				vaultMockResponse(http.StatusNotFound, `{"errors": ["secret not found"]}`),
			},
		}

		err := component.Execute(core.ExecutionContext{
			Configuration: map[string]any{
				"mountPath":  "secret",
				"secretPath": "nonexistent/path",
			},
			HTTP: httpCtx,
			Integration: &contexts.IntegrationContext{
				Configuration: map[string]any{
					"baseUrl":    "https://vault.example.com",
					"authMethod": AuthTypeToken,
					"token":      "test-token",
				},
			},
			ExecutionState: &contexts.ExecutionStateContext{},
		})

		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to read secret")
		assert.Contains(t, err.Error(), "secret not found")
	})

	t.Run("returns error when permission denied", func(t *testing.T) {
		component := &GetSecret{}
		httpCtx := &contexts.HTTPContext{
			Responses: []*http.Response{
				vaultMockResponse(http.StatusForbidden, `{"errors": ["permission denied"]}`),
			},
		}

		err := component.Execute(core.ExecutionContext{
			Configuration: map[string]any{
				"mountPath":  "secret",
				"secretPath": "restricted/path",
			},
			HTTP: httpCtx,
			Integration: &contexts.IntegrationContext{
				Configuration: map[string]any{
					"baseUrl":    "https://vault.example.com",
					"authMethod": AuthTypeToken,
					"token":      "test-token",
				},
			},
			ExecutionState: &contexts.ExecutionStateContext{},
		})

		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to read secret")
		assert.Contains(t, err.Error(), "permission denied")
	})
}

func Test__GetSecret__Actions(t *testing.T) {
	component := &GetSecret{}
	assert.Empty(t, component.Actions())
}

func Test__GetSecret__HandleAction(t *testing.T) {
	component := &GetSecret{}
	err := component.HandleAction(core.ActionContext{})
	assert.NoError(t, err)
}

func Test__GetSecret__HandleWebhook(t *testing.T) {
	component := &GetSecret{}
	status, body, err := component.HandleWebhook(core.WebhookRequestContext{})
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, status)
	assert.Nil(t, body)
}

func Test__GetSecret__Cancel(t *testing.T) {
	component := &GetSecret{}
	err := component.Cancel(core.ExecutionContext{})
	assert.NoError(t, err)
}

func Test__GetSecret__Cleanup(t *testing.T) {
	component := &GetSecret{}
	err := component.Cleanup(core.SetupContext{})
	assert.NoError(t, err)
}

func Test__GetSecret__ExampleOutput(t *testing.T) {
	component := &GetSecret{}
	assert.Nil(t, component.ExampleOutput())
}

// vaultMockResponse creates a mock HTTP response with the given status and body
func vaultMockResponse(statusCode int, body string) *http.Response {
	return &http.Response{
		StatusCode: statusCode,
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}
