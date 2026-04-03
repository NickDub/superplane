package vault

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/superplanehq/superplane/pkg/configuration"
	"github.com/superplanehq/superplane/pkg/core"
	"github.com/superplanehq/superplane/test/support/contexts"
)

func Test__Vault__Name(t *testing.T) {
	v := &Vault{}
	assert.Equal(t, "vault", v.Name())
}

func Test__Vault__Label(t *testing.T) {
	v := &Vault{}
	assert.Equal(t, "HashiCorp Vault", v.Label())
}

func Test__Vault__Icon(t *testing.T) {
	v := &Vault{}
	assert.Equal(t, "vault", v.Icon())
}

func Test__Vault__Description(t *testing.T) {
	v := &Vault{}
	assert.Equal(t, "Retrieve secrets from HashiCorp Vault KV v2 engine", v.Description())
}

func Test__Vault__Instructions(t *testing.T) {
	v := &Vault{}
	instructions := v.Instructions()
	assert.Contains(t, instructions, "Token authentication")
	assert.Contains(t, instructions, "AppRole authentication")
}

func Test__Vault__Configuration(t *testing.T) {
	v := &Vault{}
	fields := v.Configuration()

	t.Run("returns all required fields", func(t *testing.T) {
		fieldNames := make([]string, len(fields))
		for i, f := range fields {
			fieldNames[i] = f.Name
		}
		assert.Contains(t, fieldNames, "baseUrl")
		assert.Contains(t, fieldNames, "namespace")
		assert.Contains(t, fieldNames, "authMethod")
		assert.Contains(t, fieldNames, "token")
		assert.Contains(t, fieldNames, "roleId")
		assert.Contains(t, fieldNames, "secretId")
		assert.Contains(t, fieldNames, "approleMountPath")
	})

	t.Run("baseUrl field is required and not sensitive", func(t *testing.T) {
		field := findField(fields, "baseUrl")
		require.NotNil(t, field)
		assert.Equal(t, configuration.FieldTypeString, field.Type)
		assert.True(t, field.Required)
		assert.False(t, field.Sensitive)
	})

	t.Run("namespace field is not required", func(t *testing.T) {
		field := findField(fields, "namespace")
		require.NotNil(t, field)
		assert.Equal(t, configuration.FieldTypeString, field.Type)
		assert.False(t, field.Required)
		assert.False(t, field.Sensitive)
	})

	t.Run("authMethod field is select type with options", func(t *testing.T) {
		field := findField(fields, "authMethod")
		require.NotNil(t, field)
		assert.Equal(t, configuration.FieldTypeSelect, field.Type)
		assert.True(t, field.Required)
		assert.False(t, field.Sensitive)
		require.NotNil(t, field.TypeOptions)
		require.NotNil(t, field.TypeOptions.Select)
		assert.Len(t, field.TypeOptions.Select.Options, 2)

		values := make([]string, len(field.TypeOptions.Select.Options))
		for i, opt := range field.TypeOptions.Select.Options {
			values[i] = opt.Value
		}
		assert.Contains(t, values, AuthTypeToken)
		assert.Contains(t, values, AuthTypeAppRole)
	})

	t.Run("token field is sensitive with visibility condition", func(t *testing.T) {
		field := findField(fields, "token")
		require.NotNil(t, field)
		assert.Equal(t, configuration.FieldTypeString, field.Type)
		assert.True(t, field.Sensitive)
		assert.False(t, field.Required) // Not globally required

		// Check visibility condition
		require.Len(t, field.VisibilityConditions, 1)
		assert.Equal(t, "authMethod", field.VisibilityConditions[0].Field)
		assert.Contains(t, field.VisibilityConditions[0].Values, AuthTypeToken)

		// Check required condition
		require.Len(t, field.RequiredConditions, 1)
		assert.Equal(t, "authMethod", field.RequiredConditions[0].Field)
		assert.Contains(t, field.RequiredConditions[0].Values, AuthTypeToken)
	})

	t.Run("roleId field has visibility condition for approle", func(t *testing.T) {
		field := findField(fields, "roleId")
		require.NotNil(t, field)
		assert.Equal(t, configuration.FieldTypeString, field.Type)
		assert.False(t, field.Sensitive)
		assert.False(t, field.Required)

		require.Len(t, field.VisibilityConditions, 1)
		assert.Equal(t, "authMethod", field.VisibilityConditions[0].Field)
		assert.Contains(t, field.VisibilityConditions[0].Values, AuthTypeAppRole)

		require.Len(t, field.RequiredConditions, 1)
		assert.Equal(t, "authMethod", field.RequiredConditions[0].Field)
		assert.Contains(t, field.RequiredConditions[0].Values, AuthTypeAppRole)
	})

	t.Run("secretId field is sensitive with visibility condition for approle", func(t *testing.T) {
		field := findField(fields, "secretId")
		require.NotNil(t, field)
		assert.Equal(t, configuration.FieldTypeString, field.Type)
		assert.True(t, field.Sensitive)
		assert.False(t, field.Required)

		require.Len(t, field.VisibilityConditions, 1)
		assert.Equal(t, "authMethod", field.VisibilityConditions[0].Field)
		assert.Contains(t, field.VisibilityConditions[0].Values, AuthTypeAppRole)

		require.Len(t, field.RequiredConditions, 1)
		assert.Equal(t, "authMethod", field.RequiredConditions[0].Field)
		assert.Contains(t, field.RequiredConditions[0].Values, AuthTypeAppRole)
	})

	t.Run("approleMountPath field has default and visibility condition", func(t *testing.T) {
		field := findField(fields, "approleMountPath")
		require.NotNil(t, field)
		assert.Equal(t, configuration.FieldTypeString, field.Type)
		assert.False(t, field.Sensitive)
		assert.False(t, field.Required)
		assert.Equal(t, "approle", field.Default)

		require.Len(t, field.VisibilityConditions, 1)
		assert.Equal(t, "authMethod", field.VisibilityConditions[0].Field)
		assert.Contains(t, field.VisibilityConditions[0].Values, AuthTypeAppRole)
	})
}

func Test__Vault__Components(t *testing.T) {
	v := &Vault{}
	components := v.Components()
	require.Len(t, components, 1)
	assert.Equal(t, "vault.getSecret", components[0].Name())
}

func Test__Vault__Triggers(t *testing.T) {
	v := &Vault{}
	triggers := v.Triggers()
	require.Len(t, triggers, 1)
	assert.Equal(t, "vault.onSecretChange", triggers[0].Name())
}

func Test__Vault__Actions(t *testing.T) {
	v := &Vault{}
	assert.Empty(t, v.Actions())
}

func Test__Vault__HandleAction(t *testing.T) {
	v := &Vault{}
	err := v.HandleAction(core.IntegrationActionContext{})
	assert.NoError(t, err)
}

func Test__Vault__ListResources(t *testing.T) {
	v := &Vault{}
	resources, err := v.ListResources("any", core.ListResourcesContext{})
	assert.NoError(t, err)
	assert.Nil(t, resources)
}

func Test__Vault__HandleRequest(t *testing.T) {
	v := &Vault{}
	recorder := httptest.NewRecorder()

	v.HandleRequest(core.HTTPRequestContext{
		Response: recorder,
	})

	assert.Equal(t, http.StatusNotFound, recorder.Code)
}

func Test__Vault__Cleanup(t *testing.T) {
	v := &Vault{}
	err := v.Cleanup(core.IntegrationCleanupContext{})
	assert.NoError(t, err)
}

func Test__Vault__Sync(t *testing.T) {
	v := &Vault{}

	t.Run("skips when already verified", func(t *testing.T) {
		integrationCtx := &contexts.IntegrationContext{
			Metadata: map[string]any{"verified": true},
		}

		err := v.Sync(core.SyncContext{
			Logger:      logrus.NewEntry(logrus.New()),
			Integration: integrationCtx,
		})

		require.NoError(t, err)
		// State should not change
		assert.Empty(t, integrationCtx.State)
	})

	t.Run("sets error state when client creation fails", func(t *testing.T) {
		integrationCtx := &contexts.IntegrationContext{
			Configuration: map[string]any{
				// Missing required fields
			},
		}

		err := v.Sync(core.SyncContext{
			Logger:      logrus.NewEntry(logrus.New()),
			HTTP:        &contexts.HTTPContext{},
			Integration: integrationCtx,
		})

		require.NoError(t, err)
		assert.Equal(t, "error", integrationCtx.State)
		assert.Contains(t, integrationCtx.StateDescription, "baseUrl is required")
	})

	t.Run("sets error state when connection test fails", func(t *testing.T) {
		httpCtx := &contexts.HTTPContext{
			Responses: []*http.Response{
				{
					StatusCode: http.StatusForbidden,
					Body:       io.NopCloser(strings.NewReader(`{"errors": ["permission denied"]}`)),
				},
			},
		}

		integrationCtx := &contexts.IntegrationContext{
			Configuration: map[string]any{
				"baseUrl":    "https://vault.example.com",
				"authMethod": AuthTypeToken,
				"token":      "invalid-token",
			},
		}

		err := v.Sync(core.SyncContext{
			Logger:      logrus.NewEntry(logrus.New()),
			HTTP:        httpCtx,
			Integration: integrationCtx,
		})

		require.NoError(t, err)
		assert.Equal(t, "error", integrationCtx.State)
		assert.Contains(t, integrationCtx.StateDescription, "Failed to connect to Vault")
	})

	t.Run("sets ready state when connection succeeds with token auth", func(t *testing.T) {
		httpCtx := &contexts.HTTPContext{
			Responses: []*http.Response{
				{
					StatusCode: http.StatusOK,
					Body: io.NopCloser(strings.NewReader(`{
						"data": {
							"accessor": "token-accessor",
							"policies": ["default"]
						}
					}`)),
				},
			},
		}

		integrationCtx := &contexts.IntegrationContext{
			Configuration: map[string]any{
				"baseUrl":    "https://vault.example.com",
				"authMethod": AuthTypeToken,
				"token":      "valid-token",
			},
		}

		err := v.Sync(core.SyncContext{
			Logger:      logrus.NewEntry(logrus.New()),
			HTTP:        httpCtx,
			Integration: integrationCtx,
		})

		require.NoError(t, err)
		assert.Equal(t, "ready", integrationCtx.State)

		// Verify metadata was set
		metadata, ok := integrationCtx.Metadata.(Metadata)
		require.True(t, ok)
		assert.True(t, metadata.Verified)

		// Verify the request was made to lookup-self
		require.Len(t, httpCtx.Requests, 1)
		assert.Contains(t, httpCtx.Requests[0].URL.String(), "/v1/auth/token/lookup-self")
	})

	t.Run("sets ready state when connection succeeds with approle auth", func(t *testing.T) {
		httpCtx := &contexts.HTTPContext{
			Responses: []*http.Response{
				// AppRole login response
				{
					StatusCode: http.StatusOK,
					Body: io.NopCloser(strings.NewReader(`{
						"auth": {
							"client_token": "approle-client-token"
						}
					}`)),
				},
				// Token lookup-self response
				{
					StatusCode: http.StatusOK,
					Body: io.NopCloser(strings.NewReader(`{
						"data": {
							"accessor": "token-accessor",
							"policies": ["default"]
						}
					}`)),
				},
			},
		}

		integrationCtx := &contexts.IntegrationContext{
			Configuration: map[string]any{
				"baseUrl":    "https://vault.example.com",
				"authMethod": AuthTypeAppRole,
				"roleId":     "test-role-id",
				"secretId":   "test-secret-id",
			},
		}

		err := v.Sync(core.SyncContext{
			Logger:      logrus.NewEntry(logrus.New()),
			HTTP:        httpCtx,
			Integration: integrationCtx,
		})

		require.NoError(t, err)
		assert.Equal(t, "ready", integrationCtx.State)

		metadata, ok := integrationCtx.Metadata.(Metadata)
		require.True(t, ok)
		assert.True(t, metadata.Verified)

		// Verify both requests were made (AppRole login + lookup-self)
		require.Len(t, httpCtx.Requests, 2)
		assert.Contains(t, httpCtx.Requests[0].URL.String(), "/v1/auth/approle/login")
		assert.Contains(t, httpCtx.Requests[1].URL.String(), "/v1/auth/token/lookup-self")
	})

	t.Run("uses namespace when configured", func(t *testing.T) {
		httpCtx := &contexts.HTTPContext{
			Responses: []*http.Response{
				{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader(`{"data": {}}`)),
				},
			},
		}

		integrationCtx := &contexts.IntegrationContext{
			Configuration: map[string]any{
				"baseUrl":    "https://vault.example.com",
				"authMethod": AuthTypeToken,
				"token":      "valid-token",
				"namespace":  "admin/team-a",
			},
		}

		err := v.Sync(core.SyncContext{
			Logger:      logrus.NewEntry(logrus.New()),
			HTTP:        httpCtx,
			Integration: integrationCtx,
		})

		require.NoError(t, err)
		require.Len(t, httpCtx.Requests, 1)
		assert.Equal(t, "admin/team-a", httpCtx.Requests[0].Header.Get("X-Vault-Namespace"))
	})
}

// findField is a helper to find a field by name
func findField(fields []configuration.Field, name string) *configuration.Field {
	for i := range fields {
		if fields[i].Name == name {
			return &fields[i]
		}
	}
	return nil
}
