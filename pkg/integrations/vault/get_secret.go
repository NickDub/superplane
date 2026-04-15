package vault

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/mitchellh/mapstructure"
	"github.com/superplanehq/superplane/pkg/configuration"
	"github.com/superplanehq/superplane/pkg/core"
)

// GetSecret retrieves a secret from HashiCorp Vault KV v2 engine
type GetSecret struct{}

// GetSecretConfiguration holds the configuration for the GetSecret component
type GetSecretConfiguration struct {
	MountPath  string `json:"mountPath" mapstructure:"mountPath"`
	SecretPath string `json:"secretPath" mapstructure:"secretPath"`
}

// GetSecretNodeMetadata stores node metadata for the UI
type GetSecretNodeMetadata struct {
	MountPath  string `json:"mountPath,omitempty" mapstructure:"mountPath"`
	SecretPath string `json:"secretPath,omitempty" mapstructure:"secretPath"`
}

func (c *GetSecret) Name() string {
	return "vault.getSecret"
}

func (c *GetSecret) Label() string {
	return "Get Secret"
}

func (c *GetSecret) Description() string {
	return "Retrieve a secret from HashiCorp Vault KV v2 engine"
}

func (c *GetSecret) Documentation() string {
	return `The Get Secret component retrieves a secret from HashiCorp Vault's KV v2 secrets engine.

## Use Cases

- **Retrieve credentials**: Fetch database credentials, API keys, or other secrets for downstream components
- **Dynamic secrets access**: Use expressions to dynamically specify which secret to retrieve
- **Secret versioning**: Access the latest version of secrets with metadata

## Configuration

- **Mount Path**: The mount path of the KV v2 secrets engine (default: "secret")
- **Secret Path**: The path to the secret within the secrets engine (supports expressions)

## Output

Returns the secret data and metadata including version information:
- **data**: The key-value pairs stored in the secret
- **metadata**: Version number and creation timestamp

## Notes

- The Vault token or AppRole must have read permission for the specified secret path
- Only supports KV v2 (versioned) secrets engine
- Secret data is emitted as-is - handle sensitive values carefully in downstream components`
}

func (c *GetSecret) Icon() string {
	return "key"
}

func (c *GetSecret) Color() string {
	return "yellow"
}

func (c *GetSecret) ExampleOutput() map[string]any {
	return nil
}

func (c *GetSecret) OutputChannels(configuration any) []core.OutputChannel {
	return []core.OutputChannel{core.DefaultOutputChannel}
}

func (c *GetSecret) Configuration() []configuration.Field {
	return []configuration.Field{
		{
			Name:        "mountPath",
			Label:       "Mount Path",
			Type:        configuration.FieldTypeString,
			Required:    true,
			Default:     "secret",
			Description: "KV v2 engine mount path",
		},
		{
			Name:        "secretPath",
			Label:       "Secret Path",
			Type:        configuration.FieldTypeExpression,
			Required:    true,
			Description: "Path to the secret",
		},
	}
}

func (c *GetSecret) Setup(ctx core.SetupContext) error {
	config, err := decodeGetSecretConfiguration(ctx.Configuration)
	if err != nil {
		return fmt.Errorf("failed to decode configuration: %w", err)
	}

	if config.MountPath == "" {
		return fmt.Errorf("mountPath is required")
	}

	if config.SecretPath == "" {
		return fmt.Errorf("secretPath is required")
	}

	// Store metadata for UI display
	return ctx.Metadata.Set(GetSecretNodeMetadata{
		MountPath:  config.MountPath,
		SecretPath: config.SecretPath,
	})
}

func (c *GetSecret) ProcessQueueItem(ctx core.ProcessQueueContext) (*uuid.UUID, error) {
	return ctx.DefaultProcessing()
}

func (c *GetSecret) Execute(ctx core.ExecutionContext) error {
	config, err := decodeGetSecretConfiguration(ctx.Configuration)
	if err != nil {
		return fmt.Errorf("failed to decode configuration: %w", err)
	}

	if config.MountPath == "" {
		return fmt.Errorf("mountPath is required")
	}

	if config.SecretPath == "" {
		return fmt.Errorf("secretPath is required")
	}

	client, err := NewClient(ctx.HTTP, ctx.Integration)
	if err != nil {
		return fmt.Errorf("failed to create Vault client: %w", err)
	}

	secretResp, err := client.ReadSecret(config.MountPath, config.SecretPath)
	if err != nil {
		return fmt.Errorf("failed to read secret: %w", err)
	}

	return ctx.ExecutionState.Emit(
		core.DefaultOutputChannel.Name,
		"vault.secret.retrieved",
		[]any{secretResp},
	)
}

func (c *GetSecret) Actions() []core.Action {
	return []core.Action{}
}

func (c *GetSecret) HandleAction(ctx core.ActionContext) error {
	return nil
}

func (c *GetSecret) HandleWebhook(ctx core.WebhookRequestContext) (int, *core.WebhookResponseBody, error) {
	return http.StatusOK, nil, nil
}

func (c *GetSecret) Cancel(ctx core.ExecutionContext) error {
	return nil
}

func (c *GetSecret) Cleanup(ctx core.SetupContext) error {
	return nil
}

func decodeGetSecretConfiguration(input any) (GetSecretConfiguration, error) {
	config := GetSecretConfiguration{}
	if err := mapstructure.Decode(input, &config); err != nil {
		return GetSecretConfiguration{}, err
	}

	config.MountPath = strings.TrimSpace(config.MountPath)
	config.SecretPath = strings.TrimSpace(config.SecretPath)
	return config, nil
}
