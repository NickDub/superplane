package vault

import (
	"fmt"
	"net/http"

	"github.com/mitchellh/mapstructure"
	"github.com/superplanehq/superplane/pkg/configuration"
	"github.com/superplanehq/superplane/pkg/core"
	"github.com/superplanehq/superplane/pkg/registry"
)

func init() {
	registry.RegisterIntegration("vault", &Vault{})
}

// Vault implements the HashiCorp Vault integration
type Vault struct{}

// Metadata contains the state of the Vault integration
type Metadata struct {
	Verified bool `mapstructure:"verified" json:"verified"`
}

func (v *Vault) Name() string {
	return "vault"
}

func (v *Vault) Label() string {
	return "HashiCorp Vault"
}

func (v *Vault) Icon() string {
	return "vault"
}

func (v *Vault) Description() string {
	return "Retrieve secrets from HashiCorp Vault KV v2 engine"
}

func (v *Vault) Instructions() string {
	return `
Configure your Vault connection using either:
- **Token authentication**: Provide a Vault token directly
- **AppRole authentication**: Provide RoleID and SecretID for machine-based authentication

The token or AppRole credentials must have permission to read secrets from the KV v2 secrets engine.
`
}

func (v *Vault) Configuration() []configuration.Field {
	return []configuration.Field{
		{
			Name:        "baseUrl",
			Label:       "Base URL",
			Type:        configuration.FieldTypeString,
			Description: "Vault server URL (e.g., https://vault.example.com)",
			Required:    true,
			Sensitive:   false,
		},
		{
			Name:        "namespace",
			Label:       "Namespace",
			Type:        configuration.FieldTypeString,
			Description: "Vault namespace (for Vault Enterprise)",
			Required:    false,
			Sensitive:   false,
		},
		{
			Name:        "authMethod",
			Label:       "Authentication Method",
			Type:        configuration.FieldTypeSelect,
			Description: "How to authenticate with Vault",
			Required:    true,
			Sensitive:   false,
			TypeOptions: &configuration.TypeOptions{
				Select: &configuration.SelectTypeOptions{
					Options: []configuration.FieldOption{
						{Label: "Token", Value: AuthTypeToken},
						{Label: "AppRole", Value: AuthTypeAppRole},
					},
				},
			},
		},
		{
			Name:        "token",
			Label:       "Token",
			Type:        configuration.FieldTypeString,
			Description: "Vault authentication token",
			Required:    false,
			Sensitive:   true,
			VisibilityConditions: []configuration.VisibilityCondition{
				{Field: "authMethod", Values: []string{AuthTypeToken}},
			},
			RequiredConditions: []configuration.RequiredCondition{
				{Field: "authMethod", Values: []string{AuthTypeToken}},
			},
		},
		{
			Name:        "roleId",
			Label:       "Role ID",
			Type:        configuration.FieldTypeString,
			Description: "AppRole Role ID",
			Required:    false,
			Sensitive:   false,
			VisibilityConditions: []configuration.VisibilityCondition{
				{Field: "authMethod", Values: []string{AuthTypeAppRole}},
			},
			RequiredConditions: []configuration.RequiredCondition{
				{Field: "authMethod", Values: []string{AuthTypeAppRole}},
			},
		},
		{
			Name:        "secretId",
			Label:       "Secret ID",
			Type:        configuration.FieldTypeString,
			Description: "AppRole Secret ID",
			Required:    false,
			Sensitive:   true,
			VisibilityConditions: []configuration.VisibilityCondition{
				{Field: "authMethod", Values: []string{AuthTypeAppRole}},
			},
			RequiredConditions: []configuration.RequiredCondition{
				{Field: "authMethod", Values: []string{AuthTypeAppRole}},
			},
		},
		{
			Name:        "approleMountPath",
			Label:       "AppRole Mount Path",
			Type:        configuration.FieldTypeString,
			Description: "AppRole auth mount path (default: approle)",
			Required:    false,
			Sensitive:   false,
			Default:     "approle",
			VisibilityConditions: []configuration.VisibilityCondition{
				{Field: "authMethod", Values: []string{AuthTypeAppRole}},
			},
		},
	}
}

func (v *Vault) Components() []core.Component {
	return []core.Component{}
}

func (v *Vault) Triggers() []core.Trigger {
	return []core.Trigger{}
}

func (v *Vault) Actions() []core.Action {
	return []core.Action{}
}

func (v *Vault) HandleAction(ctx core.IntegrationActionContext) error {
	return nil
}

func (v *Vault) ListResources(resourceType string, ctx core.ListResourcesContext) ([]core.IntegrationResource, error) {
	return nil, nil
}

func (v *Vault) HandleRequest(ctx core.HTTPRequestContext) {
	ctx.Response.WriteHeader(http.StatusNotFound)
}

func (v *Vault) Cleanup(ctx core.IntegrationCleanupContext) error {
	return nil
}

func (v *Vault) Sync(ctx core.SyncContext) error {
	metadata := Metadata{}
	err := mapstructure.Decode(ctx.Integration.GetMetadata(), &metadata)
	if err != nil {
		return fmt.Errorf("failed to decode metadata: %v", err)
	}

	// Skip if already verified
	if metadata.Verified {
		return nil
	}

	// Create a Vault client and test the connection
	client, err := NewClient(ctx.HTTP, ctx.Integration)
	if err != nil {
		ctx.Integration.Error(err.Error())
		return nil
	}

	err = client.TestConnection()
	if err != nil {
		ctx.Integration.Error(fmt.Sprintf("Failed to connect to Vault: %v", err))
		return nil
	}

	// Connection successful - mark as verified and ready
	ctx.Integration.SetMetadata(Metadata{Verified: true})
	ctx.Integration.Ready()
	return nil
}
