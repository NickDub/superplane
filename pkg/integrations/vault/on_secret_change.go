package vault

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/mitchellh/mapstructure"
	"github.com/superplanehq/superplane/pkg/configuration"
	"github.com/superplanehq/superplane/pkg/core"
)

const (
	OnSecretChangePayloadType = "vault.secret.changed"
	OnSecretChangePollAction  = "poll"
)

// Polling interval options
var pollingIntervalOptions = []configuration.FieldOption{
	{Label: "1 minute", Value: "1m"},
	{Label: "5 minutes", Value: "5m"},
	{Label: "15 minutes", Value: "15m"},
	{Label: "30 minutes", Value: "30m"},
	{Label: "1 hour", Value: "1h"},
}

// pollingIntervalDurations maps interval strings to time.Duration
var pollingIntervalDurations = map[string]time.Duration{
	"1m":  1 * time.Minute,
	"5m":  5 * time.Minute,
	"15m": 15 * time.Minute,
	"30m": 30 * time.Minute,
	"1h":  1 * time.Hour,
}

// OnSecretChange implements the Vault secret change trigger
type OnSecretChange struct{}

// OnSecretChangeConfiguration holds the trigger configuration
type OnSecretChangeConfiguration struct {
	MountPath       string `json:"mountPath" mapstructure:"mountPath"`
	SecretPath      string `json:"secretPath" mapstructure:"secretPath"`
	PollingInterval string `json:"pollingInterval" mapstructure:"pollingInterval"`
}

// OnSecretChangeMetadata holds the trigger state
type OnSecretChangeMetadata struct {
	LastKnownVersion int    `json:"lastKnownVersion" mapstructure:"lastKnownVersion"`
	LastUpdatedTime  string `json:"lastUpdatedTime" mapstructure:"lastUpdatedTime"`
}

func (t *OnSecretChange) Name() string {
	return "vault.onSecretChange"
}

func (t *OnSecretChange) Label() string {
	return "On Secret Change"
}

func (t *OnSecretChange) Description() string {
	return "Triggers when a secret version changes in HashiCorp Vault KV v2"
}

func (t *OnSecretChange) Documentation() string {
	return `The On Secret Change trigger monitors a Vault KV v2 secret and triggers the workflow when the secret version changes.

## Use Cases

- **Configuration reload**: Trigger application restarts when config secrets change
- **Audit logging**: Track secret rotation events
- **Sync workflows**: Update dependent systems when credentials change

## Configuration

- **Mount Path**: The KV v2 secrets engine mount path (e.g., "secret")
- **Secret Path**: The path to the secret within the mount (e.g., "apps/myapp/database")
- **Polling Interval**: How often to check for changes (1m, 5m, 15m, 30m, 1h)

## How It Works

1. SuperPlane polls the Vault metadata endpoint at the configured interval
2. When the current version number increases, a change event is emitted
3. The payload includes version information but NOT the secret values
4. To retrieve secret values, chain this trigger with the "Get Secret" component

## Payload

The trigger emits a payload containing:
- ` + "`secretPath`" + `: The monitored secret path
- ` + "`mountPath`" + `: The KV v2 mount path
- ` + "`previousVersion`" + `: The last known version before the change
- ` + "`currentVersion`" + `: The new version number
- ` + "`metadata`" + `: Full metadata from Vault (versions, created_time, updated_time, etc.) - fields are at root level`
}

func (t *OnSecretChange) Icon() string {
	return "activity"
}

func (t *OnSecretChange) Color() string {
	return "gray"
}

func (t *OnSecretChange) ExampleData() map[string]any {
	return map[string]any{
		"secretPath":           "apps/myapp/database",
		"mountPath":            "secret",
		"previousVersion":      2,
		"currentVersion":       3,
		"cas_required":         false,
		"created_time":         "2024-01-15T10:30:00Z",
		"custom_metadata":      nil,
		"delete_version_after": "0s",
		"max_versions":         0,
		"oldest_version":       1,
		"updated_time":         "2024-01-16T14:20:00Z",
		"versions": map[string]any{
			"1": map[string]any{
				"created_time":  "2024-01-10T08:00:00Z",
				"deletion_time": "",
				"destroyed":     false,
			},
			"2": map[string]any{
				"created_time":  "2024-01-15T10:30:00Z",
				"deletion_time": "",
				"destroyed":     false,
			},
			"3": map[string]any{
				"created_time":  "2024-01-16T14:20:00Z",
				"deletion_time": "",
				"destroyed":     false,
			},
		},
	}
}

func (t *OnSecretChange) Configuration() []configuration.Field {
	return []configuration.Field{
		{
			Name:        "mountPath",
			Label:       "Mount Path",
			Type:        configuration.FieldTypeString,
			Required:    true,
			Default:     "secret",
			Description: "KV v2 secrets engine mount path (e.g., secret)",
		},
		{
			Name:        "secretPath",
			Label:       "Secret Path",
			Type:        configuration.FieldTypeString,
			Required:    true,
			Description: "Path to the secret to monitor (e.g., apps/myapp/database)",
		},
		{
			Name:        "pollingInterval",
			Label:       "Polling Interval",
			Type:        configuration.FieldTypeSelect,
			Required:    true,
			Default:     "5m",
			Description: "How often to check for secret changes",
			TypeOptions: &configuration.TypeOptions{
				Select: &configuration.SelectTypeOptions{
					Options: pollingIntervalOptions,
				},
			},
		},
	}
}

func (t *OnSecretChange) Setup(ctx core.TriggerContext) error {
	config, err := decodeOnSecretChangeConfiguration(ctx.Configuration)
	if err != nil {
		return err
	}

	if ctx.Integration == nil {
		return fmt.Errorf("missing integration context")
	}
	if ctx.Metadata == nil {
		return fmt.Errorf("missing metadata context")
	}

	// Create Vault client to validate configuration and get initial version
	client, err := NewClient(ctx.HTTP, ctx.Integration)
	if err != nil {
		return fmt.Errorf("failed to create Vault client: %w", err)
	}

	// Read initial metadata to validate the secret exists and get current version
	metadata, err := client.ReadSecretMetadata(config.MountPath, config.SecretPath)
	if err != nil {
		return fmt.Errorf("failed to read secret metadata: %w", err)
	}

	// Initialize trigger metadata with current version
	currentMetadata, err := decodeOnSecretChangeMetadata(ctx.Metadata.Get())
	if err != nil {
		currentMetadata = OnSecretChangeMetadata{}
	}

	// Only update if we don't have a version yet (first setup)
	if currentMetadata.LastKnownVersion == 0 {
		currentMetadata.LastKnownVersion = metadata.CurrentVersion
		currentMetadata.LastUpdatedTime = metadata.UpdatedTime
		if err := ctx.Metadata.Set(currentMetadata); err != nil {
			return fmt.Errorf("failed to save trigger metadata: %w", err)
		}
	}

	// Schedule polling
	if ctx.Requests != nil {
		interval := getPollingInterval(config.PollingInterval)
		if err := ctx.Requests.ScheduleActionCall(OnSecretChangePollAction, map[string]any{}, interval); err != nil {
			return fmt.Errorf("failed to schedule polling: %w", err)
		}
	}

	return nil
}

func (t *OnSecretChange) Actions() []core.Action {
	return []core.Action{
		{
			Name:           OnSecretChangePollAction,
			Description:    "Poll Vault for secret version changes",
			UserAccessible: false,
		},
	}
}

func (t *OnSecretChange) HandleAction(ctx core.TriggerActionContext) (map[string]any, error) {
	switch ctx.Name {
	case OnSecretChangePollAction:
		return nil, t.poll(ctx)
	default:
		return nil, fmt.Errorf("unknown action: %s", ctx.Name)
	}
}

func (t *OnSecretChange) poll(ctx core.TriggerActionContext) error {
	config, err := decodeOnSecretChangeConfiguration(ctx.Configuration)
	if err != nil {
		return err
	}

	if ctx.Metadata == nil {
		return fmt.Errorf("missing metadata context")
	}

	currentMetadata, err := decodeOnSecretChangeMetadata(ctx.Metadata.Get())
	if err != nil {
		return fmt.Errorf("failed to decode trigger metadata: %w", err)
	}

	// Create Vault client
	client, err := NewClient(ctx.HTTP, ctx.Integration)
	if err != nil {
		// Log error but reschedule polling
		if ctx.Logger != nil {
			ctx.Logger.Warnf("failed to create Vault client: %v", err)
		}
		return t.reschedulePolling(ctx, config)
	}

	// Read current secret metadata
	vaultMetadata, err := client.ReadSecretMetadata(config.MountPath, config.SecretPath)
	if err != nil {
		// Log error but reschedule polling
		if ctx.Logger != nil {
			ctx.Logger.Warnf("failed to read secret metadata: %v", err)
		}
		return t.reschedulePolling(ctx, config)
	}

	// Check if version changed OR updatedTime changed (metadata update)
	if vaultMetadata.CurrentVersion > currentMetadata.LastKnownVersion ||
		(vaultMetadata.UpdatedTime != currentMetadata.LastUpdatedTime && currentMetadata.LastUpdatedTime != "") {
		// Emit change event
		payload := map[string]any{
			"secretPath":           config.SecretPath,
			"mountPath":            config.MountPath,
			"previousVersion":      currentMetadata.LastKnownVersion,
			"currentVersion":       vaultMetadata.CurrentVersion,
			"cas_required":         vaultMetadata.CASRequired,
			"created_time":         vaultMetadata.CreatedTime,
			"custom_metadata":      vaultMetadata.CustomMetadata,
			"delete_version_after": vaultMetadata.DeleteVersionAfter,
			"max_versions":         vaultMetadata.MaxVersions,
			"oldest_version":       vaultMetadata.OldestVersion,
			"updated_time":         vaultMetadata.UpdatedTime,
			"versions":             vaultMetadata.Versions,
		}

		if err := ctx.Events.Emit(OnSecretChangePayloadType, payload); err != nil {
			return fmt.Errorf("failed to emit event: %w", err)
		}

		// Update stored metadata
		currentMetadata.LastKnownVersion = vaultMetadata.CurrentVersion
		currentMetadata.LastUpdatedTime = vaultMetadata.UpdatedTime
		if err := ctx.Metadata.Set(currentMetadata); err != nil {
			return fmt.Errorf("failed to update trigger metadata: %w", err)
		}
	}

	// Reschedule polling
	return t.reschedulePolling(ctx, config)
}

func (t *OnSecretChange) reschedulePolling(ctx core.TriggerActionContext, config OnSecretChangeConfiguration) error {
	if ctx.Requests == nil {
		return nil
	}

	interval := getPollingInterval(config.PollingInterval)
	return ctx.Requests.ScheduleActionCall(OnSecretChangePollAction, map[string]any{}, interval)
}

func (t *OnSecretChange) HandleWebhook(ctx core.WebhookRequestContext) (int, *core.WebhookResponseBody, error) {
	// Vault doesn't support webhooks for secret changes, only polling
	return http.StatusNotFound, nil, nil
}

func (t *OnSecretChange) Cleanup(ctx core.TriggerContext) error {
	return nil
}

func decodeOnSecretChangeConfiguration(value any) (OnSecretChangeConfiguration, error) {
	config := OnSecretChangeConfiguration{}
	if err := mapstructure.Decode(value, &config); err != nil {
		return OnSecretChangeConfiguration{}, fmt.Errorf("failed to decode configuration: %w", err)
	}

	config.MountPath = strings.TrimSpace(config.MountPath)
	if config.MountPath == "" {
		return OnSecretChangeConfiguration{}, fmt.Errorf("mountPath is required")
	}

	config.SecretPath = strings.TrimSpace(config.SecretPath)
	if config.SecretPath == "" {
		return OnSecretChangeConfiguration{}, fmt.Errorf("secretPath is required")
	}

	config.PollingInterval = strings.TrimSpace(config.PollingInterval)
	if config.PollingInterval == "" {
		config.PollingInterval = "5m"
	}

	// Validate polling interval
	if _, ok := pollingIntervalDurations[config.PollingInterval]; !ok {
		return OnSecretChangeConfiguration{}, fmt.Errorf("invalid pollingInterval: %s", config.PollingInterval)
	}

	return config, nil
}

func decodeOnSecretChangeMetadata(value any) (OnSecretChangeMetadata, error) {
	metadata := OnSecretChangeMetadata{}
	if err := mapstructure.Decode(value, &metadata); err != nil {
		return OnSecretChangeMetadata{}, fmt.Errorf("failed to decode metadata: %w", err)
	}
	return metadata, nil
}

func getPollingInterval(interval string) time.Duration {
	if duration, ok := pollingIntervalDurations[interval]; ok {
		return duration
	}
	return 5 * time.Minute // default
}
