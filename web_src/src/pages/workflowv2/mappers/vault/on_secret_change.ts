import { getBackgroundColorClass, getColorClass } from "@/lib/colors";
import type React from "react";
import type { TriggerEventContext, TriggerRenderer, TriggerRendererContext } from "../types";
import type { TriggerProps } from "@/ui/trigger";
import VaultIcon from "@/assets/icons/integrations/vault.svg";
import { renderTimeAgo, renderWithTimeAgo } from "@/components/TimeAgo";

interface OnSecretChangeConfiguration {
  mountPath?: string;
  secretPath?: string;
  pollingInterval?: string;
}

interface OnSecretChangeEventData {
  secretPath?: string;
  mountPath?: string;
  previousVersion?: number;
  currentVersion?: number;
  metadata?: {
    created_time?: string;
    updated_time?: string;
  };
}

export const onSecretChangeTriggerRenderer: TriggerRenderer = {
  getTitleAndSubtitle: (context: TriggerEventContext): { title: string; subtitle: string | React.ReactNode } => {
    const eventData = context.event?.data as OnSecretChangeEventData | undefined;
    const secretPath = eventData?.secretPath || "unknown";
    const currentVersion = eventData?.currentVersion;
    const title = currentVersion
      ? `Secret updated: ${secretPath} (v${currentVersion})`
      : `Secret updated: ${secretPath}`;

    const previousVersion = eventData?.previousVersion;
    const versionInfo =
      previousVersion !== undefined && currentVersion !== undefined ? `v${previousVersion} → v${currentVersion}` : "";

    const subtitle =
      versionInfo && context.event?.createdAt
        ? renderWithTimeAgo(versionInfo, new Date(context.event.createdAt))
        : versionInfo || (context.event?.createdAt ? renderTimeAgo(new Date(context.event.createdAt)) : "");

    return { title, subtitle };
  },

  getRootEventValues: (context: TriggerEventContext): Record<string, string> => {
    const eventData = context.event?.data as OnSecretChangeEventData | undefined;

    return {
      "Secret Path": eventData?.secretPath || "-",
      "Mount Path": eventData?.mountPath || "-",
      "Previous Version": eventData?.previousVersion?.toString() || "-",
      "Current Version": eventData?.currentVersion?.toString() || "-",
      "Updated Time": eventData?.metadata?.updated_time || "-",
    };
  },

  getTriggerProps: (context: TriggerRendererContext) => {
    const { node, definition, lastEvent } = context;
    const configuration = node.configuration as OnSecretChangeConfiguration | undefined;
    const metadataItems: TriggerProps["metadata"] = [];

    // Show secret path
    const fullPath = getFullSecretPath(configuration);
    if (fullPath) {
      metadataItems.push({ icon: "key", label: fullPath });
    }

    // Show polling interval
    const pollingInterval = configuration?.pollingInterval;
    if (pollingInterval) {
      metadataItems.push({ icon: "clock", label: `every ${pollingInterval}` });
    }

    const props: TriggerProps = {
      title: node.name || definition.label || "Unnamed trigger",
      iconSrc: VaultIcon,
      iconSlug: "vault",
      iconColor: getColorClass(definition.color),
      collapsedBackground: getBackgroundColorClass(definition.color),
      metadata: metadataItems,
    };

    if (lastEvent) {
      const eventData = lastEvent.data as OnSecretChangeEventData | undefined;
      const secretPath = eventData?.secretPath || "unknown";
      const currentVersion = eventData?.currentVersion;
      const title = currentVersion
        ? `Secret updated: ${secretPath} (v${currentVersion})`
        : `Secret updated: ${secretPath}`;

      const previousVersion = eventData?.previousVersion;
      const versionInfo =
        previousVersion !== undefined && currentVersion !== undefined ? `v${previousVersion} → v${currentVersion}` : "";

      const subtitle =
        versionInfo && lastEvent.createdAt
          ? renderWithTimeAgo(versionInfo, new Date(lastEvent.createdAt))
          : versionInfo || (lastEvent.createdAt ? renderTimeAgo(new Date(lastEvent.createdAt)) : "");

      props.lastEventData = {
        title,
        subtitle,
        receivedAt: new Date(lastEvent.createdAt),
        state: "triggered",
        eventId: lastEvent.id,
      };
    }

    return props;
  },
};

function getFullSecretPath(configuration: OnSecretChangeConfiguration | undefined): string | undefined {
  if (!configuration) return undefined;

  const { mountPath, secretPath } = configuration;
  if (mountPath && secretPath) {
    return `${mountPath}/${secretPath}`;
  }

  return secretPath || undefined;
}
