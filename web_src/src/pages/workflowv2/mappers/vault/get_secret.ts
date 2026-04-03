import type {
  ComponentBaseContext,
  ComponentBaseMapper,
  EventStateRegistry,
  ExecutionDetailsContext,
  ExecutionInfo,
  NodeInfo,
  OutputPayload,
  StateFunction,
  SubtitleContext,
} from "../types";
import type {
  ComponentBaseProps,
  ComponentBaseSpec,
  EventSection,
  EventState,
  EventStateMap,
} from "@/ui/componentBase";
import { DEFAULT_EVENT_STATE_MAP } from "@/ui/componentBase";
import { getBackgroundColorClass, getColorClass } from "@/lib/colors";
import type React from "react";
import type { MetadataItem } from "@/ui/metadataList";
import VaultIcon from "@/assets/icons/integrations/vault.svg";
import { renderTimeAgo } from "@/components/TimeAgo";
import { getState, getStateMap, getTriggerRenderer } from "..";
import type { CanvasesCanvasNodeExecution } from "@/api-client";
import { buildActionStateRegistry } from "../utils";

interface GetSecretConfiguration {
  mountPath?: string;
  secretPath?: string;
}

interface GetSecretMetadata {
  mountPath?: string;
  secretPath?: string;
}

interface GetSecretOutputData {
  data?: Record<string, unknown>;
  metadata?: {
    version?: number;
    created_time?: string;
  };
}

export const getSecretMapper: ComponentBaseMapper = {
  props(context: ComponentBaseContext): ComponentBaseProps {
    const lastExecution = context.lastExecutions.length > 0 ? context.lastExecutions[0] : null;
    const componentName = context.componentDefinition.name || "unknown";

    return {
      title:
        context.node.name ||
        context.componentDefinition.label ||
        context.componentDefinition.name ||
        "Unnamed component",
      iconSrc: VaultIcon,
      iconSlug: "vault",
      iconColor: getColorClass(context.componentDefinition.color),
      collapsedBackground: getBackgroundColorClass(context.componentDefinition.color),
      collapsed: context.node.isCollapsed,
      eventSections: lastExecution ? getSecretEventSections(context.nodes, lastExecution, componentName) : undefined,
      includeEmptyState: !lastExecution,
      metadata: getSecretMetadataList(context.node),
      specs: getSecretSpecs(context.node),
      eventStateMap: getStateMap(componentName),
    };
  },

  getExecutionDetails(context: ExecutionDetailsContext): Record<string, string> {
    const outputs = context.execution.outputs as { default?: OutputPayload[] } | undefined;
    const outputData = outputs?.default?.[0]?.data as GetSecretOutputData | undefined;

    return {
      "Started At": context.execution.createdAt ? new Date(context.execution.createdAt).toLocaleString() : "-",
      "Secret Path": getSecretPath(context.node) || "-",
      Version: outputData?.metadata?.version?.toString() || "-",
      "Created Time": outputData?.metadata?.created_time || "-",
    };
  },

  subtitle(context: SubtitleContext): string | React.ReactNode {
    const outputs = context.execution.outputs as { default?: OutputPayload[] } | undefined;
    const outputData = outputs?.default?.[0]?.data as GetSecretOutputData | undefined;
    const version = outputData?.metadata?.version;

    if (version && context.execution.createdAt) {
      return `v${version} · ${renderTimeAgo(new Date(context.execution.createdAt))}`;
    }

    if (context.execution.createdAt) {
      return renderTimeAgo(new Date(context.execution.createdAt));
    }

    return "";
  },
};

function getSecretMetadataList(node: NodeInfo): MetadataItem[] {
  const metadata: MetadataItem[] = [];
  const secretPath = getSecretPath(node);

  if (secretPath) {
    metadata.push({ icon: "key", label: secretPath });
  }

  return metadata;
}

function getSecretSpecs(node: NodeInfo): ComponentBaseSpec[] {
  const specs: ComponentBaseSpec[] = [];
  const configuration = node.configuration as GetSecretConfiguration | undefined;

  if (configuration?.secretPath) {
    specs.push({
      title: "secretPath",
      tooltipTitle: "Secret Path",
      iconSlug: "folder-key",
      value: configuration.secretPath,
      contentType: "text",
    });
  }

  return specs;
}

function getSecretEventSections(nodes: NodeInfo[], execution: ExecutionInfo, componentName: string): EventSection[] {
  const rootTriggerNode = nodes.find((n) => n.id === execution.rootEvent?.nodeId);
  const rootTriggerRenderer = getTriggerRenderer(rootTriggerNode?.componentName!);
  const { title } = rootTriggerRenderer.getTitleAndSubtitle({ event: execution.rootEvent });

  return [
    {
      receivedAt: new Date(execution.createdAt!),
      eventTitle: title,
      eventSubtitle: renderTimeAgo(new Date(execution.createdAt!)),
      eventState: getState(componentName)(execution),
      eventId: execution.rootEvent!.id!,
    },
  ];
}

function getSecretPath(node: NodeInfo): string | undefined {
  const nodeMetadata = node.metadata as GetSecretMetadata | undefined;
  const configuration = node.configuration as GetSecretConfiguration | undefined;

  const mountPath = nodeMetadata?.mountPath || configuration?.mountPath;
  const secretPath = nodeMetadata?.secretPath || configuration?.secretPath;

  if (mountPath && secretPath) {
    return `${mountPath}/${secretPath}`;
  }

  return secretPath || undefined;
}

export const GET_SECRET_STATE_REGISTRY: EventStateRegistry = buildActionStateRegistry("retrieved");
