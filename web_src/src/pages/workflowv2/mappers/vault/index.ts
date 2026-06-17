import type { ComponentBaseMapper, EventStateRegistry, TriggerRenderer } from "../types";
import { onSecretChangeTriggerRenderer } from "./on_secret_change";
import { getSecretMapper, GET_SECRET_STATE_REGISTRY } from "./get_secret";

export const componentMappers: Record<string, ComponentBaseMapper> = {
  getSecret: getSecretMapper,
};

export const triggerRenderers: Record<string, TriggerRenderer> = {
  onSecretChange: onSecretChangeTriggerRenderer,
};

export const eventStateRegistry: Record<string, EventStateRegistry> = {
  getSecret: GET_SECRET_STATE_REGISTRY,
};
