import type { AiProviderAdapter, ConfiguredProvider } from '../types.js';
import type { ConfigRegistry } from '../core/registry.js';
import { AnthropicProvider } from './anthropic.js';
import { GeminiProvider } from './gemini.js';
import { OpenAiCompatProvider } from './openaiCompat.js';

export { PROVIDER_CATALOG, getProviderPreset, listProviderPresets } from './catalog.js';
export { OpenAiCompatProvider, extractJsonObject } from './openaiCompat.js';
export { AnthropicProvider } from './anthropic.js';
export { GeminiProvider } from './gemini.js';
export { streamFieldWithAi, fillToolWithAi } from './aiAssistant.js';

export function createAiProviderAdapter(
  cfg: ConfiguredProvider,
  apiKey?: string,
): AiProviderAdapter {
  const resolvedKey = apiKey ?? (cfg.envVar ? process.env[cfg.envVar] : undefined) ?? '';
  switch (cfg.driver) {
    case 'anthropic':
      return new AnthropicProvider({
        id: cfg.id,
        name: cfg.name,
        baseUrl: cfg.baseUrl,
        model: cfg.model,
        apiKey: resolvedKey,
      });
    case 'gemini':
      return new GeminiProvider({
        id: cfg.id,
        name: cfg.name,
        baseUrl: cfg.baseUrl,
        model: cfg.model,
        apiKey: resolvedKey,
      });
    case 'openai-compat':
    default:
      return new OpenAiCompatProvider({
        id: cfg.id,
        name: cfg.name,
        baseUrl: cfg.baseUrl,
        model: cfg.model,
        apiKey: resolvedKey || undefined,
        extraHeaders: cfg.extraHeaders,
      });
  }
}

export function resolveAiProvider(
  registry: ConfigRegistry,
  providerId?: string,
  modelOverride?: string,
): AiProviderAdapter | undefined {
  const cfg = registry.getProvider(providerId);
  if (!cfg) return undefined;
  const secret = cfg.secretRef ? registry.vault.get(cfg.secretRef) : undefined;
  return createAiProviderAdapter(
    modelOverride ? { ...cfg, model: modelOverride } : cfg,
    secret,
  );
}
