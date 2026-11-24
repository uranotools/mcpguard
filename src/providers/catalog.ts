import type { ProviderPreset } from '../types.js';

export const PROVIDER_CATALOG: Record<string, ProviderPreset> = {
  openrouter: {
    id: 'openrouter',
    name: 'OpenRouter',
    driver: 'openai-compat',
    baseUrl: 'https://openrouter.ai/api/v1',
    envVar: 'OPENROUTER_API_KEY',
    defaultModel: 'anthropic/claude-3.5-sonnet',
    requiresKey: true,
    extraHeaders: {
      'HTTP-Referer': 'https://github.com/uranotools/mcpguard',
      'X-Title': 'mcpguard',
    },
    docsUrl: 'https://openrouter.ai/keys',
  },
  huggingface: {
    id: 'huggingface',
    name: 'Hugging Face Inference',
    driver: 'openai-compat',
    baseUrl: 'https://router.huggingface.co/v1',
    envVar: 'HF_TOKEN',
    defaultModel: 'Qwen/Qwen2.5-72B-Instruct',
    requiresKey: true,
    docsUrl: 'https://huggingface.co/settings/tokens',
  },
  openai: {
    id: 'openai',
    name: 'OpenAI',
    driver: 'openai-compat',
    baseUrl: 'https://api.openai.com/v1',
    envVar: 'OPENAI_API_KEY',
    defaultModel: 'gpt-4o-mini',
    requiresKey: true,
    docsUrl: 'https://platform.openai.com/api-keys',
  },
  anthropic: {
    id: 'anthropic',
    name: 'Anthropic',
    driver: 'anthropic',
    baseUrl: 'https://api.anthropic.com/v1',
    envVar: 'ANTHROPIC_API_KEY',
    defaultModel: 'claude-3-5-haiku-latest',
    requiresKey: true,
    docsUrl: 'https://console.anthropic.com/settings/keys',
  },
  deepseek: {
    id: 'deepseek',
    name: 'DeepSeek',
    driver: 'openai-compat',
    baseUrl: 'https://api.deepseek.com/v1',
    envVar: 'DEEPSEEK_API_KEY',
    defaultModel: 'deepseek-chat',
    requiresKey: true,
    docsUrl: 'https://platform.deepseek.com/api_keys',
  },
  alibaba: {
    id: 'alibaba',
    name: 'Alibaba Cloud Model Studio (Qwen / DashScope)',
    driver: 'openai-compat',
    baseUrl: 'https://dashscope-intl.aliyuncs.com/compatible-mode/v1',
    envVar: 'DASHSCOPE_API_KEY',
    defaultModel: 'qwen-plus',
    requiresKey: true,
    docsUrl: 'https://www.alibabacloud.com/help/en/model-studio/',
  },
  gemini: {
    id: 'gemini',
    name: 'Google Gemini',
    driver: 'gemini',
    baseUrl: 'https://generativelanguage.googleapis.com/v1beta',
    envVar: 'GEMINI_API_KEY',
    defaultModel: 'gemini-2.5-flash',
    requiresKey: true,
    docsUrl: 'https://aistudio.google.com/apikey',
  },
  ollama: {
    id: 'ollama',
    name: 'Ollama (Local)',
    driver: 'openai-compat',
    baseUrl: 'http://127.0.0.1:11434/v1',
    envVar: 'OLLAMA_API_KEY',
    defaultModel: 'qwen2.5:7b',
    requiresKey: false,
    docsUrl: 'https://ollama.com',
  },
};

export function getProviderPreset(id: string): ProviderPreset | undefined {
  return PROVIDER_CATALOG[id.toLowerCase()];
}

export function listProviderPresets(): ProviderPreset[] {
  return Object.values(PROVIDER_CATALOG);
}
