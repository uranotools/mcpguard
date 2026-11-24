import type {
  AiProviderAdapter,
  FormStepField,
  McpToolDefinition,
} from '../types.js';

/**
 * Generates a single form field's value in real time (streaming chunks to the terminal),
 * aware of the tool context, field schema, and already-filled fields.
 */
export async function streamFieldWithAi(params: {
  provider: AiProviderAdapter;
  tool: McpToolDefinition;
  field: FormStepField;
  instruction: string;
  currentValues: Record<string, unknown>;
  model?: string;
  onChunk: (delta: string) => void;
}): Promise<string> {
  const systemPrompt = [
    'You are filling a single form field for an MCP tool invocation.',
    'Return ONLY the exact field value with no quotes, labels, or explanations.',
    `Tool: ${params.tool.name}${params.tool.description ? ` — ${params.tool.description}` : ''}`,
    `Field: ${params.field.name} (type: ${params.field.type})`,
    params.field.description ? `Field description: ${params.field.description}` : '',
    params.field.enumValues ? `Allowed values: ${params.field.enumValues.join(', ')}` : '',
    Object.keys(params.currentValues).length > 0
      ? `Already filled fields: ${JSON.stringify(params.currentValues)}`
      : '',
  ]
    .filter(Boolean)
    .join('\n');

  const result = await params.provider.streamText(
    {
      systemPrompt,
      prompt: params.instruction,
      model: params.model,
    },
    params.onChunk,
  );
  return result.trim();
}

/**
 * Generates all form fields at once using the tool's JSON Schema.
 */
export async function fillToolWithAi(params: {
  provider: AiProviderAdapter;
  tool: McpToolDefinition;
  instruction: string;
  existingValues?: Record<string, unknown>;
  model?: string;
}): Promise<Record<string, unknown>> {
  return params.provider.fillSchema({
    instruction: params.instruction,
    toolName: params.tool.name,
    toolDescription: params.tool.description,
    schema: params.tool.inputSchema ?? { type: 'object', properties: {} },
    existingValues: params.existingValues,
    model: params.model,
  });
}
