import type {
  FormFieldType,
  FormSection,
  FormStepField,
  JsonSchemaObject,
  JsonSchemaProperty,
  McpToolDefinition,
  NormalizedToolForm,
} from '../types.js';

/**
 * Converts an MCP tool's JSON Schema into an ordered, sectioned form
 * (`step1: name`, `step2: descripcion`, ...) suitable for both CLI flags
 * and interactive wizard rendering.
 */
export function buildToolForm(tool: McpToolDefinition): NormalizedToolForm {
  const schema: JsonSchemaObject = tool.inputSchema ?? { type: 'object', properties: {} };
  const rawFields: Array<Omit<FormStepField, 'stepIndex'> & { order: number }> = [];

  collectFields(schema, [], 'General', rawFields);

  // Stable sort: explicit x-order first, then required fields before optional within each section
  rawFields.sort((a, b) => {
    if (a.section !== b.section) return 0;
    if (a.order !== b.order) return a.order - b.order;
    if (a.required !== b.required) return a.required ? -1 : 1;
    return 0;
  });

  const sectionMap = new Map<string, FormStepField[]>();
  const steps: FormStepField[] = [];

  rawFields.forEach((item, idx) => {
    const field: FormStepField = {
      name: item.name,
      path: item.path,
      label: item.label,
      description: item.description,
      type: item.type,
      required: item.required,
      defaultValue: item.defaultValue,
      enumValues: item.enumValues,
      section: item.section,
      stepIndex: idx + 1,
    };
    steps.push(field);
    const bucket = sectionMap.get(field.section) ?? [];
    bucket.push(field);
    sectionMap.set(field.section, bucket);
  });

  const sections: FormSection[] = Array.from(sectionMap.entries()).map(([name, fields]) => ({
    name,
    fields,
  }));

  return {
    toolName: tool.name,
    description: tool.description,
    sections,
    steps,
  };
}

function collectFields(
  schema: JsonSchemaObject | JsonSchemaProperty,
  prefixPath: string[],
  defaultSection: string,
  out: Array<Omit<FormStepField, 'stepIndex'> & { order: number }>,
): void {
  const props = schema.properties ?? {};
  const requiredSet = new Set(schema.required ?? []);

  for (const [key, prop] of Object.entries(props)) {
    const path = [...prefixPath, key];
    const primaryType = resolvePrimaryType(prop);

    // Flatten nested object properties into their own named section (max depth 3)
    if (primaryType === 'object' && prop.properties && Object.keys(prop.properties).length > 0 && path.length < 3) {
      const nestedSection = prop['x-section'] ?? prop.title ?? humanize(key);
      collectFields(prop, path, nestedSection, out);
      continue;
    }

    const section = prop['x-section'] ?? defaultSection;
    out.push({
      name: path.join('.'),
      path,
      label: prop.title ?? key,
      description: prop.description,
      type: primaryType,
      required: requiredSet.has(key),
      defaultValue: prop.default,
      enumValues: Array.isArray(prop.enum) ? prop.enum.map(String) : undefined,
      section,
      order: typeof prop['x-order'] === 'number' ? prop['x-order'] : 999,
    });
  }
}

function resolvePrimaryType(prop: JsonSchemaProperty): FormFieldType {
  if (Array.isArray(prop.enum) && prop.enum.length > 0) return 'enum';
  const rawType = Array.isArray(prop.type)
    ? prop.type.find((t) => t !== 'null') ?? 'string'
    : prop.type ?? 'string';

  switch (rawType) {
    case 'number':
    case 'integer':
      return 'number';
    case 'boolean':
      return 'boolean';
    case 'array':
      return 'array';
    case 'object':
      return 'object';
    default:
      return 'string';
  }
}

function humanize(key: string): string {
  return key
    .replace(/[_-]+/g, ' ')
    .replace(/([a-z])([A-Z])/g, '$1 $2')
    .replace(/^\w/, (c) => c.toUpperCase());
}

/**
 * Sets a dot-path field value into a nested payload object and coerces its type.
 */
export function setNestedValue(
  target: Record<string, unknown>,
  path: string[],
  value: unknown,
): void {
  let cursor: Record<string, unknown> = target;
  for (let i = 0; i < path.length - 1; i++) {
    const seg = path[i];
    if (typeof cursor[seg] !== 'object' || cursor[seg] === null || Array.isArray(cursor[seg])) {
      cursor[seg] = {};
    }
    cursor = cursor[seg] as Record<string, unknown>;
  }
  cursor[path[path.length - 1]] = value;
}

export function coerceFieldValue(raw: string, field: FormStepField): unknown {
  const trimmed = raw.trim();
  if (trimmed === '' && field.defaultValue !== undefined) return field.defaultValue;

  switch (field.type) {
    case 'number': {
      const n = Number(trimmed);
      if (Number.isNaN(n)) throw new Error(`Field "${field.name}" expects a number, received "${raw}"`);
      return n;
    }
    case 'boolean': {
      const low = trimmed.toLowerCase();
      if (['true', '1', 'yes', 'y', 'si', 'sí'].includes(low)) return true;
      if (['false', '0', 'no', 'n'].includes(low)) return false;
      throw new Error(`Field "${field.name}" expects a boolean (true/false), received "${raw}"`);
    }
    case 'enum': {
      if (field.enumValues && !field.enumValues.includes(trimmed)) {
        throw new Error(
          `Field "${field.name}" must be one of [${field.enumValues.join(', ')}], received "${raw}"`,
        );
      }
      return trimmed;
    }
    case 'array': {
      if (trimmed.startsWith('[')) {
        return JSON.parse(trimmed);
      }
      return trimmed === '' ? [] : trimmed.split(',').map((s) => s.trim());
    }
    case 'object': {
      return trimmed === '' ? {} : JSON.parse(trimmed);
    }
    default:
      return raw;
  }
}

export function validateFormValues(
  form: NormalizedToolForm,
  payload: Record<string, unknown>,
): string[] {
  const errors: string[] = [];
  for (const step of form.steps) {
    const val = getNestedValue(payload, step.path);
    if (step.required && (val === undefined || val === null || val === '')) {
      errors.push(`Missing required field "${step.name}" (step ${step.stepIndex})`);
    }
    if (val !== undefined && step.type === 'enum' && step.enumValues) {
      if (!step.enumValues.includes(String(val))) {
        errors.push(`Invalid enum value for "${step.name}": ${String(val)}`);
      }
    }
  }
  return errors;
}

export function getNestedValue(obj: Record<string, unknown>, path: string[]): unknown {
  let cursor: unknown = obj;
  for (const seg of path) {
    if (typeof cursor !== 'object' || cursor === null) return undefined;
    cursor = (cursor as Record<string, unknown>)[seg];
  }
  return cursor;
}
