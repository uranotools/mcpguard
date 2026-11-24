import test from 'node:test';
import assert from 'node:assert/strict';
import {
  buildToolForm,
  coerceFieldValue,
  setNestedValue,
  validateFormValues,
} from '../src/core/schemaForm.js';
import type { McpToolDefinition } from '../src/types.js';

test('buildToolForm converts nested JSON Schema into sectioned steps', () => {
  const tool: McpToolDefinition = {
    name: 'register_product',
    description: 'Register a new catalog item',
    inputSchema: {
      type: 'object',
      required: ['name', 'price'],
      properties: {
        name: { type: 'string', description: 'Product name', 'x-section': 'Basic Info', 'x-order': 1 },
        descripcion: { type: 'string', description: 'Product description', 'x-section': 'Basic Info', 'x-order': 2 },
        price: { type: 'number', 'x-section': 'Pricing' },
        category: { type: 'string', enum: ['coffee', 'tea'], 'x-section': 'Basic Info', 'x-order': 3 },
        meta: {
          type: 'object',
          title: 'Metadata',
          properties: {
            tags: { type: 'array', items: { type: 'string' } },
            active: { type: 'boolean', default: true },
          },
        },
      },
    },
  };

  const form = buildToolForm(tool);
  assert.equal(form.toolName, 'register_product');
  assert.equal(form.steps.length, 6);
  assert.equal(form.steps[0].name, 'name');
  assert.equal(form.steps[0].stepIndex, 1);
  assert.equal(form.steps[1].name, 'descripcion');
  assert.equal(form.sections.map((s) => s.name).includes('Metadata'), true);

  const payload: Record<string, unknown> = {};
  setNestedValue(payload, ['name'], coerceFieldValue('Café Urano', form.steps[0]));
  setNestedValue(payload, ['price'], coerceFieldValue('19.5', form.steps.find((s) => s.name === 'price')!));
  setNestedValue(payload, ['meta', 'tags'], coerceFieldValue('organic, single-origin', form.steps.find((s) => s.name === 'meta.tags')!));
  setNestedValue(payload, ['meta', 'active'], coerceFieldValue('true', form.steps.find((s) => s.name === 'meta.active')!));

  assert.deepEqual(payload, {
    name: 'Café Urano',
    price: 19.5,
    meta: { tags: ['organic', 'single-origin'], active: true },
  });
  assert.deepEqual(validateFormValues(form, payload), []);
});

test('validateFormValues flags missing required fields', () => {
  const form = buildToolForm({
    name: 'create_user',
    inputSchema: {
      type: 'object',
      required: ['email'],
      properties: {
        email: { type: 'string' },
      },
    },
  });
  const errors = validateFormValues(form, {});
  assert.equal(errors.length, 1);
  assert.match(errors[0], /email/);
});
