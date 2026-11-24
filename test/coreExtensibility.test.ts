import test from 'node:test';
import assert from 'node:assert/strict';
import {
  AuditRunner,
  createContext,
  createFlagRegistry,
  NATIVE_CONTEXT_KEYS,
} from '../src/core/index.js';
import type { FlagAdapter } from '../src/types.js';

test('FlagAdapter reads native MCP context variables, publishes custom data, and feeds an AuditSuite', async () => {
  const ctx = createContext();
  ctx.set(NATIVE_CONTEXT_KEYS.TOOLS, [
    { name: 'list_orders', description: 'Lists recent customer orders safely' },
    { name: 'get_invoice', description: 'Fetches a single invoice by ID' },
  ]);
  ctx.set(NATIVE_CONTEXT_KEYS.OUTBOUND_URLS, ['https://api.example.com/v1']);
  ctx.set(NATIVE_CONTEXT_KEYS.ENV_VARS, ['NODE_ENV']);

  const registry = createFlagRegistry();
  const auditRunner = new AuditRunner();

  const customFlag: FlagAdapter = {
    flag: 'compliance-tag',
    description: 'Publishes compliance metadata from captured MCP tools',
    valueType: 'string',
    phase: 'post-scan',
    async run(value, c) {
      const tools = c.get<Array<{ name: string }>>(NATIVE_CONTEXT_KEYS.TOOLS) ?? [];
      c.publish(
        'compliance.summary',
        { tag: String(value), toolCount: tools.length, approved: tools.length <= 5 },
        'compliance-adapter',
      );
    },
    auditSuite: {
      id: 'compliance',
      name: 'Compliance Gate',
      description: 'Validates compliance.summary exported by --compliance-tag',
      tests: [
        {
          id: 'compliance-approved',
          title: 'MCP passes compliance tool limit',
          severity: 'high',
          async run(c) {
            const summary = c.get<{ tag: string; approved: boolean }>('compliance.summary');
            return {
              passed: Boolean(summary?.approved),
              detail: `tag=${summary?.tag}`,
            };
          },
        },
      ],
    },
  };

  registry.register(customFlag);
  for (const s of registry.listAttachedSuites()) auditRunner.register(s);

  const ranFlags = await registry.runPhase('post-scan', { 'compliance-tag': 'soc2' }, ctx);
  assert.deepEqual(ranFlags, ['compliance-tag']);
  assert.equal(ctx.sources()['compliance.summary'], 'compliance-adapter');

  const complianceReport = await auditRunner.runSuite('compliance', ctx);
  assert.equal(complianceReport.passed, 1);
  assert.equal(complianceReport.failed, 0);

  const privacyReport = await auditRunner.runSuite('privacy', ctx);
  assert.equal(privacyReport.passed, 2);
  assert.equal(privacyReport.failed, 0);
});
