import { createInterface } from 'node:readline/promises';
import type { AiProviderAdapter, McpToolDefinition, NormalizedToolForm } from '../types.js';
import { coerceFieldValue, getNestedValue, setNestedValue } from '../core/schemaForm.js';
import { streamFieldWithAi } from '../providers/aiAssistant.js';
import { ansi } from './ansi.js';

export interface WizardOptions {
  tool: McpToolDefinition;
  form: NormalizedToolForm;
  initialValues?: Record<string, unknown>;
  aiProvider?: AiProviderAdapter;
  aiModel?: string;
}

/**
 * Interactive sectioned form wizard (`step1: name`, `step2: descripcion`, ...).
 * Inside any step, typing `@ai <instruction>` streams an AI-generated value in real time.
 */
export async function runInteractiveFormWizard(
  opts: WizardOptions,
): Promise<{ cancelled: boolean; values: Record<string, unknown> }> {
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  const values: Record<string, unknown> = structuredClone(opts.initialValues ?? {});

  try {
    console.log('');
    console.log(ansi.bold(ansi.cyan(`▸ ${opts.form.toolName}`)));
    if (opts.form.description) console.log(ansi.dim(`  ${opts.form.description}`));
    console.log(
      ansi.gray('  Tips: type "@ai <prompt>" in any field to stream AI help, "@back" to go back, "@skip" for optional fields.'),
    );

    let currentSection = '';
    let idx = 0;

    while (idx < opts.form.steps.length) {
      const step = opts.form.steps[idx];
      if (step.section !== currentSection) {
        currentSection = step.section;
        console.log(`\n${ansi.bold(ansi.blue(`[Section: ${currentSection}]`))}`);
      }

      const existing = getNestedValue(values, step.path);
      const reqTag = step.required ? ansi.red('*') : ansi.dim('(optional)');
      const enumHint = step.enumValues ? ansi.dim(` [${step.enumValues.join('|')}]`) : '';
      const defHint =
        existing !== undefined
          ? ansi.dim(` (current: ${JSON.stringify(existing)})`)
          : step.defaultValue !== undefined
            ? ansi.dim(` (default: ${JSON.stringify(step.defaultValue)})`)
            : '';

      console.log(
        `${ansi.cyan(`step${step.stepIndex}`)}: ${ansi.bold(step.name)} ${reqTag}${enumHint}${defHint}`,
      );
      if (step.description) console.log(`  ${ansi.dim(step.description)}`);

      const answer = (await rl.question(ansi.green('  > '))).trim();

      if (answer === '@back') {
        idx = Math.max(0, idx - 1);
        continue;
      }

      if (answer === '@skip' && !step.required) {
        idx++;
        continue;
      }

      if (answer.startsWith('@ai ')) {
        if (!opts.aiProvider) {
          console.log(ansi.yellow('  No AI provider configured. Run: mcpguard provider add <openrouter|openai|anthropic|deepseek|alibaba|huggingface>'));
          continue;
        }
        const instruction = answer.slice(4).trim();
        process.stdout.write(ansi.magenta('  [AI] '));
        const generated = await streamFieldWithAi({
          provider: opts.aiProvider,
          tool: opts.tool,
          field: step,
          instruction,
          currentValues: values,
          model: opts.aiModel,
          onChunk: (delta) => process.stdout.write(delta),
        });
        process.stdout.write('\n');

        const accept = (await rl.question(ansi.dim('  Accept generated value? [Y/n] '))).trim().toLowerCase();
        if (accept === '' || accept === 'y' || accept === 'yes' || accept === 's' || accept === 'si') {
          try {
            setNestedValue(values, step.path, coerceFieldValue(generated, step));
            idx++;
          } catch (err) {
            console.log(ansi.red(`  ${err instanceof Error ? err.message : String(err)}`));
          }
        }
        continue;
      }

      if (answer === '') {
        if (existing !== undefined) {
          idx++;
          continue;
        }
        if (step.defaultValue !== undefined) {
          setNestedValue(values, step.path, step.defaultValue);
          idx++;
          continue;
        }
        if (!step.required) {
          idx++;
          continue;
        }
        console.log(ansi.red('  This field is required.'));
        continue;
      }

      try {
        setNestedValue(values, step.path, coerceFieldValue(answer, step));
        idx++;
      } catch (err) {
        console.log(ansi.red(`  ${err instanceof Error ? err.message : String(err)}`));
      }
    }

    console.log('\n' + ansi.bold('Payload Preview:'));
    console.log(ansi.dim(JSON.stringify(values, null, 2)));
    const confirm = (await rl.question(ansi.bold('Execute tool call? [Y/n] '))).trim().toLowerCase();
    const cancelled = confirm === 'n' || confirm === 'no';
    return { cancelled, values };
  } finally {
    rl.close();
  }
}

export async function promptConfirm(message: string, defaultYes = true): Promise<boolean> {
  if (!process.stdin.isTTY) return defaultYes;
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  try {
    const suffix = defaultYes ? '[Y/n]' : '[y/N]';
    const ans = (await rl.question(`${message} ${suffix} `)).trim().toLowerCase();
    if (ans === '') return defaultYes;
    return ans === 'y' || ans === 'yes' || ans === 's' || ans === 'si';
  } finally {
    rl.close();
  }
}
