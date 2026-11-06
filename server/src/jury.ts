import { anthropic, openaiCompatible } from './lib/llm.js';
import type { Jury } from './lib/judge.js';

/** Original three-provider jury; never silently substitutes simulated votes. */
export function createJury(env: NodeJS.ProcessEnv): Jury {
  const a = env.ANTHROPIC_API_KEY, o = env.OPENAI_API_KEY;
  if (!a || !o) throw new Error('Both personal AI provider credentials are required.');
  return {
    judges: [
      anthropic(a, env.ANTHROPIC_JUDGE_MODEL ?? 'claude-opus-5-5'),
      openaiCompatible(o, env.OPENAI_JUDGE_MODEL ?? 'gpt-5'),
      anthropic(a, env.ANTHROPIC_JUDGE_MODEL_2 ?? 'claude-haiku-5-5'),
    ],
    sentinelClient(model, custom) {
      if ((model === 'custom' || model === 'llama') && custom) return openaiCompatible(custom.apiKey, custom.model, custom.baseUrl);
      return model === 'gpt'
        ? openaiCompatible(o, env.OPENAI_SENTINEL_MODEL ?? 'gpt-5')
        : anthropic(a, env.ANTHROPIC_SENTINEL_MODEL ?? 'claude-sonnet-5-5');
    },
  };
}
