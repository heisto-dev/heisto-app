/** Thin fetch clients for Anthropic and OpenAI(-compatible) chat APIs. */

export interface ChatRequest { system: string; user: string; maxTokens?: number; json?: boolean; temperature?: number }
export interface LlmClient { name: string; complete(req: ChatRequest): Promise<string> }

class ProviderError extends Error {
  constructor(message: string, readonly retryable = false) { super(message); }
}

// Bound concurrent provider requests, including calls from parallel juries.
let active = 0;
const waiting: (() => void)[] = [];
async function limited<T>(fn: () => Promise<T>): Promise<T> {
  if (active >= 2) {
    if (waiting.length >= 64) throw new ProviderError('AI service is busy. Try again later.');
    await new Promise<void>(resolve => waiting.push(resolve));
  } else active++;
  try { return await fn(); } finally {
    const next = waiting.shift();
    if (next) next();
    else active--;
  }
}

async function withTimeout<T>(p: (signal: AbortSignal) => Promise<T>, ms: number): Promise<T> {
  const ac = new AbortController();
  const t = setTimeout(() => ac.abort(), ms);
  try { return await p(ac.signal); } finally { clearTimeout(t); }
}

async function retry<T>(fn: () => Promise<T>, attempts = 3): Promise<T> {
  for (let i = 0; i < attempts; i++) {
    try { return await limited(fn); } catch (e) {
      const error = e instanceof ProviderError ? e : new ProviderError('AI connection failed or timed out.', true);
      if (!error.retryable || i === attempts - 1) throw error;
      await new Promise(r => setTimeout(r, 600 * 2 ** i));
    }
  }
  throw new ProviderError('AI request failed.');
}

async function checkStatus(res: Response, provider: string) {
  if (res.ok) return;
  // Provider bodies can contain account details or echoed input. Never expose them.
  await res.body?.cancel();
  throw new ProviderError(`${provider} request failed (HTTP ${res.status}).`, res.status === 429 || res.status >= 500);
}

export function anthropic(apiKey: string, model: string): LlmClient {
  const thinkingModel = /^claude-(?:opus|sonnet|haiku|fable)-5(?:-|$)/.test(model);
  return {
    name: `anthropic:${model}`,
    complete: req => retry(() => withTimeout(async signal => {
      const res = await fetch('https://api.anthropic.com/v1/messages', {
        method: 'POST', signal,
        headers: { 'content-type': 'application/json', 'x-api-key': apiKey, 'anthropic-version': '2023-06-01' },
        body: JSON.stringify({
          model,
          // Thinking and visible output share this budget on newer models.
          max_tokens: thinkingModel ? Math.max(8192, req.maxTokens ?? 0) : req.maxTokens ?? 600,
          ...(thinkingModel ? {} : { temperature: req.temperature ?? 0 }),
          system: req.system, messages: [{ role: 'user', content: req.user }],
        }),
      });
      await checkStatus(res, 'Anthropic');
      const body = await res.json() as { content: { type: string; text?: string }[] };
      const text = body.content?.filter(c => c.type === 'text').map(c => c.text ?? '').join('') ?? '';
      if (!text.trim()) throw new ProviderError('Anthropic returned no text.');
      return text;
    }, 45_000)),
  };
}

export function openaiCompatible(apiKey: string, model: string, baseUrl = 'https://api.openai.com/v1'): LlmClient {
  const reasoningModel = /^(?:gpt-[5-9]|o[134])/.test(model);
  const supportsMinimalEffort = /^gpt-5(?:-(?:mini|nano))?$/.test(model);
  return {
    name: `openai:${model}`,
    complete: req => retry(() => withTimeout(async signal => {
      const res = await fetch(`${baseUrl.replace(/\/$/, '')}/chat/completions`, {
        method: 'POST', signal,
        headers: { 'content-type': 'application/json', authorization: `Bearer ${apiKey}` },
        body: JSON.stringify({
          model,
          max_completion_tokens: reasoningModel ? Math.max(8192, req.maxTokens ?? 0) : req.maxTokens ?? 600,
          ...(supportsMinimalEffort ? { reasoning_effort: 'minimal' } : {}),
          ...(req.json ? { response_format: { type: 'json_object' } } : {}),
          messages: [{ role: 'system', content: req.system }, { role: 'user', content: req.user }],
        }),
      });
      await checkStatus(res, 'OpenAI');
      const body = await res.json() as { choices: { message: { content: string | null } }[] };
      const text = body.choices?.[0]?.message?.content ?? '';
      if (!text.trim()) throw new ProviderError('OpenAI returned no text.');
      return text;
    }, 45_000)),
  };
}
