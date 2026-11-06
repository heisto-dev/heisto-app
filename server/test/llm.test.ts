import { afterEach, describe, expect, it, vi } from 'vitest';
import { anthropic, openaiCompatible } from '../src/lib/llm.js';

afterEach(() => vi.unstubAllGlobals());

function capture(response: object) {
  const fetcher = vi.fn().mockResolvedValue(new Response(JSON.stringify(response), { status: 200 }));
  vi.stubGlobal('fetch', fetcher);
  return fetcher;
}

describe('personal AI provider compatibility', () => {
  it('omits unsupported sampling controls for Claude 5 and budgets for thinking', async () => {
    const fetcher = capture({ content: [{ type: 'thinking' }, { type: 'text', text: '{"breach":false}' }] });
    const text = await anthropic('test-key', 'claude-opus-5-5').complete({ system: 'judge', user: 'test', maxTokens: 400, temperature: 0 });
    const body = JSON.parse(fetcher.mock.calls[0][1].body);
    expect(body.max_tokens).toBe(8192);
    expect(body).not.toHaveProperty('temperature');
    expect(text).toBe('{"breach":false}');
  });

  it('keeps legacy Claude request options unchanged', async () => {
    const fetcher = capture({ content: [{ type: 'text', text: 'ok' }] });
    await anthropic('test-key', 'claude-sonnet-4-6').complete({ system: 's', user: 'u', maxTokens: 500, temperature: 0.4 });
    expect(JSON.parse(fetcher.mock.calls[0][1].body)).toMatchObject({ max_tokens: 500, temperature: 0.4 });
  });

  it('reserves GPT-5 reasoning tokens and requests JSON', async () => {
    const fetcher = capture({ choices: [{ message: { content: '{"breach":false}' } }] });
    await openaiCompatible('test-key', 'gpt-5').complete({ system: 's', user: 'u', json: true, maxTokens: 400 });
    expect(JSON.parse(fetcher.mock.calls[0][1].body)).toMatchObject({
      max_completion_tokens: 8192, reasoning_effort: 'minimal', response_format: { type: 'json_object' },
    });
  });

  it('does not add GPT-specific reasoning options to custom models', async () => {
    const fetcher = capture({ choices: [{ message: { content: 'ok' } }] });
    await openaiCompatible('test-key', 'custom-model', 'https://example.invalid/v1').complete({ system: 's', user: 'u', maxTokens: 400 });
    const body = JSON.parse(fetcher.mock.calls[0][1].body);
    expect(body.max_completion_tokens).toBe(400);
    expect(body).not.toHaveProperty('reasoning_effort');
  });

  it('rejects empty output instead of silently accepting it', async () => {
    capture({ choices: [{ message: { content: null } }] });
    await expect(openaiCompatible('test-key', 'gpt-5').complete({ system: 's', user: 'u' })).rejects.toThrow('OpenAI returned no text.');
  });

  it('does not retry permanent provider errors or expose their bodies', async () => {
    const fetcher = vi.fn().mockResolvedValue(new Response('PRIVATE_ACCOUNT_INFORMATION', { status: 401 }));
    vi.stubGlobal('fetch', fetcher);
    await expect(anthropic('test-key', 'claude-haiku-5-5').complete({ system: 's', user: 'u' })).rejects.toThrow('Anthropic request failed (HTTP 401).');
    expect(fetcher).toHaveBeenCalledTimes(1);
  });

  it('limits concurrent calls from parallel juries to two', async () => {
    let active = 0;
    let peak = 0;
    vi.stubGlobal('fetch', vi.fn(async () => {
      active++;
      peak = Math.max(peak, active);
      await new Promise(resolve => setTimeout(resolve, 10));
      active--;
      return new Response(JSON.stringify({ choices: [{ message: { content: 'ok' } }] }));
    }));
    const client = openaiCompatible('test-key', 'gpt-5');
    await Promise.all(Array.from({ length: 5 }, () => client.complete({ system: 's', user: 'u' })));
    expect(peak).toBe(2);
  });
});
