/**
 * Deterministic OpenAI-compatible chat-completions server for the e2e run.
 *
 * Turn 1 (no tool result yet): answer with N calls (default 1, set through
 * `POST /__control {"calls": N}`) to the tool named by FAKE_TOOL (default
 * `e2e_fixture_echo`). Turn 2 (a tool result is present):
 * answer with `FINAL:` followed by the tool result text, so the run output
 * shows exactly what the tool pipeline returned. Every request is appended to
 * the JSONL log given as the second argument.
 *
 * usage: node e2e/fake-llm.mjs <port> <request-log.jsonl>
 */

import { createServer } from 'node:http';
import { appendFileSync } from 'node:fs';

const port = Number(process.argv[2] ?? 0);
const log = process.argv[3];
const toolName = process.env.FAKE_TOOL ?? 'e2e_fixture_echo';
const MODEL = 'fake-model';
const control = { calls: 1 };

const textOf = (content) => typeof content === 'string' ? content
  : Array.isArray(content) ? content.map((part) => part?.text ?? '').join('') : '';

function reply(body) {
  const messages = Array.isArray(body.messages) ? body.messages : [];
  const toolResults = messages.filter((m) => m.role === 'tool');
  if (toolResults.length > 0) return { content: `FINAL: ${toolResults.map((m) => textOf(m.content)).join(' | ')}` };
  const count = Math.max(1, control.calls);
  return { toolCalls: Array.from({ length: count }, (_, i) => ({ id: `call_${Date.now()}_${i}`, name: toolName, arguments: JSON.stringify({ text: 'hello-e2e' }) })) };
}

function chunk(delta, finish = null) {
  return `data: ${JSON.stringify({ id: 'chatcmpl-e2e', object: 'chat.completion.chunk', created: 0, model: MODEL,
    choices: [{ index: 0, delta, finish_reason: finish }] })}\n\n`;
}

const server = createServer((req, res) => {
  let raw = '';
  req.on('data', (d) => { raw += d; });
  req.on('end', () => {
    if (req.method === 'POST' && req.url === '/__control') {
      try { Object.assign(control, JSON.parse(raw || '{}')); } catch { /* keep */ }
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify(control));
      return;
    }
    if (req.method === 'GET' && req.url.endsWith('/models')) {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ object: 'list', data: [{ id: MODEL, object: 'model' }] }));
      return;
    }
    let body = {};
    try { body = JSON.parse(raw || '{}'); } catch { /* keep empty */ }
    const answer = reply(body);
    if (log) {
      appendFileSync(log, `${JSON.stringify({ at: new Date().toISOString(), url: req.url,
        tools: (body.tools ?? []).map((t) => t.function?.name ?? t.name), roles: (body.messages ?? []).map((m) => m.role), answer })}\n`);
    }
    const usage = { prompt_tokens: 10, completion_tokens: 5, total_tokens: 15 };
    if (body.stream) {
      res.writeHead(200, { 'content-type': 'text/event-stream', 'cache-control': 'no-cache' });
      if (answer.toolCalls) {
        res.write(chunk({ role: 'assistant', content: null, tool_calls: answer.toolCalls.map((call, index) => ({ index, id: call.id, type: 'function',
          function: { name: call.name, arguments: call.arguments } })) }));
        res.write(chunk({}, 'tool_calls'));
      } else {
        res.write(chunk({ role: 'assistant', content: answer.content }));
        res.write(chunk({}, 'stop'));
      }
      res.write(`data: ${JSON.stringify({ id: 'chatcmpl-e2e', object: 'chat.completion.chunk', created: 0, model: MODEL, choices: [], usage })}\n\n`);
      res.end('data: [DONE]\n\n');
      return;
    }
    const message = answer.toolCalls
      ? { role: 'assistant', content: null, tool_calls: answer.toolCalls.map((call) => ({ id: call.id, type: 'function', function: { name: call.name, arguments: call.arguments } })) }
      : { role: 'assistant', content: answer.content };
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ id: 'chatcmpl-e2e', object: 'chat.completion', created: 0, model: MODEL,
      choices: [{ index: 0, message, finish_reason: answer.toolCalls ? 'tool_calls' : 'stop' }], usage }));
  });
});

server.listen(port, '127.0.0.1', () => {
  process.stdout.write(`${server.address().port}\n`);
});
