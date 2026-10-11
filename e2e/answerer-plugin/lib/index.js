/**
 * TEST FIXTURE: answers the dsh-plugin-security gate question on the real
 * `user-questions/request` waterfall with the label in E2E_ANSWER, and logs
 * every gate question it sees to E2E_QUESTION_LOG. Without E2E_ANSWER it
 * delegates, so the host behaves as if no client could answer.
 */

import { appendFileSync } from 'node:fs';

export const name = 'security-e2e-answerer';
export const inject = [];

const GATE_QUESTION = 'plugin-security-gate';

export function apply(ctx) {
  ctx.on('user-questions/request', async (request, next) => {
    const question = request?.questions?.find((q) => q.id === GATE_QUESTION);
    if (question === undefined) return next();
    if (process.env.E2E_QUESTION_LOG) {
      appendFileSync(process.env.E2E_QUESTION_LOG, `${JSON.stringify({ hasAgent: request.agent !== undefined, question })}\n`);
    }
    const label = process.env.E2E_ANSWER;
    if (!label) return next();
    return { answers: [{ id: GATE_QUESTION, selected: [label] }] };
  });
}
