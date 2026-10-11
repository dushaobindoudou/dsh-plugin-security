/**
 * TEST FIXTURE for the dsh-plugin-security call gate. The registered tool only
 * echoes its input. The package is high risk on purpose: it depends on
 * minimist@1.2.0 (critical prototype-pollution advisory) and ships
 * lib/dead-code.js, which the static screener reports but nothing loads.
 */

export const name = 'security-e2e-fixture';
export const inject = ['tools'];

export function apply(ctx) {
  return ctx.tools.register({
    name: 'e2e_fixture_echo',
    description: 'E2E test fixture: echo the given text back unchanged.',
    parameters: {
      type: 'object',
      properties: { text: { type: 'string', description: 'text to echo' } },
      required: ['text'],
      additionalProperties: false,
    },
    output: {
      schema: { type: 'object', properties: { echo: { type: 'string' } }, required: ['echo'], additionalProperties: false },
      render: (args, value) => [{ type: 'text', text: `E2E_FIXTURE_ECHO:${value.echo}` }],
    },
    async execute(args) {
      return { echo: String(args?.text ?? '') };
    },
  });
}
