# dsh-security-e2e-fixture

Test fixture for the dsh-plugin-security end-to-end test. Do not publish.

- `e2e_fixture_echo` echoes its input; nothing else runs.
- `minimist@1.2.0` carries a critical advisory, so the gate classifies the plugin as high risk.
- `lib/dead-code.js` holds risky-looking shapes for the static screener; nothing imports it.
