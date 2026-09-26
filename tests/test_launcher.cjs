const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const { parseArgs, shellQuote } = require('../bin/vps-guardian.js');

test('strict host, user, port and missing-argument validation', () => {
  for (const args of [
    ['--host', 'example;echo bad'], ['--host', 'host', '--user', '-oProxyCommand=bad'],
    ['--host', 'host', '--port', '22junk'], ['--host', 'host', '--port', '0'],
    ['--host', 'host', '--port', '65536'], ['--host', 'host', '--key'],
    ['--host', 'host', '--unknown'], ['--host', 'host', '--remote-path', 'cmd;bad'],
    ['--host', 'host', '--remote-path', '/bin/test\nbad']
  ]) assert.throws(() => parseArgs(args));
  assert.equal(parseArgs(['root@example.org', '--port', '2222']).port, 2222);
  assert.equal(parseArgs(['--host', '2001:db8::1']).host, '2001:db8::1');
});

test('POSIX single quotes are escaped, including command substitutions', () => {
  assert.equal(shellQuote('/opt/a b/bin'), "'/opt/a b/bin'");
  assert.equal(shellQuote("/opt/a'b;$(bad)"), "'/opt/a'\\''b;$(bad)'");
});

test('remote executable is passed as quoted shell text, never raw fragments', () => {
  let captured;
  const module = { exports: {} };
  const customRequire = name => name === 'child_process'
    ? { spawn: (command, args) => { captured = { command, args }; return { on() {}, killed: false, kill() {} }; } }
    : require(name);
  customRequire.main = module;
  vm.runInNewContext(fs.readFileSync(require.resolve('../bin/vps-guardian.js'), 'utf8'), {
    module, require: customRequire,
    process: { argv: ['node', 'launcher', '--host', 'example.org', '--remote-path', '/opt/a b;$(bad)/bin'], env: {}, stderr: { write() {} }, on() {}, exit() { throw new Error('unexpected exit'); } }
  });
  assert.equal(captured.command, 'ssh');
  assert.equal(captured.args.at(-1), "env VPS_GUARDIAN_MODE=read-only VPS_GUARDIAN_TOOL_PROFILE=full '/opt/a b;$(bad)/bin'");
});
