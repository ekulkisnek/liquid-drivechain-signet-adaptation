// Uses two real local relay processes and Node 24's browser-compatible WebSocket.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn, execFileSync } from 'node:child_process';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { resolve, join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';
import { ReceiptMonitor } from './monitor.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
// Default-feature Cargo tests can overwrite the example at the same path.
// Select required features here so test order cannot silently change fixtures.
execFileSync('cargo', ['build', '--locked', '--features', 'relay', '--bin', 'preconf-relay',
  '--example', 'operator_vectors'], { cwd: root, stdio: 'pipe', timeout: 300000 });
const fixtures = JSON.parse(execFileSync(join(root, 'target/debug/examples/operator_vectors'), { encoding: 'utf8' }));
assert.ok(fixtures.profile_id, 'build operator_vectors with the relay feature');
const binary = join(root, 'target/debug/preconf-relay');

async function until(predicate, label) {
  const deadline = performance.now() + 10000;
  while (!predicate()) {
    assert.ok(performance.now() < deadline, `timed out: ${label}`);
    await delay(20);
  }
}
async function startRelay(dir, name, peers = [], port = 0) {
  const child = spawn(binary, [join(dir, 'profile.json'), join(dir, `${name}.jsonl`), `127.0.0.1:${port}`,
    ...peers.flatMap(p => ['--peer', p])], { stdio: ['ignore', 'pipe', 'pipe'] });
  let output = ''; let error = ''; let spawnError;
  child.stdout.on('data', b => { output += b; }); child.stderr.on('data', b => { error += b; });
  child.on('error', e => { spawnError = e; });
  const stopped = new Promise(resolve => child.once('exit', resolve));
  const stop = async () => {
    if (child.exitCode !== null || child.signalCode !== null) return;
    child.kill('SIGINT');
    const timer = setTimeout(() => child.kill('SIGKILL'), 5000);
    try { await stopped; } finally { clearTimeout(timer); }
  };
  try {
    await until(() => {
      assert.ifError(spawnError); assert.equal(child.exitCode, null, error);
      return /Listening on (127\.0\.0\.1:\d+)/.test(output);
    }, 'relay startup');
    return { url: `ws://${output.match(/Listening on (127\.0\.0\.1:\d+)/)[1]}`, stop };
  } catch (e) { await stop(); throw e; }
}
async function publisher(url) {
  const socket = new WebSocket(url); let ready = false;
  socket.addEventListener('open', () => socket.send(JSON.stringify({ type: 'subscribe', profile: fixtures.profile_id, cursor: null })));
  socket.addEventListener('message', e => { if (JSON.parse(e.data).type === 'caught_up') ready = true; });
  await until(() => ready, 'publisher sync');
  return { send: receipt => socket.send(JSON.stringify({ type: 'publish', receipt })), close: () => socket.close() };
}

test('browser transport: live peer fanout, relay restart replay, retained conflict', { timeout: 40000 }, async t => {
  const dir = await mkdtemp(join(tmpdir(), 'preconf-browser-test-'));
  const processes = []; const publishers = []; let monitor;
  t.after(async () => {
    monitor?.stop(); publishers.forEach(p => p.close());
    await Promise.all(processes.map(p => p.stop()));
    await rm(dir, { recursive: true, force: true });
  });
  await writeFile(join(dir, 'profile.json'), JSON.stringify(fixtures.profile), { mode: 0o600 });
  const a = await startRelay(dir, 'a'); processes.push(a);
  const b = await startRelay(dir, 'b', [a.url]); processes.push(b);
  // Only a fixture whitelist for transport interop. NOT a cryptographic verifier
  // for integration in a wallet; the Rust relay validates the actual signatures.
  monitor = new ReceiptMonitor({ profile: fixtures.profile_id, bonds: fixtures.profile.sessions.map(s => s.bond),
    relays: [a.url, b.url], reconnectMs: 100,
    verifyReceipt: r => fixtures.receipts.some(f => ['bond', 'txid', 'signature'].every(k => f[k] === r[k])) });
  monitor.start(); await until(() => monitor.health().monitoringReady, 'two live subscriptions');
  const sender = await publisher(a.url); publishers.push(sender);
  const [first, second] = fixtures.receipts;
  sender.send(first);
  await until(() => monitor.observation(first.bond, first.txid).observedEverywhere, 'receipt on both relays');
  await b.stop(); await until(() => !monitor.health().monitoringReady, 'disconnect disables monitor');
  sender.send(second);
  await until(() => monitor.observation(first.bond, first.txid).conflicted, 'live conflict while other relay offline');
  const resumed = await startRelay(dir, 'b', [a.url], Number(new URL(b.url).port)); processes.push(resumed);
  await until(() => monitor.health().monitoringReady && monitor.observation(second.bond, second.txid).observedEverywhere,
    'same-journal replay and peer backfill');
  assert.equal(monitor.observation(first.bond, first.txid).conflicted, true);
  assert.equal(monitor.observation(first.bond, first.txid).evidence.length, 2);
});
