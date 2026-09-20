import test from 'node:test';
import assert from 'node:assert/strict';
import { setImmediate as tick, setTimeout as delay } from 'node:timers/promises';
import { ReceiptMonitor } from './monitor.mjs';

const profile = 'aa'.repeat(32);
const bond = `${'44'.repeat(32)}:4`;
const first = { bond, txid: '11'.repeat(32), signature: 'ab'.repeat(64) };
const second = { bond, txid: '22'.repeat(32), signature: 'cd'.repeat(64) };
const stream = n => String(n).repeat(64);
const begin = (id, from = 0, through = 0) => ({ type: 'begin', profile, stream: stream(id), from, through });
const caught = (id, seq = 0) => ({ type: 'caught_up', cursor: { stream: stream(id), seq } });
const event = (receipt, seq = 1, conflict_with = null) => ({ type: 'event', event: { seq, receipt, conflict_with } });

function setup(t, options = {}) {
  const sockets = []; const clock = { value: 0 };
  class FakeSocket extends EventTarget {
    readyState = 0; sent = [];
    constructor(url) { super(); this.url = url; sockets.push(this); }
    open() { this.readyState = 1; this.dispatchEvent(new Event('open')); }
    send(text) { assert.equal(this.readyState, 1); this.sent.push(JSON.parse(text)); }
    close() { this.readyState = 3; this.dispatchEvent(new Event('close')); }
    message(value) { this.dispatchEvent(new MessageEvent('message', { data: JSON.stringify(value) })); }
  }
  // These are state-machine tests; cryptographic verification is exercised in
  // Rust. The stub only allows exact synthetic fixtures, never arbitrary data.
  const verifyReceipt = r => [first, second].some(f => JSON.stringify(f) === JSON.stringify(r));
  const monitor = new ReceiptMonitor({ profile, bonds: [bond], relays: ['wss://one.invalid', 'wss://two.invalid'],
    verifyReceipt, WebSocketImpl: FakeSocket, now: () => clock.value, reconnectMs: 10, ...options });
  monitor.start(); t.after(() => monitor.stop());
  sockets.forEach(s => s.open());
  return { monitor, sockets, clock };
}
async function emptySync(sockets) {
  sockets.forEach((s, i) => { s.message(begin(i + 1)); s.message(caught(i + 1)); }); await tick();
}

test('multiple persistent subscriptions require complete replay before ready', async t => {
  const { monitor, sockets } = setup(t);
  for (const s of sockets) assert.deepEqual(s.sent, [{ type: 'subscribe', profile, cursor: null }]);
  sockets.forEach((s, i) => { s.message(begin(i + 1, 0, 1)); s.message(event(first)); });
  assert.equal(monitor.health().monitoringReady, false);
  await tick(); assert.equal(monitor.health().monitoringReady, false);
  sockets[0].message(caught(1, 1)); await tick();
  assert.equal(monitor.health().monitoringReady, false);
  sockets[1].message(caught(2, 1)); await tick();
  assert.equal(monitor.health().monitoringReady, true);
  assert.equal(monitor.observation(bond, first.txid).observedEverywhere, true);
  assert.equal(monitor.observation(bond, first.txid).conflicted, false);
});

test('conflicts are detected across relays even if neither flags its receipt', async t => {
  const { monitor, sockets } = setup(t);
  [first, second].forEach((r, i) => {
    sockets[i].message(begin(i + 1, 0, 1)); sockets[i].message(event(r)); sockets[i].message(caught(i + 1, 1));
  });
  await tick();
  const result = monitor.observation(bond, first.txid);
  assert.equal(result.conflicted, true); assert.equal(result.evidence.length, 2);
  assert.equal(result.observedEverywhere, false);
  result.evidence[0].txid = 'ff'.repeat(32);
  assert.equal(monitor.observation(bond, first.txid).evidence[0].txid, first.txid);
  sockets[1].close(); assert.equal(monitor.health().monitoringReady, false);
  assert.equal(monitor.observation(bond, first.txid).conflicted, true);
});

test('disconnect pauses readiness and resumes from the last verified cursor', async t => {
  const { monitor, sockets } = setup(t);
  await emptySync(sockets); sockets[0].message(event(first)); await tick();
  sockets[0].close(); assert.equal(monitor.health().monitoringReady, false);
  await delay(25);
  const resumed = sockets[2]; resumed.open();
  assert.deepEqual(resumed.sent[0].cursor, { stream: stream(1), seq: 1 });
  resumed.message(begin(1, 1, 2)); resumed.message(event(second, 2, first));
  await tick(); assert.equal(monitor.health().monitoringReady, false);
  resumed.message(caught(1, 2)); await tick();
  assert.equal(monitor.health().monitoringReady, true);
  assert.equal(monitor.observation(bond, first.txid).conflicted, true);
});

test('stale state is rejected synchronously, even before browser timers run', async t => {
  const { monitor, sockets, clock } = setup(t);
  await emptySync(sockets); assert.equal(monitor.health().monitoringReady, true);
  clock.value = 10001;
  assert.equal(monitor.health().monitoringReady, false);
  monitor.checkStaleness(); assert.equal(sockets[0].readyState, 3);
});

test('gaps, changed stream/profile, early catch-up and forged evidence fail closed', async t => {
  for (const bad of [
    event(first, 2),
    { type: 'heartbeat', cursor: { stream: stream(1), seq: 1 } },
    begin(1),
    { type: 'error', reason: 'journal gap' },
    event({ ...first, signature: '00'.repeat(64) }),
    event({ ...first, bond: `${'99'.repeat(32)}:0` }),
    event(second, 1, { ...first, signature: '00'.repeat(64) }),
    { type: 'event', event: { ...event(first).event, extra: true } },
  ]) {
    const { monitor, sockets } = setup(t);
    await emptySync(sockets); sockets[0].message(bad); await tick();
    assert.equal(monitor.health().monitoringReady, false);
    assert.equal(sockets[0].readyState, 3);
    monitor.stop();
  }
  for (const bad of [{ ...begin(1), profile: 'ff'.repeat(32) }, begin(1, 1, 1)]) {
    const { monitor, sockets } = setup(t);
    sockets[0].message(bad); await tick();
    assert.equal(sockets[0].readyState, 3); assert.equal(monitor.health().monitoringReady, false);
    monitor.stop();
  }
  const { monitor, sockets } = setup(t);
  sockets[0].message(begin(1, 0, 1)); sockets[0].message(caught(1, 1)); await tick();
  assert.equal(monitor.health().monitoringReady, false); assert.equal(sockets[0].readyState, 3);
});

test('unverified queued evidence immediately disables ready; late results cannot restore it', async t => {
  let resolveVerification;
  const { monitor, sockets } = setup(t, { verifyReceipt: () => new Promise(r => { resolveVerification = r; }) });
  await emptySync(sockets); assert.equal(monitor.health().monitoringReady, true);
  sockets[0].message(event(first)); assert.equal(monitor.health().monitoringReady, false);
  await tick(); sockets[0].close(); resolveVerification(true); await tick();
  assert.equal(monitor.health().relays[0].cursor.seq, 0);
  assert.deepEqual(monitor.observation(bond, first.txid).evidence, []);
  assert.equal(monitor.health().monitoringReady, false);
});

test('suspended event processing cannot make old data fresh', async t => {
  const { monitor, sockets, clock } = setup(t);
  await emptySync(sockets);
  sockets[0].message({ type: 'heartbeat', cursor: { stream: stream(1), seq: 0 } });
  clock.value = 10001; await tick();
  assert.equal(monitor.health().monitoringReady, false); assert.equal(sockets[0].readyState, 3);
});

test('oversized frames, binary frames and excess queue depth are rejected', async t => {
  for (const data of ['x'.repeat(4097), new Uint8Array([1])]) {
    const { monitor, sockets } = setup(t); await emptySync(sockets);
    sockets[0].dispatchEvent(new MessageEvent('message', { data }));
    assert.equal(sockets[0].readyState, 3); assert.equal(monitor.health().monitoringReady, false);
    monitor.stop();
  }
  const { monitor, sockets } = setup(t); await emptySync(sockets);
  for (let i = 0; i < 33; i++) sockets[0].message({ type: 'heartbeat', cursor: { stream: stream(1), seq: 0 } });
  assert.equal(sockets[0].readyState, 3); assert.equal(monitor.health().monitoringReady, false);
});

test('configuration requires pinned bonds, multiple TLS endpoints and a verifier', () => {
  const args = { profile, bonds: [bond], relays: ['wss://one.invalid', 'wss://two.invalid'], verifyReceipt: () => false };
  for (const override of [{ verifyReceipt: undefined }, { relays: ['wss://one.invalid'] },
    { relays: ['wss://one.invalid', 'wss://one.invalid/'] },
    { relays: ['ws://remote.invalid', 'wss://one.invalid'] },
    { relays: ['wss://user:password@one.invalid', 'wss://two.invalid'] },
    { bonds: [] }, { bonds: [bond, bond] }, { profile: 'untrusted' }]) {
    assert.throws(() => new ReceiptMonitor({ ...args, ...override }));
  }
});
