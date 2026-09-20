// Reference browser transport/monitor, NOT a payment authorization API.
// The wallet MUST supply its cryptographic receipt verifier and pinned profile.
// No keys, signing, balance crediting, funding checks or transaction broadcast.
const HASH = /^[0-9a-f]{64}$/;
const OUTPOINT = /^[0-9a-f]{64}:(0|[1-9][0-9]{0,9})$/;
const MAX_FRAME = 4096;
const MAX_PENDING = 32;

function assert(ok, message) { if (!ok) throw new Error(message); }
function exact(value, keys) {
  assert(value && typeof value === 'object' && !Array.isArray(value)
    && Object.keys(value).sort().join(',') === [...keys].sort().join(','), 'invalid message fields');
}
function sequence(n, max) { return Number.isSafeInteger(n) && n >= 0 && n <= max; }
function sameCursor(a, b) { return a && b && a.stream === b.stream && a.seq === b.seq; }
function endpoint(value) {
  const url = new URL(value);
  assert(!url.username && !url.password && !url.hash, 'URL credentials/fragments are not allowed');
  assert(url.protocol === 'wss:' || (url.protocol === 'ws:'
    && (url.hostname === '127.0.0.1' || url.hostname === '[::1]')), 'use wss or loopback ws');
  return url.href;
}

export class ReceiptMonitor extends EventTarget {
  #profile; #bonds; #relays; #verify; #WebSocket; #now; #staleMs; #retryMs;
  #evidence = new Map(); #running = false; #timer;

  constructor({ profile, bonds, relays, verifyReceipt, WebSocketImpl = globalThis.WebSocket,
    now = () => performance.now(), staleMs = 10000, reconnectMs = 1000 }) {
    super();
    assert(HASH.test(profile), 'pin the authenticated profile ID');
    assert(Array.isArray(bonds) && bonds.length >= 1 && bonds.length <= 128
      && new Set(bonds).size === bonds.length && bonds.every(b => OUTPOINT.test(b)
        && Number(b.split(':')[1]) <= 0xffffffff), 'pin 1..128 distinct bonds');
    assert(typeof verifyReceipt === 'function', 'a cryptographic receipt verifier is required');
    assert(typeof WebSocketImpl === 'function', 'WebSocket is required');
    assert(Array.isArray(relays) && relays.length >= 2 && relays.length <= 8, 'configure 2..8 relays');
    assert(Number.isFinite(staleMs) && staleMs >= 100 && Number.isFinite(reconnectMs)
      && reconnectMs >= 10, 'invalid timeouts');
    const urls = relays.map(endpoint);
    assert(new Set(urls).size === urls.length, 'relay URLs must be distinct');
    this.#profile = profile; this.#bonds = new Set(bonds); this.#verify = verifyReceipt;
    this.#WebSocket = WebSocketImpl; this.#now = now; this.#staleMs = staleMs; this.#retryMs = reconnectMs;
    this.#relays = urls.map(url => ({ url, cursor: null, through: null, caughtUp: false,
      lastMessage: -Infinity, opened: -Infinity, generation: 0, pending: 0,
      queue: Promise.resolve(), socket: null, retry: null, error: 'not started', seen: new Map() }));
  }

  start() {
    if (this.#running) return;
    this.#running = true;
    for (const relay of this.#relays) this.#connect(relay);
    // Health also checks the clock synchronously: an inactive browser tab must
    // not report a cached ready flag before its delayed interval callback runs.
    this.#timer = setInterval(() => this.checkStaleness(), Math.min(1000, this.#staleMs / 2));
  }
  stop() {
    this.#running = false; clearInterval(this.#timer);
    for (const relay of this.#relays) this.#lose(relay, 'stopped', false);
  }
  #healthy(relay) {
    const age = this.#now() - relay.lastMessage;
    return this.#running && relay.socket?.readyState === 1 && relay.caughtUp
      && relay.pending === 0 && age >= 0 && age < this.#staleMs;
  }
  health() {
    return { monitoringReady: this.#relays.every(r => this.#healthy(r)),
      relays: this.#relays.map(r => ({ url: r.url, synchronized: this.#healthy(r),
        cursor: r.cursor ? { ...r.cursor } : null, error: r.error })) };
  }
  observation(bond, txid) {
    assert(this.#bonds.has(bond) && HASH.test(txid), 'unknown bond/invalid transaction ID');
    const receipts = [...(this.#evidence.get(bond)?.values() ?? [])];
    const observedOn = this.#relays.filter(r => this.#healthy(r) && r.seen.get(bond)?.has(txid)).map(r => r.url);
    return { ...this.health(), conflicted: receipts.length > 1, observedOn,
      observedEverywhere: observedOn.length === this.#relays.length,
      // Copies keep consumers from mutating retained evidence.
      evidence: receipts.map(r => ({ ...r })) };
  }
  checkStaleness() {
    for (const relay of this.#relays) {
      if (!relay.socket) continue;
      const age = this.#now() - Math.max(relay.opened, relay.lastMessage);
      if (age < 0 || age >= this.#staleMs) {
        // A wedged verifier is a local failure, not an invitation to accumulate
        // more unbounded verification jobs on automatically reopened sockets.
        this.#lose(relay, 'stale or stalled connection', relay.pending === 0);
      }
    }
  }
  #changed() { this.dispatchEvent(new Event('change')); }
  #lose(relay, reason, retry) {
    relay.generation++;
    relay.caughtUp = false; relay.through = null; relay.pending = 0;
    relay.queue = Promise.resolve(); relay.error = reason;
    clearTimeout(relay.retry);
    const socket = relay.socket; relay.socket = null;
    try { socket?.close(); } catch { /* already closed */ }
    this.#changed();
    if (retry && this.#running) relay.retry = setTimeout(() => this.#connect(relay), this.#retryMs);
  }
  #connect(relay) {
    if (!this.#running) return;
    const generation = ++relay.generation;
    relay.opened = this.#now(); relay.lastMessage = -Infinity;
    relay.error = 'synchronizing';
    let socket;
    try { socket = new this.#WebSocket(relay.url); }
    catch { this.#lose(relay, 'connection failed', true); return; }
    relay.socket = socket;
    const current = () => this.#running && generation === relay.generation;
    socket.addEventListener('open', () => {
      if (!current()) return;
      try { socket.send(JSON.stringify({ type: 'subscribe', profile: this.#profile, cursor: relay.cursor })); }
      catch { this.#lose(relay, 'subscribe failed', true); }
    });
    socket.addEventListener('close', () => { if (current()) this.#lose(relay, 'disconnected', true); });
    socket.addEventListener('error', () => { if (current()) this.#lose(relay, 'connection failed', true); });
    socket.addEventListener('message', event => {
      if (!current()) return;
      const receivedAt = this.#now();
      if (typeof event.data !== 'string' || new TextEncoder().encode(event.data).length > MAX_FRAME
        || ++relay.pending > MAX_PENDING) {
        this.#lose(relay, 'frame/queue limit exceeded', false); return;
      }
      this.#changed(); // Do not accept while an unverified event is queued.
      relay.queue = relay.queue.then(async () => {
        if (!current()) return;
        assert(this.#now() - receivedAt < this.#staleMs, 'stale queued event');
        await this.#process(relay, JSON.parse(event.data), current);
        if (!current()) return;
        assert(this.#now() - receivedAt < this.#staleMs, 'verification timeout');
        relay.lastMessage = receivedAt; relay.pending--;
        relay.error = relay.caughtUp ? null : 'synchronizing';
        this.#changed();
      }).catch(() => {
        if (current()) this.#lose(relay, 'invalid protocol/evidence; revalidation required', false);
      });
    });
  }
  #cursor(cursor) {
    exact(cursor, ['stream', 'seq']);
    assert(HASH.test(cursor.stream) && sequence(cursor.seq, this.#bonds.size * 2), 'invalid cursor');
  }
  async #receipt(value) {
    exact(value, ['bond', 'txid', 'signature']);
    assert(this.#bonds.has(value.bond) && HASH.test(value.txid)
      && /^[0-9a-f]{128}$/.test(value.signature), 'invalid receipt');
    const copy = Object.freeze({ ...value });
    assert(await this.#verify(copy) === true, 'invalid receipt signature');
    return copy;
  }
  #remember(relay, receipt) {
    let evidence = this.#evidence.get(receipt.bond);
    if (!evidence) { evidence = new Map(); this.#evidence.set(receipt.bond, evidence); }
    if (evidence.size < 2) evidence.set(receipt.txid, receipt);
    let seen = relay.seen.get(receipt.bond);
    if (!seen) { seen = new Set(); relay.seen.set(receipt.bond, seen); }
    if (seen.size < 2) seen.add(receipt.txid);
  }
  async #process(relay, message, current) {
    switch (message?.type) {
      case 'begin': {
        exact(message, ['type', 'profile', 'stream', 'from', 'through']);
        assert(relay.through === null && message.profile === this.#profile && HASH.test(message.stream)
          && sequence(message.from, this.#bonds.size * 2) && sequence(message.through, this.#bonds.size * 2)
          && message.through >= message.from, 'invalid synchronization header');
        const cursor = { stream: message.stream, seq: message.from };
        assert(relay.cursor ? sameCursor(relay.cursor, cursor) : message.from === 0, 'stream/cursor changed');
        relay.cursor = cursor; relay.through = message.through; relay.caughtUp = false;
        break;
      }
      case 'event': {
        exact(message, ['type', 'event']);
        const event = message.event;
        exact(event, ['seq', 'receipt', 'conflict_with']);
        assert(relay.through !== null && sequence(event.seq, this.#bonds.size * 2)
          && event.seq === relay.cursor.seq + 1
          && (relay.caughtUp || event.seq <= relay.through), 'event gap');
        const receipt = await this.#receipt(event.receipt);
        const other = event.conflict_with === null ? null : await this.#receipt(event.conflict_with);
        assert(!other || (other.bond === receipt.bond && other.txid !== receipt.txid), 'invalid conflict pair');
        if (!current()) return; // Late verification after disconnect cannot advance a cursor.
        this.#remember(relay, receipt);
        if (other) this.#remember(relay, other);
        relay.cursor = { stream: relay.cursor.stream, seq: event.seq };
        break;
      }
      case 'caught_up':
        exact(message, ['type', 'cursor']); this.#cursor(message.cursor);
        assert(!relay.caughtUp && sameCursor(relay.cursor, message.cursor)
          && relay.through === message.cursor.seq, 'incomplete replay');
        relay.caughtUp = true;
        break;
      case 'heartbeat':
        exact(message, ['type', 'cursor']); this.#cursor(message.cursor);
        assert(relay.caughtUp && sameCursor(relay.cursor, message.cursor), 'heartbeat gap');
        break;
      default:
        // A read-only subscriber cannot receive legitimate publish acks.
        throw new Error('relay error/unknown message');
    }
  }
}
