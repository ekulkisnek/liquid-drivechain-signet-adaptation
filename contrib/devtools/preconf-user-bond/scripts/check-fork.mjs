// Build and exercise the actual pinned fork interpreter without touching a node.
// Usage: node scripts/check-fork.mjs /path/to/node [vectors|operator_vectors]
import { spawnSync } from 'node:child_process';
import { mkdirSync, realpathSync } from 'node:fs';
import { dirname, resolve, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import assert from 'node:assert/strict';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
if (process.argv.length < 3 || process.argv.length > 4) throw new Error('Pass node checkout and optional fixture example');
const example = process.argv[3] ?? 'vectors';
assert.ok(['vectors', 'operator_vectors'].includes(example), 'unknown fixture example');
const node = realpathSync(process.argv[2]);
const expected = '4041a8ba5d9c0870dbe22c188bce28410c10348a';
function run(command, args, options = {}) {
  const r = spawnSync(command, args, { cwd: root, encoding: 'utf8', maxBuffer: 8 * 1024 * 1024, ...options });
  if (r.error || r.status !== 0) throw new Error(`${command} failed: ${r.error ?? r.stderr ?? r.status}`);
  return r.stdout;
}
assert.equal(
  run('git', ['-C', node, 'rev-parse', 'HEAD:src/simplicity']).trim(),
  run('git', ['-C', node, 'rev-parse', expected + ':src/simplicity']).trim(),
  'fork interpreter differs from the pinned baseline',
);
run('git', ['-C', node, 'diff', '--exit-code', 'HEAD', '--', 'src/simplicity']);
const target = join(root, 'target', 'fork-vm');
mkdirSync(target, { recursive: true });
const sources = ['bitstream','cmr','dag','deserialize','eval','frame','jets','jets-secp256k1',
  'rsort','sha256','type','typeInference','elements/env','elements/exec','elements/ops',
  'elements/elementsJets','elements/primitive','elements/cmr','elements/txEnv'];
const executable = join(target, 'verify');
run('cc', ['-std=c11','-O2','-DPRODUCTION', '-I',join(node,'src/simplicity/include'),
  join(root,'tests/fork_vm.c'), ...sources.map(s => join(node, 'src/simplicity', `${s}.c`)),
  '-o', executable]);
const fixtures = JSON.parse(run('cargo', ['run', '--locked', '--quiet', '--example', example]));

const u32 = n => { const b = Buffer.alloc(4); b.writeUInt32LE(n); return b; };
const blob = h => {
  assert.match(h, /^(?:[0-9a-f]{2})*$/);
  const b = Buffer.from(h, 'hex'); return Buffer.concat([u32(b.length), b]);
};
function encode(f) {
  const chunks = [f.program, f.witness, f.cmr, f.control, f.genesis, f.txid].map(blob);
  chunks.push(u32(f.version), u32(f.lock_time), u32(f.inputs.length));
  for (const i of f.inputs) chunks.push(blob(i.txid), u32(i.vout), u32(i.sequence), blob(i.asset), blob(i.value), blob(i.script));
  chunks.push(u32(f.outputs.length));
  for (const o of f.outputs) chunks.push(blob(o.asset), blob(o.value), blob(o.script));
  return Buffer.concat(chunks);
}
let count = 0;
function check(f, pass, label) {
  const r = JSON.parse(run(executable, [], {input: encode(f)}));
  assert.equal(r.error === 0, pass, `${label}: ${JSON.stringify(r)}`);
  console.log(`PASS ${label} (interpreter=${r.error}, budget=${r.budget} WU)`); count++;
}
for (const f of fixtures.vectors) check(f, true, f.name);
const penalty = fixtures.vectors[0];
for (const [name, mutate] of [
  ['corrupted evidence', f => { f.witness = f.witness.slice(0,-2) + (f.witness.endsWith('00') ? '01' : '00'); }],
  ['wrong network', f => { f.genesis = '77'.repeat(32); }],
  ['another bond', f => { f.inputs[0].vout++; }],
  ['diverted penalty', f => { f.outputs[0].script = '51'; }],
  ['partial penalty', f => { f.outputs[0].value = '010000000000000001'; }],
  ['wrong penalty asset', f => { f.outputs[0].asset = '01' + '99'.repeat(32); }],
  ['extra output', f => { f.outputs.push(structuredClone(f.outputs[0])); }],
  ['extra input', f => { f.inputs.push(structuredClone(f.inputs[0])); }],
]) {
  const f = structuredClone(penalty); mutate(f); check(f, false, name);
}
for (const f0 of fixtures.vectors.slice(1)) {
  const f = structuredClone(f0); f.lock_time = 1009; check(f, false, `${f.name}: early release`);
  const final = structuredClone(f0); final.inputs[0].sequence = 0xffffffff;
  check(final, false, `${final.name}: disabled locktime`);
}
console.log(`${count} pinned-fork interpreter checks passed. No full-node or live-network test was performed.`);
