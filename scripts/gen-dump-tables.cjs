#!/usr/bin/env node
/**
 * `scripts/dump-offsets.sh` 안에 임베드된 테이블(SYM/XA/AN)을
 * `src/offsets.ts` 로부터 다시 생성한다.
 *
 *   node scripts/gen-dump-tables.cjs
 *
 * dump-offsets.sh 는 게임 .so 만 있는 다른 환경(코드스페이스 등)에서 단독으로
 * 실행되므로 offsets.ts 를 읽을 수 없다. 그래서 필요한 테이블을 스크립트 안에
 * 통째로 박아두고, offsets.ts 가 바뀔 때마다 이 생성기로 갱신한다.
 */
const fs = require('fs');
const path = require('path');

const root    = path.resolve(__dirname, '..');
const tsPath  = path.join(root, 'src', 'offsets.ts');
const shPath  = path.join(root, 'scripts', 'dump-offsets.sh');

const ts = fs.readFileSync(tsPath, 'utf8');

/** `export const <name> = { ... } as const` 블록 본문을 잘라낸다. */
function block(name) {
    const i = ts.indexOf(`export const ${name}`);
    if (i < 0) throw new Error(`[gen-dump-tables] ${name} 을(를) offsets.ts 에서 찾지 못했습니다.`);
    const j = ts.indexOf('} as const', i);
    if (j < 0) throw new Error(`[gen-dump-tables] ${name} 블록의 끝을 찾지 못했습니다.`);
    return ts.slice(i, j);
}

const symbols = [...block('_symbols').matchAll(/'([^']+)':\s*"([^"]+)"/g)]
    .map(m => [m[1], m[2]]);
const xaOffset = [...block('_xaOffset').matchAll(/'([^']+)':\s*\{\s*name:\s*"([^"]+)",\s*offset:\s*(-?0x[0-9a-fA-F]+)/g)]
    .map(m => [m[1], m[2], m[3]]);
const xaPatch = [...block('_xaPatch').matchAll(/'([^']+)':\s*\{\s*on:\s*([-\d_]+),\s*off:\s*([-\d_.]+),\s*type:\s*'(\w+)'/g)]
    .map(m => [m[1], m[2].replace(/_/g, ''), m[3].replace(/_/g, ''), m[4]]);
const anOffset = [...block('_anOffset').matchAll(/"([^"]+)":\s*([^,\n]+)/g)]
    .map(m => [m[1], m[2].trim()]);

if (!symbols.length || !xaOffset.length) throw new Error('[gen-dump-tables] 테이블 파싱 실패');

// 정수/부동소수 상수를 32비트 워드(대문자 hex)로 — 스크립트가 .so 안에서
// 이 워드를 그대로 찾아 새 offset 을 제안하는 데 쓴다.
const dv = new DataView(new ArrayBuffer(4));
function word32(value, type) {
    if (type === 'f32') dv.setFloat32(0, parseFloat(value));
    else                dv.setInt32(0, parseInt(value, 10));
    return dv.getUint32(0).toString(16).toUpperCase().padStart(8, '0');
}

const patchByKey = Object.fromEntries(xaPatch.map(r => [r[0], r]));

const lines = [];
lines.push('# ----------------------------------------------------------------------------');
lines.push('#  임베드된 테이블 — src/offsets.ts 에서 생성됨');
lines.push('#  (offsets.ts 가 바뀌면 node scripts/gen-dump-tables.cjs 로 다시 생성하세요)');
lines.push('# ----------------------------------------------------------------------------');
lines.push('');
lines.push('# key|mangled');
lines.push("SYM_TABLE=$(cat <<'EOF'");
symbols.forEach(([k, n]) => lines.push(`${k}|${n}`));
lines.push('EOF');
lines.push(')');
lines.push('');
lines.push('# key|mangled|offset|offword|offdec|onword|ondec|type');
lines.push("XA_TABLE=$(cat <<'EOF'");
xaOffset.forEach(([k, n, o]) => {
    const p = patchByKey[k];
    if (!p) throw new Error(`[gen-dump-tables] _xaPatch 에 '${k}' 항목이 없습니다.`);
    lines.push([k, n, o, word32(p[2], p[3]), p[2], word32(p[1], p[3]), p[1], p[3]].join('|'));
});
lines.push('EOF');
lines.push(')');
lines.push('');
lines.push('# key|value');
lines.push("AN_TABLE=$(cat <<'EOF'");
anOffset.forEach(([k, v]) => {
    const n = Function(`return (${v})`)();   // "0x7ABE28 + 0x4" 같은 식을 평가
    lines.push(`${k}|0x${n.toString(16).toUpperCase()}`);
});
lines.push('EOF');
lines.push(')');

const BEGIN = '# >>> BEGIN GENERATED TABLES';
const END   = '# <<< END GENERATED TABLES';
const sh = fs.readFileSync(shPath, 'utf8');
const bi = sh.indexOf(BEGIN);
const ei = sh.indexOf(END);
if (bi < 0 || ei < 0) throw new Error(`[gen-dump-tables] ${shPath} 에서 생성 구간 마커를 찾지 못했습니다.`);
const head = sh.slice(0, bi);
const tail = sh.slice(ei);
const beginLine = sh.slice(bi, sh.indexOf('\n', bi) + 1);

fs.writeFileSync(shPath, head + beginLine + lines.join('\n') + '\n' + tail, 'utf8');
console.log(`[gen-dump-tables] ${path.relative(root, shPath)} 갱신: ` +
            `symbols=${symbols.length} xa=${xaOffset.length} an=${anOffset.length}`);
