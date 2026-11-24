// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
// Exercise the actual shipped HTML offline, including its embedded compiler.
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync } from 'node:fs';
import { gunzipSync } from 'node:zlib';
import { runInThisContext } from 'node:vm';

const atlasURL = new URL('../../Docs/RoutingAtlas.html', import.meta.url);
let html = readFileSync(atlasURL, 'utf8');
const scripts = Array.from(html.matchAll(/<script([^>]*)>([\s\S]*?)<\/script>/g),
    ([, attributes, source]) => ({ attributes, source }));
const runtime = scripts.find(script => script.source.includes('globalThis.Go = class'));
const binary = scripts.find(script => script.attributes.includes('id="routing-wasm"'));
const examples = scripts.find(script => script.source.includes('const routingPlaybooks='));
assert.ok(runtime && binary && examples, 'Missing runtime or playbooks in the routing atlas');
runInThisContext(runtime.source);
const go = new globalThis.Go();
const bytes = gunzipSync(Buffer.from(binary.source.trim(), 'base64'));
const { instance } = await WebAssembly.instantiate(bytes, go.importObject);
const ready = new Promise(resolve => { globalThis.simpleVPNRulesBooted = resolve; });
void go.run(instance);
await ready;
const catalog = JSON.parse(globalThis.simpleVPNRulesCatalog);
const adapters = JSON.parse(globalThis.simpleVPNRoutingAdapters);
const verifiedAdapters = JSON.parse(readFileSync(new URL('../../Vendor/proxy-engine/src/routelang/catalog/adapters.json', import.meta.url), 'utf8'));
assert.deepEqual(adapters,verifiedAdapters,'Embedded adapter capabilities must match native preflight');
assert.ok(!catalog['l2tp.state'].packet && catalog['l2tp.state'].live === 'simulation','Exported L2TP has no observed session in the app');
const playbooks = runInThisContext(examples.source + '\naddProtocolExamples(JSON.parse(simpleVPNRulesCatalog));routingPlaybooks');
const replay = (book, events = book.events) => JSON.parse(globalThis.simpleVPNRulesRun(
    JSON.stringify({ source: book.source, events, tableJSON: book.tables })));
for (const book of playbooks) {
    const result = replay(book);
    assert.equal(result.ok, true, book.title + ' · ' + result.error);
    assert.equal(result.steps.length, book.events.length, book.title);
    for (const step of result.steps) {
        assert.equal(step.error, undefined, book.title + ' · ' + step.error);
    }
}
const presence = replay(playbooks.find(p => p.id === 'presence'));
assert.equal(presence.steps[0].trace.filter(t => t.lookup && t.taken).length, 3);
assert.equal(presence.steps[0].after['dns.rd'], false);
assert.equal(presence.steps[0].after['ip.dscp'], 0);
assert.ok(presence.steps[1].trace.some(t => t.lookup && !t.taken));
const curlBook = playbooks.find(p => p.id === 'curl-context');
const curl = replay(curlBook);
assert.equal(curl.steps[0].actions[0].args[0], 'work');
assert.ok(curl.steps.every(step => step.event === 'socket.open'));
assert.deepEqual(curl.steps.map(step => step.dropped), [false, true, true, true, true]);
assert.equal(curl.steps[3].before['process.signature_verified'], false);
assert.equal(curl.steps[4].before['socket.remote_address'], '203.0.113.15');
const missingProxyEvidence = structuredClone(curlBook.events[0]);
delete missingProxyEvidence.fields['process.proxy_endpoint_matched'];
const unavailable = replay(curlBook, [missingProxyEvidence]).steps[0];
assert.equal(unavailable.dropped, true);
assert.match(unavailable.error, /missing or invalid field "process\.proxy_endpoint_matched"/);
assert.deepEqual(unavailable.actions, []);

// Exercise the general and refined subscriptions through the embedded compiler,
// including the opposite endpoint roles of a listener on the Mac.
const passiveServer = playbooks.find(book => book.id === 'laptop-passive');
const session = replay(passiveServer);
assert.deepEqual(session.steps[2].dispatched, ['ftp.command', 'ftp.command.passive']);
assert.deepEqual(session.steps[2].matched, ['any_command','passive']);
assert.equal(session.steps[2].before['ip.dst'], session.steps[2].before['ip.server_address']);
assert.equal(session.steps[3].before['ip.src'], session.steps[2].before['ip.server_address']);
assert.deepEqual(session.steps[2].actions.filter(action=>action.name==='session.expect'), []);
assert.deepEqual(session.steps[4].actions.find(action=>action.name==='session.expect')?.args, ['10.80.0.2',50010,30]);
for (const command of ['PASV','EPSV','NOOP']) {
    const input = structuredClone(passiveServer.events[2]);
    input.fields['ftp.command'] = command;
    const step = replay(passiveServer,[input]).steps[0];
    assert.deepEqual(step.dispatched,command==='NOOP'?['ftp.command']:['ftp.command','ftp.command.passive']);
}
const rejected = structuredClone(passiveServer.events[2]);
rejected.fields['flow.member']='other';
const denied = replay(passiveServer,[rejected]).steps[0];
assert.equal(denied.dropped,true);
assert.deepEqual(denied.matched,['any_command']);
const opaque = replay(playbooks.find(book=>book.id==='ftp-opaque'));
assert.deepEqual(opaque.steps.flatMap(step=>step.matched), ['hello','bytes_seen']);
assert.equal(opaque.counters.find(counter=>counter.id==='passive')?.events,0);

// Verify the user-facing documentation against the compiler embedded in this file.
const documentedEvents = [...html.matchAll(/data-event-name="([^"]+)"/g)].map(m => m[1]);
assert.deepEqual(documentedEvents.sort(), Object.keys(catalog).sort(), 'Lifecycle event coverage');
const fields = new Set(Object.values(catalog).flatMap(e => Object.keys(e.fields)));
const documentedFields = [...html.matchAll(/data-api-field="([^"]+)"/g)].map(m => m[1]);
assert.deepEqual(documentedFields.sort(), [...fields].sort(), 'Manual field coverage');
// Publish each field's event and adapter availability directly from the same
// schemas used for live compilation. Keep these readable without JavaScript.
const escapeHTML = value => String(value).replace(/[&<>"']/g, c => ({
    '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;'
})[c]);
const adapterNames = new Map(adapters.map(adapter => [adapter.id, adapter.name]));
function fieldScopes(field) {
    const groups = new Map();
    let count = 0;
    for (const [event, schema] of Object.entries(catalog).sort(([a], [b]) => a.localeCompare(b, 'en'))) {
        const entry = schema.fields[field];
        if (!entry) continue;
        count++;
        assert.ok(Object.hasOwn(entry, 'liveAdapters'), 'Compiler inventory lacks adapter ownership');
        const owners = entry.liveAdapters || [];
        const mode = owners.length > 2 ? 'packet adapters and replay' :
            owners.length ? owners.map(id => adapterNames.get(id)).join(', ') + ' and replay' : 'offline replay';
        const label = (entry.writable ? 'Read and write' : 'Read') + ' · ' + mode;
        const detail = [schema.boundary, schema.description, ...owners.map(id => adapterNames.get(id))].join(' · ');
        const link = '<a data-atlas-play="' + escapeHTML(event) + '" href="#rich-playground" title="' +
            escapeHTML(detail) + '">' + escapeHTML(event) + '</a>';
        if (!groups.has(label)) groups.set(label, []);
        groups.get(label).push(link);
    }
    return '<details class="api-domains"><summary>' + count + ' event scope' + (count === 1 ? '' : 's') +
        '</summary><div>' + [...groups].map(([label, links]) => '<p><b>' + escapeHTML(label) + '</b><br>' +
            links.join(' · ') + '</p>').join('') + '</div></details>';
}
const refreshed = html.replace(/(<article\b[^>]*data-api-field="([^"]+)"[^>]*>)([\s\S]*?)(<\/article>)/g,
    (_, open, field, body, close) => open + body.replace(/<details class="api-domains">[\s\S]*?<\/details>/g, '') +
        fieldScopes(field) + close);
if (process.argv.includes('--refresh-manual')) {
    html = refreshed;
    writeFileSync(atlasURL, html);
} else {
    assert.ok(html === refreshed, 'Field scopes differ from the compiler. Run check-atlas.mjs --refresh-manual');
}
for (const [id, values] of [['llvm-office', [15, 11, 'drop']], ['llvm-mail', ['pass', 'drop']], ['llvm-dscp', [16, 40, 40]]]) {
    const book = playbooks.find(book => book.id === id);
    const source = readFileSync(new URL('../../Vendor/routing-core/policies/' + id.slice(5) + '.route', import.meta.url), 'utf8');
    assert.equal(book.source.trim(), source.trim(), id + ' matches the bundled native policy');
    assert.deepEqual(replay(book).steps.map(step => step.dropped ? 'drop' : step.after['ip.dscp'] ?? 'pass'), values, id);
}
const actions = Object.entries(catalog).flatMap(([event, schema]) =>
    Object.keys(schema.actions || {}).map(name => [name, event]));
const actionContexts = new Map(actions);
const namespaces = new Set([...fields, ...actionContexts.keys()].map(name => name.split('.')[0]));
const documentedObjects = [...html.matchAll(/data-api-namespace="([^"]+)"/g)].map(m => m[1]);
assert.deepEqual(documentedObjects.sort(), [...namespaces].sort(), 'Manual object coverage');
const functions = new Set([...JSON.parse(globalThis.simpleVPNRulesFunctions),
    ...actionContexts.keys(), 'lookup', 'match', 'count', 'drop']);
const snippets = [...html.matchAll(/<article\b[^>]*data-api-function="([^"]+)"[^>]*>[\s\S]*?<pre[^>]*><code>([\s\S]*?)<\/code><\/pre>/g)];
assert.deepEqual(snippets.map(m => m[1]).sort(), [...functions].sort(), 'Manual function coverage');
const entities = {'&lt;':'<', '&gt;':'>', '&quot;':'"', '&#x27;':"'", '&amp;':'&'};
for (const [, name, encoded] of snippets) {
    const snippet = encoded.replace(/&(?:lt|gt|quot|#x27|amp);/g, token => entities[token]);
    const exampleEvent = snippet.match(/\bon\s+\w+\s*:\s*(\w+(?:\.\w+)+)/)?.[1];
    const event = exampleEvent || actionContexts.get(name) || 'ip.packet';
    const source = exampleEvent ? snippet : 'on example: ' + event + ' {\n' + snippet + '\n}';
    const input = event === 'ftp.command.passive' ? {event:'ftp.command',fields:{'ftp.command':'PASV'}} : {event,fields:{}};
    const result = replay({source, tables: {}, events: [input]});
    assert.equal(result.ok, true, name + ' · ' + result.error);
    assert.equal(result.steps[0].error, undefined, name);
}
// Cross-check the diagram labels against the actual compiler and session simulator.
const valuesOf = attribute => [...html.matchAll(new RegExp(attribute + '="([^"]+)"', 'g'))].map(match => match[1]);
const sameNames = (actual, expected, label) => assert.deepEqual([...actual].sort(), [...expected].sort(), label);
sameNames(valuesOf('data-layer-event'), Object.keys(catalog), 'Typed events in the layer map');
sameNames(valuesOf('data-layer-legacy'), valuesOf('data-legacy-event'), 'Compact hooks in the layer map');
sameNames(valuesOf('data-layer-namespace'), namespaces, 'Objects in the layer map');
const layerIDs = new Set(valuesOf('data-layer-detail'));
for (const ids of valuesOf('data-layer-ids')) {
    for (const id of ids.split(' ')) assert.ok(layerIDs.has(id), 'Layer drill-down ' + id);
}
const simulator = scripts.find(script => script.source.includes('globalThis.RoutingLab='));
assert.ok(simulator, 'Embedded session simulator');
runInThisContext(simulator.source);
const timelineNames = new Set();
for (const scenario of RoutingLab.scenarios) {
    const trace = RoutingLab.run(scenario.id, RoutingLab.compile(scenario.source));
    for (const step of trace.steps) {
        for (const name of step.event.split(' + ')) timelineNames.add(name);
    }
}
sameNames(valuesOf('data-layer-step'), timelineNames, 'Every session event emitted by the simulator has a layer');
const sequenceScript = scripts.find(script => script.source.includes('const sequenceEvents ='));
const sequenceDeclarations = sequenceScript.source.match(/const sequenceEvents = (\{[\s\S]*?\n  \});/);
const sequenceEvents = runInThisContext('(' + sequenceDeclarations[1] + ')');
sameNames(Object.keys(sequenceEvents), Object.keys(catalog), 'Packet sequence observation points');
const describeSource = sequenceScript.source.match(/  function describeSequence\(input, step\) \{[\s\S]*?\n  \}/)[0];
const describe = runInThisContext('((sequenceEvents,scalar) => { ' + describeSource + '; return describeSequence; })')(sequenceEvents, String);
for (const book of playbooks) {
    const result = replay(book);
    book.events.forEach((input,i) => {
        const step = result.steps[i], row = describe(input, step);
        assert.ok(['left','right','local'].includes(row.leg), book.title);
        assert.ok(row.label.length && row.outcome.includes(step.error ? 'Evaluation failed' : step.dropped ? 'Dropped' : 'Continued'), book.title);
    });
}
assert.equal(describe({event:'ftp.data_offer',fields:{'ftp.mode':'active'}}).leg, 'left');
assert.equal(describe({event:'ftp.data_offer',fields:{'ftp.mode':'passive'}}).leg, 'right');
assert.equal(describe({event:'tcp.data',fields:{}}).leg, 'local');
assert.equal(describe({event:'tls.backend_connect'}).leg, 'local');
sameNames(valuesOf('data-traffic-sequence'), [...html.matchAll(/<article class="case" id="([^"]+)"/g)].map(match => match[1]), 'Traffic path sequences');
// Keep the design directory linked to the real catalog while leaving proposed
// names out of the compiler. Check message completion at every fixture split.
const cards=[...html.matchAll(/<details class="pd-card" data-protocol-entry="([^"]+)"[^>]*>([\s\S]*?)<\/details>/g)];
const directoryNames=cards.map(([,name])=>name);
assert.equal(new Set(directoryNames).size,cards.length,'Unique protocol entries');
for (const name of ['HTTP/2','HTTP/3','QUIC','gRPC','TLS','STUN · binding and consent checks','SSH remote forwarding','FTP · passive data']) {
    assert.ok(directoryNames.includes(name),'Protocol design for '+name);
}
for(const [,name,body] of cards) {
    for(const label of ['Stack','Wire messages or local signals','When events fire','Event vocabulary','Object field examples','Actions at the owner','Visibility and limits']) {
        assert.ok(body.includes('<dt>'+label+'</dt>'),name+' · '+label);
    }
    for(const [,hook] of body.matchAll(/data-atlas-event="([^"]+)"/g)) assert.ok(catalog[hook],name+' · '+hook);
    for(const [,field] of body.matchAll(/data-atlas-field="([^"]+)"/g)) assert.ok(fields.has(field),name+' · '+field);
}
const framingSource=scripts.find(script=>script.source.includes('function grpcFramingTrace(')).source;
const frame=runInThisContext('('+framingSource.match(/function grpcFramingTrace\([\s\S]*?\n  \}/)[0]+')');
for(let size=1;size<=20;size++) {
    for(const [ending,n,outcome] of [['complete',3,'RPC completed'],['error',3,'RPC error'],['truncated',2,'Truncated message'],['reset',1,'Stream reset']]) {
        const trace=frame(size,ending);
        assert.deepEqual(trace.rows.flatMap(r=>r.events),Array.from({length:n},(_,i)=>i+1),ending+' · '+size+' bytes');
        assert.equal(trace.completed,n);
        assert.ok(trace.outcome.startsWith(outcome));
    }
}
console.log(`${playbooks.length} playbooks, ${documentedEvents.length} lifecycle events, ${documentedFields.length} fields and ${snippets.length} manual examples, ${cards.length} protocol entries and 80 gRPC framing cases passed.`);
