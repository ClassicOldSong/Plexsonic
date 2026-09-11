import assert from 'node:assert/strict';
import { execFile, execFileSync } from 'node:child_process';
import { EventEmitter, once } from 'node:events';
import fs from 'node:fs/promises';
import { get } from 'node:http';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import test from 'node:test';
import { createFixture } from './helpers/server.js';

for (const mode of ['cold', 'cached', 'same-source']) {
  test(`overlapping ${mode} MP3 streams isolate successor and seek cancellation`, { timeout: 30000 }, async (t) => {
    const duration = 60;
    const source = execFileSync('ffmpeg', [
      '-v', 'error', '-f', 'lavfi', '-i', `anoisesrc=sample_rate=44100:duration=${duration}:seed=1`,
      '-ac', '2', '-c:a', 'pcm_s16le', '-f', 'wav', 'pipe:1',
    ], { maxBuffer: 16 * 1024 * 1024 });
    await fs.mkdir('data', { recursive: true });
    const cacheRoot = await fs.mkdtemp(path.resolve('data/audio-overlap-test-'));
    t.after(() => fs.rm(cacheRoot, { recursive: true, force: true }));
    const events = new EventEmitter();
    const held = [];
    let hold = false;
    let sourceRequests = 0;
    const { app, params } = await createFixture(t, (request, response) => {
      const url = new URL(request.url, 'http://fixture');
      if (url.pathname.startsWith('/library/metadata/')) {
        const id = url.pathname.split('/').at(-1);
        response.end(JSON.stringify({ MediaContainer: { Metadata: [{
          type: 'track', ratingKey: id, duration: duration * 1000,
          Media: [{ container: 'wav', Part: [{ key: `/audio/${id}`, size: source.length }] }],
        }] } }));
      } else if (url.pathname.startsWith('/audio/')) {
        sourceRequests++;
        response.writeHead(200, { 'content-length': source.length });
        if (!hold) { response.end(source); return; }
        const entry = { response, closed: once(response, 'close') };
        held.push(entry);
        // Keep the upstream and FFmpeg alive after enough PCM to begin output.
        // A successor's cancellation must not retire this producer or its cache.
        response.write(source.subarray(0, 2 * 1024 * 1024));
        events.emit('source', entry);
      } else response.end('{}');
    }, { transcodeCachePath: cacheRoot });
    await app.listen({ host: '127.0.0.1', port: 0 });
    const origin = `http://127.0.0.1:${app.server.address().port}`;
    const stream = (id, extra = {}) => `${origin}/rest/stream?${new URLSearchParams({ ...params, id, format: 'mp3', ...extra })}`;
    const open = (url, headers = {}) => new Promise((resolve, reject) => {
      get(url, { headers, signal: t.signal }, resolve).on('error', reject);
    });
    let warm;
    if (mode === 'cached') warm = await (await fetch(stream('1'))).arrayBuffer();
    hold = true;
    const active = await open(stream('1'), { range: 'bytes=0-' });
    assert.equal(active.statusCode, mode === 'cached' ? 206 : 200);
    active.pause();
    // Drain A slowly while every other request below uses the same account/client.
    const activeBytes = (async () => {
      const chunks = [];
      await delay(150);
      for await (const chunk of active) { chunks.push(chunk); await delay(5); }
      assert.equal(active.complete, true, 'A must reach a complete HTTP message');
      return Buffer.concat(chunks);
    })();
    activeBytes.catch(() => {});
    const activeSource = mode === 'cached' ? null : held[0];

    // Native probing asks for a range even when the cold transcode is sequential.
    const successorId = mode === 'same-source' ? '1' : '2';
    const nextStarted = once(events, 'source', { signal: t.signal });
    const successor = await open(stream(successorId), { range: 'bytes=0-1' });
    const [nextSource] = await nextStarted;
    assert.equal(successor.statusCode, 200);
    assert.equal(successor.headers['accept-ranges'], 'none');
    successor.destroy();
    await nextSource.closed;
    if (activeSource) assert.equal(activeSource.response.destroyed, false, 'abandoning B must leave A upstream alive');

    // Retire a late seek before it can produce any response headers/audio.
    const seekStarted = once(events, 'source', { signal: t.signal });
    const seek = get(stream('3', { timeOffset: '45' }), { signal: t.signal });
    const seekFailed = once(seek, 'error');
    const [seekSource] = await seekStarted;
    seek.destroy(new Error('seek superseded'));
    await seekFailed;
    await seekSource.closed;
    if (activeSource) assert.equal(activeSource.response.destroyed, false, 'abandoning a seek must leave A upstream alive');

    // A replacement B completes while A is still held. Both must be independent.
    hold = false;
    const replacement = await fetch(stream('2'), { signal: t.signal });
    const replacementBytes = Buffer.from(await replacement.arrayBuffer());
    if (activeSource) {
      assert.equal(activeSource.response.destroyed, false, 'finishing B must leave A upstream alive');
      activeSource.response.end(source.subarray(2 * 1024 * 1024));
    }
    const streamed = await activeBytes;
    if (warm) assert.deepEqual(streamed, Buffer.from(warm));
    for (const bytes of [streamed, replacementBytes]) {
      const pcm = execFileSync('ffmpeg', ['-v', 'error', '-i', 'pipe:0', '-f', 's16le', 'pipe:1'], {
        input: bytes, maxBuffer: 16 * 1024 * 1024,
      });
      const expected = duration * 44100 * 4;
      assert.ok(pcm.length >= expected && pcm.length < expected + 2304 * 4, `full track samples: ${pcm.length}`);
    }
    const beforeReplay = sourceRequests;
    const replay = await fetch(stream('1'), { signal: t.signal });
    assert.equal(Number(replay.headers.get('content-length')), streamed.length);
    assert.deepEqual(Buffer.from(await replay.arrayBuffer()), streamed);
    assert.equal(sourceRequests, beforeReplay, 'A publishes a full cache despite unrelated canceled writes');
    const range = await fetch(stream('1'), { headers: { range: 'bytes=17-63' }, signal: t.signal });
    assert.equal(range.status, 206);
    assert.deepEqual(Buffer.from(await range.arrayBuffer()), streamed.subarray(17, 64));
  });
}

for (const holdMs of [0, 35000]) {
test(holdMs ? 'Resonance gapless streams survive consumer backpressure beyond the default HTTP idle timeout'
  : 'Resonance gapless playback overlaps real Plexsonic cold and cached MP3 transcodes', {
  skip: !process.env.RESONANCE_BIN || !process.env.RESONANCE_PLAYER_MODULE,
  timeout: 90000,
}, async (t) => {
  const source = execFileSync('ffmpeg', [
    '-v', 'error', '-f', 'lavfi', '-i', 'anoisesrc=sample_rate=44100:duration=60:seed=1',
    '-ac', '2', '-c:a', 'pcm_s16le', '-f', 'wav', 'pipe:1',
  ], { maxBuffer: 16 * 1024 * 1024 });
  await fs.mkdir('data', { recursive: true });
  const cacheRoot = await fs.mkdtemp(path.resolve('data/audio-native-overlap-test-'));
  t.after(() => fs.rm(cacheRoot, { recursive: true, force: true }));
  let heldId = '';
  let held = [];
  const { app, params } = await createFixture(t, (request, response) => {
    const url = new URL(request.url, 'http://fixture');
    const id = url.pathname.split('/').at(-1);
    if (url.pathname.startsWith('/library/metadata/')) {
      response.end(JSON.stringify({ MediaContainer: { Metadata: [{
        type: 'track', ratingKey: id, duration: 60000,
        Media: [{ container: 'wav', Part: [{ key: `/audio/${id}`, size: source.length }] }],
      }] } }));
    } else if (url.pathname.startsWith('/audio/')) {
      response.writeHead(200, { 'content-length': source.length });
      if (id === heldId) {
        held.push(response);
        response.write(source.subarray(0, 2 * 1024 * 1024));
      } else response.end(source);
    } else response.end('{}');
  }, { transcodeCachePath: cacheRoot });
  await app.listen({ host: '127.0.0.1', port: 0 });
  const origin = `http://127.0.0.1:${app.server.address().port}`;
  const stream = id => `${origin}/rest/stream?${new URLSearchParams({ ...params, id, format: 'mp3' })}`;
  const modes = holdMs ? ['cold-cold'] : ['cold-cold', 'cold-cached', 'cached-cold', 'cached-cached'];
  for (const [index, mode] of modes.entries()) {
    const activeId = String(index * 2 + 1), nextId = String(index * 2 + 2);
    const [activeMode, nextMode] = mode.split('-');
    heldId = '';
    for (const id of [activeMode === 'cached' ? activeId : '', nextMode === 'cached' ? nextId : ''].filter(Boolean)) {
      await (await fetch(stream(id), { signal: t.signal })).arrayBuffer();
    }
    heldId = activeMode === 'cold' ? activeId : '';
    held = [];
    let observedPrepared = false;
    const result = await new Promise((resolve, reject) => {
      const child = execFile(process.env.RESONANCE_BIN, [path.resolve('test/helpers/resonance-gapless.cjs')], {
        env: { ...process.env, GAPLESS_HOLD_MS: String(holdMs), TRANSCODE_URL: stream(activeId), SUCCESSOR_URL: stream(nextId),
          EXTENSIONS_URL: `${origin}/rest/getOpenSubsonicExtensions?${new URLSearchParams(params)}` },
        timeout: holdMs ? 60000 : 20000,
      }, (error, stdout, stderr) => error ? reject(Object.assign(error, { stdout, stderr })) : resolve({ stdout, stderr }));
      let output = '';
      child.stdout.on('data', chunk => {
        output += chunk;
        if (observedPrepared || !output.includes('GAPLESS_PREPARED\n')) return;
        observedPrepared = true;
        // Release actual upstream A only after the real native B decoder is ready.
        for (const response of held) response.end(source.subarray(2 * 1024 * 1024));
      });
    });
    assert.equal(observedPrepared, true);
    if (activeMode === 'cold') assert.ok(held.length > 0, 'A stayed upstream-active until B readiness');
    const report = JSON.parse(result.stdout.trim().split('\n').at(-1));
    t.diagnostic(`${mode}: ${JSON.stringify(report)}`);
    assert.equal(report.finals, 1);
  }
});
}
