import assert from 'node:assert/strict';
import { execFile, execFileSync } from 'node:child_process';
import { once } from 'node:events';
import fs from 'node:fs/promises';
import { get } from 'node:http';
import path from 'node:path';
import test from 'node:test';
import { promisify } from 'node:util';
import { createFixture } from './helpers/server.js';

test('transcodeOffset restarts real audio at the requested time without poisoning the full cache', async (t) => {
  const wav = execFileSync('ffmpeg', [
    '-v', 'error', '-f', 'lavfi', '-i',
    'sine=frequency=440:sample_rate=44100:duration=2[a];sine=frequency=880:sample_rate=44100:duration=2[b];[a][b]concat=n=2:v=0:a=1',
    '-c:a', 'pcm_s16le', '-f', 'wav', 'pipe:1',
  ]);
  const sourcePcm = execFileSync('ffmpeg', [
    '-v', 'error', '-i', 'pipe:0', '-f', 's16le', 'pipe:1',
  ], { input: wav });
  await fs.mkdir('data', { recursive: true });
  const cacheRoot = await fs.mkdtemp(path.resolve('data/audio-seek-test-'));
  t.after(() => fs.rm(cacheRoot, { recursive: true, force: true }));
  let source = wav;
  let sourceFormat = 'wav';
  let sourceRequests = 0;
  const { app, params } = await createFixture(t, (request, response) => {
    if (request.url.startsWith('/library/metadata/')) {
      response.end(JSON.stringify({ MediaContainer: { Metadata: [{
        type: 'track', ratingKey: '1', duration: 4000,
        Media: [{ container: sourceFormat, Part: [{ key: '/audio', size: source.length }] }],
      }] } }));
    } else if (request.url.startsWith('/audio')) {
      sourceRequests += 1;
      response.writeHead(200, { 'content-length': source.length });
      response.end(source);
    } else {
      response.end('{}');
    }
  }, { transcodeCachePath: cacheRoot });
  const baseParams = { ...params, id: '1', format: 'flac' };
  const extensions = await app.inject(`/rest/getOpenSubsonicExtensions?${new URLSearchParams(params)}`);
  assert.ok(extensions.json()['subsonic-response'].openSubsonicExtensions.some(
    (extension) => extension.name === 'transcodeOffset' && extension.versions.includes(1),
  ));

  for (const timeOffset of ['-1', 'NaN', 'Infinity', '2seconds', '1e100', '4', '5']) {
    const response = await app.inject(`/rest/stream?${new URLSearchParams({ ...baseParams, timeOffset })}`);
    assert.equal(response.json()['subsonic-response'].error.code, 10);
  }
  const raw = await app.inject(`/rest/stream?${new URLSearchParams({ ...baseParams, format: 'raw', timeOffset: '1' })}`);
  assert.equal(raw.json()['subsonic-response'].error.code, 10);
  assert.equal(sourceRequests, 0, 'invalid offsets must not fetch audio');

  for (const format of ['flac', 'mp3', 'aac', 'opus']) {
    const response = await app.inject({
      method: 'POST', url: '/rest/stream',
      headers: { 'content-type': 'application/x-www-form-urlencoded', range: 'bytes=0-1023' },
      payload: new URLSearchParams({ ...baseParams, format, timeOffset: '2.1254' }).toString(),
    });
    assert.equal(response.statusCode, 200, 'an offset response has no byte-range representation');
    assert.equal(response.headers['accept-ranges'], 'none');
    assert.equal(response.headers['content-length'], undefined);
    assert.equal(response.headers['content-range'], undefined);
    assert.equal(response.headers['x-content-duration'], '1.875');
    assert.match(response.headers['access-control-expose-headers'], /x-content-duration/);
    const pcm = execFileSync('ffmpeg', [
      '-v', 'error', '-i', 'pipe:0', '-ar', '44100', '-f', 's16le', 'pipe:1',
    ], { input: response.rawPayload });
    const expected = sourcePcm.subarray(Math.round(2.125 * 44100) * 2);
    if (format === 'flac') {
      assert.deepEqual(pcm, expected, 'lossless seek must deliver the exact remaining samples');
    } else {
      assert.ok(pcm.length >= expected.length && pcm.length < expected.length + 2304 * 2);
      // Ignore encoder delay and count a full second of the 880 Hz suffix.
      // Starting from zero would yield 440 Hz even if the response were shortened.
      let crossings = 0;
      for (let sample = 8820; sample < 52920; sample += 1) {
        if (pcm.readInt16LE((sample - 1) * 2) <= 0 && pcm.readInt16LE(sample * 2) > 0) crossings += 1;
      }
      assert.ok(crossings >= 879 && crossings <= 881, `expected 880 Hz after seek, got ${crossings}`);
    }
    assert.deepEqual(await fs.readdir(cacheRoot), [], 'a suffix must not become a full-song cache entry');
  }

  const baseUrl = `/rest/stream?${new URLSearchParams(baseParams)}`;
  const full = await app.inject(baseUrl);
  const cachedRequests = sourceRequests;
  const seek = await app.inject(`${baseUrl}&timeOffset=3`);
  assert.equal(seek.headers['x-content-duration'], '1');
  assert.equal(sourceRequests, cachedRequests + 1, 'offset audio must not silently replay the full cached file');
  const replay = await app.inject(baseUrl);
  assert.deepEqual(replay.rawPayload, full.rawPayload);
  assert.equal(Number(replay.headers['content-length']), full.rawPayload.length);
  const range = await app.inject({ url: baseUrl, headers: { range: 'bytes=17-63' } });
  assert.equal(range.statusCode, 206);
  assert.deepEqual(range.rawPayload, full.rawPayload.subarray(17, 64));

  source = execFileSync('ffmpeg', [
    '-v', 'error', '-i', 'pipe:0', '-c:a', 'flac', '-f', 'flac', 'pipe:1',
  ], { input: wav });
  sourceFormat = 'flac';
  for (const format of ['flac', '']) {
    const response = await app.inject(`/rest/stream?${new URLSearchParams({ ...baseParams, id: `same-${format}`, format, timeOffset: '1' })}`);
    const pcm = execFileSync('ffmpeg', [
      '-v', 'error', '-i', 'pipe:0', '-f', 's16le', 'pipe:1',
    ], { input: response.rawPayload });
    assert.deepEqual(pcm, sourcePcm.subarray(44100 * 2), 'offset applies when no codec conversion was otherwise needed');
  }
});

test('canceling a seek before audio is available aborts the upstream source', { timeout: 10000 }, async (t) => {
  const source = execFileSync('ffmpeg', [
    '-v', 'error', '-f', 'lavfi', '-i', 'sine=sample_rate=44100:duration=4',
    '-c:a', 'pcm_s16le', '-f', 'wav', 'pipe:1',
  ]);
  const cacheRoot = await fs.mkdtemp(path.resolve('data/audio-seek-abort-test-'));
  t.after(() => fs.rm(cacheRoot, { recursive: true, force: true }));
  let sourceStarted;
  let sourceClosed;
  const upstreamStarted = new Promise((resolve) => { sourceStarted = resolve; });
  const upstreamClosed = new Promise((resolve) => { sourceClosed = resolve; });
  const { app, params } = await createFixture(t, (request, response) => {
    if (request.url.startsWith('/library/metadata/')) {
      response.end(JSON.stringify({ MediaContainer: { Metadata: [{
        type: 'track', ratingKey: '1', duration: 4000,
        Media: [{ container: 'wav', Part: [{ key: '/audio', size: source.length }] }],
      }] } }));
    } else if (request.url.startsWith('/audio')) {
      response.once('close', sourceClosed);
      response.writeHead(200, { 'content-length': source.length });
      // Leave the prefix incomplete: output-side seeking cannot emit audio yet.
      response.write(source.subarray(0, 44100));
      sourceStarted();
    } else {
      response.end('{}');
    }
  }, { transcodeCachePath: cacheRoot });
  await app.listen({ host: '127.0.0.1', port: 0 });
  const request = get(`http://127.0.0.1:${app.server.address().port}/rest/stream?${new URLSearchParams({
    ...params, id: '1', format: 'mp3', timeOffset: '2',
  })}`, { signal: t.signal });
  const requestFailed = once(request, 'error');
  await upstreamStarted;
  request.destroy(new Error('seek superseded'));
  await requestFailed;
  await upstreamClosed;
  assert.deepEqual(await fs.readdir(cacheRoot), []);
});

test('Resonance player seeks both live and cached Plexsonic MP3 streams', {
  skip: !process.env.RESONANCE_BIN || !process.env.RESONANCE_PLAYER_MODULE,
  timeout: 90000,
}, async (t) => {
  const source = execFileSync('ffmpeg', [
    '-v', 'error', '-f', 'lavfi', '-i', 'anoisesrc=sample_rate=44100:duration=180:seed=1',
    '-ac', '2', '-c:a', 'pcm_s16le', '-f', 'wav', 'pipe:1',
  ], { maxBuffer: 32 * 1024 * 1024 });
  const cacheRoot = await fs.mkdtemp(path.resolve('data/audio-native-seek-test-'));
  t.after(() => fs.rm(cacheRoot, { recursive: true, force: true }));
  const { app, params } = await createFixture(t, (request, response) => {
    if (request.url.startsWith('/library/metadata/')) {
      response.end(JSON.stringify({ MediaContainer: { Metadata: [{
        type: 'track', ratingKey: '1', duration: 180000,
        Media: [{ container: 'wav', Part: [{ key: '/audio', size: source.length }] }],
      }] } }));
    } else if (request.url.startsWith('/audio')) {
      response.writeHead(200, { 'content-length': source.length });
      response.end(source);
    } else {
      response.end('{}');
    }
  }, { transcodeCachePath: cacheRoot });
  const offsets = [];
  const requests = [];
  app.addHook('onRequest', async (request, reply) => {
    const url = new URL(request.url, 'http://fixture');
    if (url.pathname.startsWith('/rest/stream')) {
      offsets.push(url.searchParams.get('timeOffset'));
      const entry = { at: Date.now(), range: request.headers.range, finished: false, closed: false };
      requests.push(entry);
      reply.raw.once('finish', () => { entry.finished = true; });
      reply.raw.once('close', () => { entry.closed = true; });
    }
  });
  await app.listen({ host: '127.0.0.1', port: 0 });
  const origin = `http://127.0.0.1:${app.server.address().port}`;
  const streamPath = `/rest/stream?${new URLSearchParams({ ...params, id: '1', format: 'mp3' })}`;
  for (const mode of ['worker', 'live', 'cached']) {
    if (mode === 'cached') await app.inject(streamPath);
    offsets.length = 0;
    requests.length = 0;
    const modePath = mode === 'worker'
      ? `/rest/stream?${new URLSearchParams({ ...params, id: '2', format: 'mp3' })}`
      : streamPath;
    const result = await promisify(execFile)(process.env.RESONANCE_BIN, [
      path.resolve(mode === 'worker' ? 'test/helpers/resonance-worker-seeking.cjs' : 'test/helpers/resonance-seeking.cjs'),
    ], {
      env: { ...process.env, SEEK_MODE: mode, TRANSCODE_URL: origin + modePath,
        EXTENSIONS_URL: `${origin}/rest/getOpenSubsonicExtensions?${new URLSearchParams(params)}` },
      timeout: 45000,
    }).finally(() => {
      t.diagnostic(`${mode} HTTP: ${JSON.stringify({ count: requests.length,
        first: requests.slice(0, 5), last: requests.slice(-5) })}`);
    });
    assert.ok(result.stdout.trim(), `Resonance did not finish the seek sequence: ${result.stderr}`);
    // The worker runtime logs startup details; each helper's final line is its JSON report.
    const report = JSON.parse(result.stdout.trim().split('\n').at(-1));
    t.diagnostic(`${mode}: ${JSON.stringify(report)}`);
    if (mode === 'worker') {
      assert.equal(report.paused, true);
      assert.equal(report.shutdownCompleted, true);
    } else {
      assert.equal(report.finalCompleted, true);
    }
    if (mode !== 'cached') {
      for (const offset of ['120.125', '40.5', '90.25']) assert.ok(offsets.includes(offset));
    } else {
      assert.ok(offsets.every((offset) => offset === null), 'cached seeks use HTTP byte ranges');
    }
  }
});
