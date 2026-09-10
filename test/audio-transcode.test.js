import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { watch } from 'node:fs';
import fs from 'node:fs/promises';
import { get } from 'node:http';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import test from 'node:test';
import { createFixture } from './helpers/server.js';

test('a slow first transcode delivers every sample; cached replay has exact length and byte ranges', async (t) => {
  const duration = 45;
  const source = execFileSync('ffmpeg', [
    '-v', 'error', '-f', 'lavfi', '-i', `anoisesrc=sample_rate=44100:duration=${duration}:seed=1`,
    '-ac', '2', '-c:a', 'pcm_s16le', '-f', 'wav', 'pipe:1',
  ], { maxBuffer: 32 * 1024 * 1024 });
  await fs.mkdir('data', { recursive: true });
  const cacheRoot = await fs.mkdtemp(path.resolve('data/audio-test-'));
  t.after(() => fs.rm(cacheRoot, { recursive: true, force: true }));
  const watcher = watch(cacheRoot, { recursive: true });
  t.after(() => watcher.close());
  const cacheReady = new Promise((resolve, reject) => {
    watcher.on('change', (_, filename) => {
      if (filename?.endsWith('.flac')) resolve(path.join(cacheRoot, filename));
    });
    watcher.on('error', reject);
    AbortSignal.timeout(10000).addEventListener('abort', () => reject(new Error('Transcode was not cached')), { once: true });
  });
  cacheReady.catch(() => {});
  let sourceRequests = 0;
  const { app, params } = await createFixture(t, (request, response) => {
    if (request.url.startsWith('/library/metadata/')) {
      response.end(JSON.stringify({ MediaContainer: { Metadata: [{
        type: 'track', ratingKey: '1', duration: duration * 1000, updatedAt: 1,
        Media: [{ container: 'wav', Part: [{ key: '/audio', size: source.length }] }],
      }] } }));
    } else if (request.url.startsWith('/audio')) {
      sourceRequests += 1;
      response.writeHead(200, { 'content-type': 'audio/wav', 'content-length': source.length });
      response.end(source);
    } else {
      response.end('{}');
    }
  }, { transcodeCachePath: cacheRoot });
  await app.listen({ host: '127.0.0.1', port: 0 });
  const url = `/rest/stream?${new URLSearchParams({ ...params, id: '1', format: 'flac' })}`;
  const response = await new Promise((resolve, reject) => {
    get(`http://127.0.0.1:${app.server.address().port}${url}`, resolve).on('error', reject);
  });
  assert.equal(response.statusCode, 200);
  // Exercise real socket backpressure instead of replacing the encoder or its output.
  response.pause();
  await delay(150);
  const chunks = [];
  for await (const chunk of response) {
    chunks.push(chunk);
    await delay(2);
  }
  const streamed = Buffer.concat(chunks);
  const pcm = execFileSync('ffmpeg', [
    '-v', 'error', '-i', 'pipe:0', '-f', 's16le', 'pipe:1',
  ], { input: streamed, maxBuffer: 32 * 1024 * 1024 });
  assert.equal(pcm.length, duration * 44100 * 2 * 2, 'the live response must contain every audio sample');
  const cacheFile = await cacheReady;
  assert.deepEqual(await fs.readFile(cacheFile), streamed);
  const replay = await app.inject(url);
  assert.equal(replay.statusCode, 200);
  assert.equal(Number(replay.headers['content-length']), streamed.length);
  assert.equal(replay.headers['accept-ranges'], 'bytes');
  assert.deepEqual(replay.rawPayload, streamed);
  const range = await app.inject({ url, headers: { range: 'bytes=17-63' } });
  assert.equal(range.statusCode, 206);
  assert.equal(range.headers['content-range'], `bytes 17-63/${streamed.length}`);
  assert.equal(Number(range.headers['content-length']), 47);
  assert.deepEqual(range.rawPayload, streamed.subarray(17, 64));
  assert.equal(sourceRequests, 1);
});
