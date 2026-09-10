import assert from 'node:assert/strict';
import { execFile, execFileSync } from 'node:child_process';
import { once } from 'node:events';
import { watch } from 'node:fs';
import fs from 'node:fs/promises';
import { get } from 'node:http';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import test from 'node:test';
import { promisify } from 'node:util';
import { createFixture } from './helpers/server.js';

for (const format of ['flac', 'mp3']) {
  test(`a slow ${format} transcode delivers every sample; cached replay has exact length and byte ranges`, async (t) => {
    const duration = format === 'mp3' ? 180 : 45;
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
        if (filename?.endsWith(`.${format}`)) resolve(path.join(cacheRoot, filename));
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
    const url = `/rest/stream?${new URLSearchParams({ ...params, id: '1', format })}`;
    const response = await new Promise((resolve, reject) => {
      get(`http://127.0.0.1:${app.server.address().port}${url}`, resolve).on('error', reject);
    });
    assert.equal(response.statusCode, 200);
    // Exercise real socket backpressure instead of replacing the encoder or its output.
    response.pause();
    await delay(format === 'mp3' ? 2000 : 150);
    const chunks = [];
    for await (const chunk of response) {
      chunks.push(chunk);
      await delay(format === 'mp3' ? 100 : 2);
    }
    const streamed = Buffer.concat(chunks);
    const pcm = execFileSync('ffmpeg', [
      '-v', 'error', '-i', 'pipe:0', '-f', 's16le', 'pipe:1',
    ], { input: streamed, maxBuffer: 32 * 1024 * 1024 });
    const sourcePcmBytes = duration * 44100 * 2 * 2;
    if (format === 'flac') {
      assert.equal(pcm.length, sourcePcmBytes, 'the live response must contain every audio sample');
    } else {
      // Pipe MP3 has no LAME gapless header, so decoding includes encoder delay
      // and final frame padding. It must never lose the source's final samples.
      assert.ok(pcm.length >= sourcePcmBytes && pcm.length < sourcePcmBytes + 2304 * 4);
    }
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

    if (format === 'mp3' && process.env.RESONANCE_BIN) {
      // A completed HTTP message may be followed by a normal keep-alive socket
      // close while the player still has compressed bytes buffered for decoding.
      app.server.keepAliveTimeout = 100;
      const nativeUrl = `http://127.0.0.1:${app.server.address().port}${url.replace('id=1', 'id=2')}`;
      const reports = [];
      for (const mode of ['live', 'cached']) {
        const result = await promisify(execFile)(process.env.RESONANCE_BIN, [
          path.resolve('test/helpers/resonance-playback.cjs'),
        ], { env: { ...process.env, TRANSCODE_URL: nativeUrl }, timeout: 60000 });
        const report = JSON.parse(result.stdout.trim());
        t.diagnostic(`${mode}: ${JSON.stringify(report)}`);
        assert.equal(report.bytes, pcm.length, `${mode} Resonance playback must deliver all decoded samples`);
        assert.equal(report.finalCompleted, true, 'ended must wait for the sink to finish');
        reports.push(report);
      }
      // mpg123 currently reports zero for an unknown pipe length; providers may
      // also expose null. Neither is a usable duration for this nonempty source.
      assert.ok(reports[0].before.durationUs == null || reports[0].before.durationUs === 0);
      assert.equal(reports[0].before.seekable, false);
      assert.ok(reports[1].before.durationUs > 0);
      assert.equal(reports[1].before.seekable, true);
    }
  });
}

test('a failed encoder returns an error and does not publish a cache file', async (t) => {
  const cacheRoot = await fs.mkdtemp(path.resolve('data/audio-failure-test-'));
  t.after(() => fs.rm(cacheRoot, { recursive: true, force: true }));
  const watcher = watch(cacheRoot);
  t.after(() => watcher.close());
  let cleanupArmed = false;
  const cacheRemoved = new Promise((resolve, reject) => {
    watcher.on('error', reject);
    watcher.on('change', async () => {
      if (!cleanupArmed) return;
      try {
        if ((await fs.readdir(cacheRoot)).length === 0) resolve();
      } catch (error) {
        reject(error);
      }
    });
    AbortSignal.timeout(10000).addEventListener('abort', () => reject(new Error('Failed transcode cache was not removed')), { once: true });
  });
  cacheRemoved.catch(() => {});
  const { app, params } = await createFixture(t, (request, response) => {
    if (request.url.startsWith('/library/metadata/')) {
      response.end(JSON.stringify({ MediaContainer: { Metadata: [{
        type: 'track', ratingKey: '1', duration: 1000,
        Media: [{ container: 'wav', Part: [{ key: '/audio' }] }],
      }] } }));
    } else if (request.url.startsWith('/audio')) {
      response.end('invalid audio source');
    } else {
      response.end('{}');
    }
  }, { transcodeCachePath: cacheRoot });
  const response = await app.inject(`/rest/stream?${new URLSearchParams({ ...params, id: '1', format: 'mp3' })}`);
  assert.equal(response.statusCode, 500);
  // Response errors are published promptly; descriptor close and temporary
  // file removal finish asynchronously. Observe that completion before stat.
  cleanupArmed = true;
  if ((await fs.readdir(cacheRoot)).length) await cacheRemoved;
  assert.deepEqual(await fs.readdir(cacheRoot), []);
});

test('disconnecting a live transcode aborts its source and removes the partial cache', { timeout: 15000 }, async (t) => {
  const source = execFileSync('ffmpeg', [
    '-v', 'error', '-f', 'lavfi', '-i', 'sine=sample_rate=44100:duration=15',
    '-ac', '2', '-f', 'wav', 'pipe:1',
  ], { maxBuffer: 4 * 1024 * 1024 });
  const cacheRoot = await fs.mkdtemp(path.resolve('data/audio-abort-test-'));
  t.after(() => fs.rm(cacheRoot, { recursive: true, force: true }));
  const watcher = watch(cacheRoot);
  t.after(() => watcher.close());
  let cleanupArmed = false;
  const cacheRemoved = new Promise((resolve, reject) => {
    watcher.on('error', reject);
    watcher.on('change', async () => {
      if (!cleanupArmed) return;
      try {
        if ((await fs.readdir(cacheRoot)).length === 0) resolve();
      } catch (error) {
        reject(error);
      }
    });
  });
  cacheRemoved.catch(() => {});
  let sourceClosed;
  const upstreamClosed = new Promise((resolve) => { sourceClosed = resolve; });
  const { app, params } = await createFixture(t, (request, response) => {
    if (request.url.startsWith('/library/metadata/')) {
      response.end(JSON.stringify({ MediaContainer: { Metadata: [{
        type: 'track', ratingKey: '1', duration: 15000,
        Media: [{ container: 'wav', Part: [{ key: '/audio', size: source.length }] }],
      }] } }));
    } else if (request.url.startsWith('/audio')) {
      response.once('close', sourceClosed);
      response.writeHead(200, { 'content-length': source.length });
      // Send enough real WAV to start the encoder, then leave the source
      // open so client cancellation must abort an active upstream request.
      response.write(source.subarray(0, 2 * 1024 * 1024));
    } else {
      response.end('{}');
    }
  }, { transcodeCachePath: cacheRoot });
  await app.listen({ host: '127.0.0.1', port: 0 });
  const url = `http://127.0.0.1:${app.server.address().port}/rest/stream?${new URLSearchParams({ ...params, id: '1', format: 'mp3' })}`;
  const response = await new Promise((resolve, reject) => {
    get(url, { signal: t.signal }, resolve).on('error', reject);
  });
  await once(response, 'data');
  cleanupArmed = true;
  response.destroy();
  await upstreamClosed;
  await cacheRemoved;
  assert.deepEqual(await fs.readdir(cacheRoot), []);
});
