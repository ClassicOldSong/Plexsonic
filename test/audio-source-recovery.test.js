import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { once } from 'node:events';
import { watch } from 'node:fs';
import fs from 'node:fs/promises';
import { get } from 'node:http';
import path from 'node:path';
import test from 'node:test';
import { createFixture } from './helpers/server.js';

for (const [format, offset] of [['flac', 0], ['mp3', 0], ['flac', 7.25]]) {
  test(`${format} transcode at offset ${offset} recovers early and late Plex disconnects without repeating audio`, { timeout: 15000 }, async (t) => {
    const source = execFileSync('ffmpeg', [
      '-v', 'error', '-f', 'lavfi', '-i', 'anoisesrc=sample_rate=44100:duration=20:seed=1',
      '-ac', '2', '-c:a', 'pcm_s16le', '-f', 'wav', 'pipe:1',
    ], { maxBuffer: 4 * 1024 * 1024 });
    await fs.mkdir('data', { recursive: true });
    const cacheRoot = await fs.mkdtemp(path.resolve('data/audio-source-recovery-'));
    t.after(() => fs.rm(cacheRoot, { recursive: true, force: true }));
    let sourceRequests = 0;
    const { app, params } = await createFixture(t, (request, response) => {
      if (request.url.startsWith('/library/metadata/')) {
        response.end(JSON.stringify({ MediaContainer: { Metadata: [{
          type: 'track', ratingKey: '1', duration: 20000,
          Media: [{ container: 'wav', Part: [{ key: '/audio', size: source.length }] }],
        }] } }));
      } else if (request.url.startsWith('/audio')) {
        sourceRequests++;
        response.writeHead(200, { 'content-type': 'audio/wav', 'content-length': source.length });
        const cutoff = sourceRequests === 1 ? 65536 : sourceRequests === 2 ? source.length - 65536 : 0;
        if (cutoff) {
          // Real premature TCP EOF, with valid headers and an incomplete body.
          // FFmpeg remains the production encoder, including its input buffering.
          response.write(source.subarray(0, cutoff), () => {
            const timer = setTimeout(() => response.destroy(), 20);
            timer.unref();
          });
        } else response.end(source);
      } else response.end('{}');
    }, { transcodeCachePath: cacheRoot });
    await app.listen({ host: '127.0.0.1', port: 0 });
    const url = `http://127.0.0.1:${app.server.address().port}/rest/stream?${new URLSearchParams({ ...params, id: '1', format, timeOffset: String(offset) })}`;
    const response = await fetch(url, { signal: t.signal });
    assert.equal(response.status, 200);
    const bytes = Buffer.from(await response.arrayBuffer());
    assert.equal(sourceRequests, 3, 'both broken upstream bodies must be recovered');
    const pcm = execFileSync('ffmpeg', ['-v', 'error', '-xerror', '-i', 'pipe:0', '-f', 's16le', 'pipe:1'], {
      input: bytes, maxBuffer: 4 * 1024 * 1024,
    });
    if (format === 'flac') {
      const expected = execFileSync('ffmpeg', ['-v', 'error', '-i', 'pipe:0', '-f', 's16le', 'pipe:1'], {
        input: source, maxBuffer: 4 * 1024 * 1024,
      });
      assert.deepEqual(pcm, expected.subarray(offset * 44100 * 4), 'every remaining original sample appears exactly once');
    } else {
      const expectedBytes = 20 * 44100 * 4;
      assert.ok(pcm.length >= expectedBytes && pcm.length < expectedBytes + 2304 * 4);
    }
    if (offset) {
      assert.deepEqual(await fs.readdir(cacheRoot), [], 'a recovered suffix must not become a full-song cache');
    } else {
      const cached = await fetch(url, { signal: t.signal });
      assert.equal(Number(cached.headers.get('content-length')), bytes.length);
      assert.deepEqual(Buffer.from(await cached.arrayBuffer()), bytes);
      assert.equal(sourceRequests, 3, 'only a complete recovered transcode is cached');
    }
  });
}

for (const failure of ['prefix', 'etag', 'length', 'shorter', 'partial', 'exhausted', 'cancel']) {
  test(`source recovery rejects ${failure} without publishing a partial transcode`, { timeout: 10000 }, async (t) => {
    const source = execFileSync('ffmpeg', [
      '-v', 'error', '-f', 'lavfi', '-i', 'anoisesrc=sample_rate=44100:duration=10:seed=1',
      '-ac', '2', '-c:a', 'pcm_s16le', '-f', 'wav', 'pipe:1',
    ], { maxBuffer: 2 * 1024 * 1024 });
    await fs.mkdir('data', { recursive: true });
    const cacheRoot = await fs.mkdtemp(path.resolve('data/audio-source-reject-'));
    t.after(() => fs.rm(cacheRoot, { recursive: true, force: true }));
    const watcher = watch(cacheRoot, { recursive: true });
    t.after(() => watcher.close());
    let cleanupArmed = false;
    let resolveCleaned;
    const cleaned = new Promise(resolve => { resolveCleaned = resolve; });
    watcher.on('change', async () => {
      if (cleanupArmed && (await fs.readdir(cacheRoot)).length === 0) resolveCleaned();
    });
    let resolveReplacement;
    const replacement = new Promise(resolve => { resolveReplacement = resolve; });
    let sourceRequests = 0;
    const { app, params } = await createFixture(t, (request, response) => {
      if (request.url.startsWith('/library/metadata/')) {
        response.end(JSON.stringify({ MediaContainer: { Metadata: [{
          type: 'track', ratingKey: '1', duration: 10000,
          Media: [{ container: 'wav', Part: [{ key: '/audio', size: source.length }] }],
        }] } }));
      } else if (request.url.startsWith('/audio')) {
        sourceRequests++;
        const broken = sourceRequests === 1 || failure === 'exhausted';
        const headers = { 'content-type': 'audio/wav' };
        if (failure !== 'shorter') headers['content-length'] = source.length - (failure === 'length' && !broken ? 1 : 0);
        if (failure === 'etag') headers.etag = broken ? '"first"' : '"changed"';
        response.writeHead(failure === 'partial' && !broken ? 206 : 200, headers);
        if (broken) {
          response.write(source.subarray(0, 65536), () => {
            const timer = setTimeout(() => response.destroy(), 20);
            timer.unref();
          });
        } else if (failure === 'cancel') {
          response.write(source.subarray(0, 32768));
          resolveReplacement({ closed: once(response, 'close') });
        } else if (failure === 'prefix') {
          const changed = Buffer.from(source);
          changed[10000] ^= 255;
          response.end(changed);
        } else response.end(source.subarray(0, failure === 'shorter' ? 16384 : failure === 'length' ? -1 : undefined));
      } else response.end('{}');
    }, { transcodeCachePath: cacheRoot });
    await app.listen({ host: '127.0.0.1', port: 0 });
    const url = `http://127.0.0.1:${app.server.address().port}/rest/stream?${new URLSearchParams({ ...params, id: '1', format: 'mp3' })}`;
    if (failure === 'cancel') {
      const request = get(url, { signal: t.signal });
      const canceled = once(request, 'error');
      const { closed } = await replacement;
      request.destroy(new Error('player abandoned recovering stream'));
      await canceled;
      await closed;
    } else {
      const response = await fetch(url, { signal: t.signal });
      if (response.status === 200) await assert.rejects(response.arrayBuffer(), { name: 'TypeError' });
      else {
        assert.equal(response.status, 500);
        const error = await response.json();
        const reason = {
          prefix: /Plex source changed/,
          etag: /Plex source etag changed/,
          length: /Plex source content-length changed/,
          shorter: /Plex source became shorter/,
          partial: /Plex source recovery returned HTTP 206/,
          exhausted: /Upstream stream terminated during transcode/,
        }[failure];
        assert.match(error.message, reason);
      }
    }
    assert.equal(t.signal.aborted, false, 'failure must be handled without reaching the test deadline');
    assert.equal(sourceRequests, failure === 'exhausted' ? 3 : 2);
    cleanupArmed = true;
    if ((await fs.readdir(cacheRoot)).length) await cleaned;
    cleanupArmed = false;
    assert.deepEqual(await fs.readdir(cacheRoot), []);
  });
}
