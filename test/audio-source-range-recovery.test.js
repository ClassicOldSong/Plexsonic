import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { once } from 'node:events';
import { watch } from 'node:fs';
import fs from 'node:fs/promises';
import { get } from 'node:http';
import path from 'node:path';
import test from 'node:test';
import { createFixture } from './helpers/server.js';

const source = execFileSync('ffmpeg', [
  '-v', 'error', '-f', 'lavfi', '-i', 'anoisesrc=sample_rate=44100:duration=20:seed=1',
  '-ac', '2', '-c:a', 'pcm_s16le', '-f', 'wav', 'pipe:1',
], { maxBuffer: 4 * 1024 * 1024 });
const originalPcm = execFileSync('ffmpeg', ['-v', 'error', '-i', 'pipe:0', '-f', 's16le', 'pipe:1'], {
  input: source, maxBuffer: 4 * 1024 * 1024,
});
const etag = '"source\\tag-1"'; // Backslash is a literal valid opaque-tag character.
const lastModified = 'Mon, 12 Oct 2026 00:00:00 GMT';
const responseDate = 'Mon, 12 Oct 2026 00:02:00 GMT';

for (const [mode, format, offset = 0] of [
  ['etag', 'mp3'], ['etag', 'flac'], ['etag', 'flac', 7.25],
  ['last-modified', 'flac'], ['empty-opaque-tag', 'flac'], ['unknown-length', 'flac'],
  ['ignored-range', 'flac'], ['chunked-short-range', 'flac'],
  ['weak-etag', 'flac'], ['malformed-etag', 'flac'], ['recent-last-modified', 'flac'],
]) {
  test(`${mode}: ${format} recovery at ${offset}s preserves audio across early and late disconnects`, { timeout: 15000 }, async (t) => {
    await fs.mkdir('data', { recursive: true });
    const cacheRoot = await fs.mkdtemp(path.resolve('data/audio-range-recovery-'));
    t.after(() => fs.rm(cacheRoot, { recursive: true, force: true }));
    const requests = [];
    const useRange = !['weak-etag', 'malformed-etag', 'recent-last-modified'].includes(mode);
    const dateValidator = mode === 'last-modified' || mode === 'recent-last-modified';
    const sourceTag = mode === 'weak-etag' ? `W/${etag}` : mode === 'malformed-etag' ? '"unescaped"quote"'
      : mode === 'empty-opaque-tag' ? '""' : etag;
    const { app, params } = await createFixture(t, (request, response) => {
      if (request.url.startsWith('/library/metadata/')) {
        response.end(JSON.stringify({ MediaContainer: { Metadata: [{
          type: 'track', ratingKey: '1', duration: 20000,
          Media: [{ container: 'wav', Part: [{ key: '/audio', size: source.length }] }],
        }] } }));
      } else if (request.url.startsWith('/audio')) {
        requests.push(request.headers);
        const partial = request.headers.range && !(mode === 'ignored-range' && requests.length === 2);
        // This fixture accepts only the generated, open-ended byte range. The
        // complete request grammar is asserted below, outside the server callback.
        const start = partial ? Number(request.headers.range.slice(6, -1)) : 0;
        const headers = { 'content-type': 'audio/wav', date: responseDate };
        if (!dateValidator) headers.etag = sourceTag;
        // A 206 answering If-Range may omit Last-Modified (RFC 9110 15.3.7).
        if (!partial) headers['last-modified'] = mode === 'recent-last-modified' ? responseDate : lastModified;
        if (partial) headers['content-range'] = `bytes ${start}-${source.length - 1}/${source.length}`;
        const chunkedShort = mode === 'chunked-short-range' && requests.length === 2;
        if (!(mode === 'unknown-length' && requests.length === 1) && !chunkedShort) {
          headers['content-length'] = source.length - start;
        }
        response.writeHead(partial ? 206 : 200, headers);
        const cutoff = requests.length === 1 ? 65536 : requests.length === 2 ? source.length - 65536 : source.length;
        if (requests.length < 3 && !chunkedShort) {
          response.write(source.subarray(start, cutoff), () => {
            const timer = setTimeout(() => response.destroy(), 20);
            timer.unref();
          });
        } else response.end(source.subarray(start, cutoff));
      } else response.end('{}');
    }, { transcodeCachePath: cacheRoot });
    await app.listen({ host: '127.0.0.1', port: 0 });
    const url = `http://127.0.0.1:${app.server.address().port}/rest/stream?${new URLSearchParams({ ...params, id: '1', format, timeOffset: String(offset) })}`;
    const response = await fetch(url, { signal: t.signal });
    assert.equal(response.status, 200);
    const bytes = Buffer.from(await response.arrayBuffer());
    assert.equal(requests.length, 3);
    assert.equal(requests[0].range, undefined);
    assert.ok(requests.every(request => request['accept-encoding'] === 'identity'));
    for (const request of requests.slice(1)) {
      if (useRange) {
        assert.match(request.range, /^bytes=[1-9]\d*-$/);
        assert.equal(request['if-range'], dateValidator ? lastModified : sourceTag);
      } else {
        assert.equal(request.range, undefined, 'unsafe validators retain prefix verification');
        assert.equal(request['if-range'], undefined);
      }
    }
    if (useRange) {
      const offsets = requests.slice(1).map(request => Number(request.range.slice(6, -1)));
      assert.ok(offsets[0] > 0 && offsets[0] <= 65536);
      assert.ok(offsets[1] > offsets[0], 'a second disconnection resumes from new progress');
      assert.ok(offsets[1] <= source.length - 65536);
    }
    const pcm = execFileSync('ffmpeg', ['-v', 'error', '-xerror', '-i', 'pipe:0', '-f', 's16le', 'pipe:1'], {
      input: bytes, maxBuffer: 4 * 1024 * 1024,
    });
    if (format === 'flac') {
      assert.deepEqual(pcm, originalPcm.subarray(offset * 44100 * 4), 'every remaining original sample appears exactly once');
    } else {
      assert.ok(pcm.length >= originalPcm.length && pcm.length < originalPcm.length + 2304 * 4,
        'MP3 includes the entire song with only bounded encoder padding');
    }
    if (offset) assert.deepEqual(await fs.readdir(cacheRoot), []);
    else {
      const cached = await fetch(url, { signal: t.signal });
      assert.equal(Number(cached.headers.get('content-length')), bytes.length);
      assert.deepEqual(Buffer.from(await cached.arrayBuffer()), bytes);
      assert.equal(requests.length, 3, 'successful recovery publishes a complete cache');
    }
  });
}

for (const failure of [
  'wrong-offset', 'wrong-total', 'reversed-range', 'unknown-total', 'unsafe-integer',
  'other-unit', 'multiple-ranges', 'trailing-syntax', 'capped-range', 'multipart', 'missing-range', 'invalid-content-type',
  'missing-etag', 'changed-etag', 'changed-last-modified', 'suffix-length', 'encoding',
  'body-overrun', 'exhausted', 'cancel',
]) {
  test(`range recovery rejects ${failure} without publishing a partial transcode`, { timeout: 10000 }, async (t) => {
    await fs.mkdir('data', { recursive: true });
    const cacheRoot = await fs.mkdtemp(path.resolve('data/audio-range-reject-'));
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
    const requests = [];
    const { app, params } = await createFixture(t, (request, response) => {
      if (request.url.startsWith('/library/metadata/')) {
        response.end(JSON.stringify({ MediaContainer: { Metadata: [{
          type: 'track', ratingKey: '1', duration: 20000,
          Media: [{ container: 'wav', Part: [{ key: '/audio', size: source.length }] }],
        }] } }));
      } else if (request.url.startsWith('/audio')) {
        requests.push(request.headers);
        if (requests.length === 1) {
          response.writeHead(200, { 'content-type': 'audio/wav', 'content-length': source.length, etag, 'last-modified': lastModified });
          response.write(source.subarray(0, 65536), () => {
            const timer = setTimeout(() => response.destroy(), 20);
            timer.unref();
          });
          return;
        }
        const start = Number(request.headers.range?.slice(6, -1));
        const ranges = {
          'wrong-offset': `bytes ${start + 1}-${source.length - 1}/${source.length}`,
          'wrong-total': `bytes ${start}-${source.length}/${source.length + 1}`,
          'reversed-range': `bytes ${start}-${start - 1}/${source.length}`,
          'unknown-total': `bytes ${start}-${source.length - 1}/*`,
          'unsafe-integer': `bytes ${start}-9007199254740992/9007199254740993`,
          'other-unit': `items ${start}-${source.length - 1}/${source.length}`,
          'multiple-ranges': `bytes ${start}-${source.length - 1}/${source.length}, 0-1/${source.length}`,
          'trailing-syntax': `bytes ${start}-${source.length - 1}/${source.length}; extra=1`,
          'capped-range': `bytes ${start}-${source.length - 2}/${source.length}`,
        };
        const headers = {
          'content-type': 'audio/wav', 'content-length': source.length - start,
          etag, 'last-modified': lastModified,
          'content-range': ranges[failure] || `bytes ${start}-${source.length - 1}/${source.length}`,
        };
        if (failure === 'multipart') headers['content-type'] = 'Multipart/ByteRanges; boundary="range-boundary"';
        if (failure === 'missing-range') delete headers['content-range'];
        if (failure === 'invalid-content-type') headers['content-type'] = 'invalid type';
        if (failure === 'missing-etag') delete headers.etag;
        if (failure === 'changed-etag') headers.etag = '"changed"';
        if (failure === 'changed-last-modified') headers['last-modified'] = responseDate;
        if (failure === 'suffix-length') headers['content-length'] = source.length - start - 1;
        if (failure === 'encoding') headers['content-encoding'] = 'gzip';
        if (failure === 'body-overrun') delete headers['content-length'];
        response.writeHead(206, headers);
        if (failure === 'exhausted') {
          response.write(source.subarray(start, start + 65536), () => {
            const timer = setTimeout(() => response.destroy(), 20);
            timer.unref();
          });
        } else if (failure === 'cancel') {
          response.write(source.subarray(start, start + 32768));
          resolveReplacement({ closed: once(response, 'close') });
        } else if (failure === 'body-overrun') response.end(Buffer.concat([source.subarray(start), Buffer.from([0])]));
        else response.end(source.subarray(start, failure === 'suffix-length' ? -1 : undefined));
      } else response.end('{}');
    }, { transcodeCachePath: cacheRoot });
    await app.listen({ host: '127.0.0.1', port: 0 });
    const url = `http://127.0.0.1:${app.server.address().port}/rest/stream?${new URLSearchParams({ ...params, id: '1', format: 'mp3' })}`;
    if (failure === 'cancel') {
      const request = get(url, { signal: t.signal });
      const canceled = once(request, 'error');
      const { closed } = await replacement;
      request.destroy(new Error('player abandoned range recovery'));
      await canceled;
      await closed;
    } else {
      const response = await fetch(url, { signal: t.signal });
      if (response.status === 200) await assert.rejects(response.arrayBuffer(), { name: 'TypeError' });
      else {
        assert.equal(response.status, 500);
        const error = await response.json();
        const reason = failure.includes('etag') ? /Plex source etag changed/
          : failure === 'changed-last-modified' ? /Plex source last-modified changed/
          : failure === 'body-overrun' ? /Plex source recovery exceeded its Content-Range/
          : failure === 'exhausted' ? /Upstream stream terminated during transcode/
          : failure === 'invalid-content-type' ? /Plex source recovery returned an invalid Content-Type/
          : /Plex source recovery returned an invalid Content-Range response/;
        assert.match(error.message, reason);
      }
    }
    assert.equal(t.signal.aborted, false, 'failure must be handled without reaching the test deadline');
    assert.equal(requests.length, failure === 'exhausted' ? 3 : 2);
    for (const request of requests.slice(1)) {
      assert.match(request.range, /^bytes=[1-9]\d*-$/);
      assert.equal(request['if-range'], etag);
    }
    cleanupArmed = true;
    if ((await fs.readdir(cacheRoot)).length) await cleaned;
    cleanupArmed = false;
    assert.deepEqual(await fs.readdir(cacheRoot), []);
  });
}
