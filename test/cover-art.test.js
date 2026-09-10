/* Copyright Yukino Song, SudoMaker Ltd.
 *
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 * 	http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { once } from 'node:events';
import { createServer } from 'node:http';
import { PassThrough, Readable } from 'node:stream';
import test from 'node:test';
import { loadConfig } from '../src/config.js';
import { resizeCoverArt } from '../src/cover-art.js';
import { buildServer } from '../src/server.js';
import { createTokenCipher } from '../src/token-crypto.js';

function makeImage(dimensions, codec = 'png') {
  return execFileSync('ffmpeg', [
    '-v', 'error', '-f', 'lavfi', '-i', `color=red@0.5:s=${dimensions},format=rgba`,
    '-frames:v', '1', '-threads', '1', '-c:v', codec, '-f', 'image2pipe', 'pipe:1',
  ]);
}

function inspectImage(image) {
  return JSON.parse(execFileSync('ffprobe', [
    '-v', 'error', '-show_entries', 'stream=codec_name,width,height,pix_fmt',
    '-of', 'json', 'pipe:0',
  ], { input: image, encoding: 'utf8' })).streams[0];
}

test('cover art sizes through authenticated GET and POST requests', async (t) => {
  const original = makeImage('320x160', 'mjpeg');
  const upstream = createServer((request, response) => {
    const pathname = new URL(request.url, 'http://fixture').pathname;
    if (pathname === '/missing') {
      response.writeHead(404);
      response.end('missing');
      return;
    }
    if (pathname === '/bad') {
      response.writeHead(200, { 'content-type': 'image/jpeg', etag: '"bad"' });
      response.end('not an image');
      return;
    }
    response.writeHead(200, {
      'content-type': 'image/jpeg',
      'content-length': original.length,
      'cache-control': 'private, max-age=3600',
      etag: '"original"',
    });
    response.end(original);
  });
  upstream.listen(0, '127.0.0.1');
  await once(upstream, 'listening');
  t.after(() => new Promise((resolve) => upstream.close(resolve)));

  const config = loadConfig({
    SQLITE_PATH: ':memory:', CACHE_SQLITE_PATH: ':memory:',
    TRANSCODE_CACHE_PATH: '.', TRANSCODE_CLEANUP_INTERVAL_SEC: '0', LOG_LEVEL: 'silent',
  });
  const app = await buildServer(config);
  t.after(() => app.close());
  const cipher = createTokenCipher({ fallbackSeed: config.sessionSecret });
  app.repo.createAccount({
    id: 'cover-test', username: 'cover-test', passwordHash: 'unused-token-auth',
    subsonicPasswordEnc: cipher.encrypt('password'),
  });
  app.repo.upsertSelectedServer({
    accountId: 'cover-test', machineId: 'fixture', name: 'fixture',
    baseUrl: `http://127.0.0.1:${upstream.address().port}`,
    encryptedServerToken: cipher.encrypt('fixture-token'),
  });
  app.repo.upsertSelectedLibrary({ accountId: 'cover-test', musicSectionId: '1' });
  const params = {
    u: 'cover-test', t: createHash('md5').update('passwordsalt').digest('hex'), s: 'salt',
    id: '/cover', f: 'json', v: '1.16.1', c: 'test',
  };

  for (const size of [undefined, '0', '-1', 'invalid', '12px', '1.5']) {
    await t.test(`original for size=${size}`, async () => {
      const query = new URLSearchParams({ ...params, ...(size === undefined ? {} : { size }) });
      const response = await app.inject(`/rest/getCoverArt.view?${query}`);
      assert.equal(response.statusCode, 200);
      assert.deepEqual(response.rawPayload, original);
      assert.equal(response.headers['content-type'], 'image/jpeg');
      assert.equal(response.headers.etag, '"original"');
    });
  }

  let previousEtag;
  for (const [method, size, width, height] of [
    ['GET', '80', 80, 80], ['POST', '40', 40, 40], ['GET', '1000', 160, 160],
  ]) {
    await t.test(`${method} size=${size}`, async () => {
      const query = new URLSearchParams({ ...params, size });
      const response = await app.inject(method === 'GET'
        ? `/rest/getCoverArt.view?${query}`
        : { method, url: '/rest/getCoverArt', headers: { 'content-type': 'application/x-www-form-urlencoded' }, payload: query.toString() });
      assert.equal(response.statusCode, 200);
      assert.equal(response.headers['content-type'], 'image/png');
      assert.equal(Number(response.headers['content-length']), response.rawPayload.length);
      assert.equal(response.headers['cache-control'], 'private, max-age=3600');
      assert.notEqual(response.headers.etag, '"original"');
      assert.notEqual(response.headers.etag, previousEtag);
      previousEtag = response.headers.etag;
      const image = inspectImage(response.rawPayload);
      assert.equal(image.codec_name, 'png');
      assert.equal(image.width, width);
      assert.equal(image.height, height);
    });
  }

  for (const [id, code] of [['/bad', 10], ['/missing', 70]]) {
    await t.test(`image failure for ${id}`, async () => {
      const query = new URLSearchParams({ ...params, id, size: '80' });
      const response = await app.inject(`/rest/getCoverArt.view?${query}`);
      assert.equal(response.json()['subsonic-response'].error.code, code);
      assert.match(response.headers['content-type'], /application\/json/);
      assert.equal(response.headers.etag, undefined);
      assert.equal(Number(response.headers['content-length']), response.rawPayload.length);
    });
  }
});

test('portrait, square, transparency, and one-pixel output', async () => {
  for (const [dimensions, size, width, height] of [
    ['160x320', 80, 80, 80], ['100x100', 33, 33, 33], ['320x160', 1, 1, 1],
  ]) {
    const image = await resizeCoverArt(Readable.from([makeImage(dimensions)]), size);
    const metadata = inspectImage(image);
    assert.equal(metadata.width, width);
    assert.equal(metadata.height, height);
    assert.equal(metadata.pix_fmt, 'rgba');
    const pixels = execFileSync('ffmpeg', [
      '-v', 'error', '-i', 'pipe:0', '-f', 'rawvideo', '-pix_fmt', 'rgba', 'pipe:1',
    ], { input: image });
    assert.ok(pixels[3] > 0 && pixels[3] < 255, 'alpha must remain translucent');
  }
});

test('non-square artwork crops the middle without stretching its contents', async () => {
  for (const [width, height] of [[128, 64], [64, 128], [129, 65], [65, 129]]) {
    const side = Math.min(width, height);
    const source = execFileSync('ffmpeg', [
      '-v', 'error', '-f', 'lavfi', '-i',
      `color=blue:s=${width}x${height},format=rgba,` +
      `drawbox=x=${(width - side) / 2}:y=${(height - side) / 2}:w=${side}:h=${side}:color=red:t=fill,` +
      `drawbox=x=${(width - 9) / 2}:y=${(height - 9) / 2}:w=9:h=9:color=lime:t=fill`,
      '-frames:v', '1', '-threads', '1', '-c:v', 'png', '-f', 'image2pipe', 'pipe:1',
    ]);
    // Keep native resolution so every pixel of the expected center crop is exact.
    const image = await resizeCoverArt(Readable.from([source]), 1000);
    const metadata = inspectImage(image);
    assert.equal(metadata.width, side);
    assert.equal(metadata.height, side);
    const pixels = execFileSync('ffmpeg', [
      '-v', 'error', '-i', 'pipe:0', '-f', 'rawvideo', '-pix_fmt', 'rgba', 'pipe:1',
    ], { input: image });
    const markerStart = Math.floor((side - 9) / 2);
    for (let y = 0; y < side; y += 1) {
      for (let x = 0; x < side; x += 1) {
        const inside = x >= markerStart && x < markerStart + 9 && y >= markerStart && y < markerStart + 9;
        const offset = (y * side + x) * 4;
        assert.deepEqual([...pixels.subarray(offset, offset + 4)], inside ? [0, 255, 0, 255] : [255, 0, 0, 255]);
      }
    }
  }
});

test('invalid images and broken sources reject instead of returning partial images', async () => {
  await assert.rejects(resizeCoverArt(Readable.from([Buffer.from('not an image')]), 80));
  const source = new PassThrough();
  const result = resizeCoverArt(source, 80);
  source.destroy(new Error('upstream failed'));
  await assert.rejects(result, /upstream failed/);
  assert.equal(source.destroyed, true);
});

test('cancellation stops image conversion and closes its source', async () => {
  const source = new PassThrough();
  const controller = new AbortController();
  const result = resizeCoverArt(source, 80, controller.signal);
  controller.abort();
  await assert.rejects(result, { name: 'AbortError' });
  assert.equal(source.destroyed, true);
});
