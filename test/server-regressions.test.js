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
import { EventEmitter, once } from 'node:events';
import test from 'node:test';
import { encodeChoicePayload } from '../src/html.js';
import { createFixture } from './helpers/server.js';

test('empty collections are cached independently', async (t) => {
  const counts = new Map();
  const { app, params } = await createFixture(t, (request, response) => {
    const url = new URL(request.url, 'http://fixture');
    const type = url.searchParams.get('type');
    counts.set(type, (counts.get(type) || 0) + 1);
    response.end(JSON.stringify({ MediaContainer: { totalSize: 0, Metadata: [], Directory: [] } }));
  });
  for (let i = 0; i < 3; i += 1) {
    const response = await app.inject(`/rest/getArtists?${new URLSearchParams(params)}`);
    assert.equal(response.json()['subsonic-response'].status, 'ok');
  }
  assert.equal(counts.get('8'), 1);
  const genres = await app.inject(`/rest/getGenres?${new URLSearchParams(params)}`);
  assert.equal(genres.json()['subsonic-response'].status, 'ok');
  assert.ok(counts.get('10') >= 1, 'loading artists must not mark tracks as loaded');
});

test('cover art uses one metadata request for a track', async (t) => {
  let metadataRequests = 0;
  const { app, params } = await createFixture(t, (request, response) => {
    if (request.url.startsWith('/library/metadata/')) {
      metadataRequests += 1;
      response.end(JSON.stringify({ MediaContainer: { Metadata: [{ type: 'track', ratingKey: '1', parentThumb: '/art' }] } }));
    } else {
      response.setHeader('content-type', 'image/jpeg');
      response.end('original image');
    }
  });
  const response = await app.inject(`/rest/getCoverArt?${new URLSearchParams({ ...params, id: '1' })}`);
  assert.equal(response.body, 'original image');
  assert.equal(metadataRequests, 1);
});

test('stream and download accept form POST ids', async (t) => {
  const { app, params } = await createFixture(t, (request, response) => {
    if (request.url.startsWith('/library/metadata/')) {
      response.end(JSON.stringify({ MediaContainer: { Metadata: [{
        type: 'track', ratingKey: '1', Media: [{ container: 'mp3', Part: [{ key: '/audio' }] }],
      }] } }));
    } else {
      response.end('audio bytes');
    }
  });
  for (const endpoint of ['download', 'stream']) {
    const response = await app.inject({
      method: 'POST', url: `/rest/${endpoint}`,
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      payload: new URLSearchParams({ ...params, id: '1' }).toString(),
    });
    assert.equal(response.body, 'audio bytes');
  }
});

test('saved queues preserve alias ids and duplicate occurrences without refetching cached tracks', async (t) => {
  let metadataRequests = 0;
  const { app, params, cacheKey } = await createFixture(t, (request, response) => {
    metadataRequests += 1;
    response.writeHead(404).end();
  });
  app.cacheDb.prepare(`INSERT INTO plex_library_cache_state
    (cache_key, last_synced_at, last_checked_at, updated_at) VALUES (?, ?, ?, ?)`)
    .run(cacheKey, Math.floor(Date.now() / 1000), Date.now(), Math.floor(Date.now() / 1000));
  app.cacheDb.prepare(`INSERT INTO plex_library_cache_tracks
    (cache_key, rating_key, guid, title, updated_cache_at) VALUES (?, '1', 'local://song', 'Song', ?)`)
    .run(cacheKey, Math.floor(Date.now() / 1000));
  const query = new URLSearchParams(params);
  for (const id of ['local://song', '1', 'local://song']) query.append('id', id);
  const saved = await app.inject(`/rest/savePlayQueue?${query}`);
  assert.equal(saved.json()['subsonic-response'].status, 'ok');
  const result = await app.inject(`/rest/getPlayQueue?${new URLSearchParams(params)}`);
  assert.deepEqual(result.json()['subsonic-response'].playQueue.entry.map((entry) => entry.id), ['1', '1', '1']);
  assert.equal(metadataRequests, 0);
});

test('warm-up retries after recovery with the same cache key', async (t) => {
  const events = new EventEmitter();
  let artistRequests = 0;
  const { app } = await createFixture(t, (request, response) => {
    const url = new URL(request.url, 'http://fixture');
    if (url.pathname === '/library/sections') {
      response.end(JSON.stringify({ MediaContainer: { Directory: [{ key: '1', title: 'Music', type: 'artist' }] } }));
      return;
    }
    if (url.searchParams.get('type') === '8') {
      artistRequests += 1;
      if (artistRequests === 1) {
        response.writeHead(503).end('temporary failure');
        return;
      }
      events.emit('retried');
    }
    response.end(JSON.stringify({ MediaContainer: { Metadata: [], totalSize: 0 } }));
    if (url.searchParams.get('type') === '10') events.emit('tracks');
  });
  const login = await app.inject({ method: 'POST', url: '/auth/login', payload: { username: 'tester', password: 'password' } });
  const retry = once(events, 'retried', { signal: AbortSignal.timeout(2000) });
  const tracks = once(events, 'tracks', { signal: AbortSignal.timeout(2000) });
  // Attach handlers immediately so a timeout reports an assertion rather than an unhandled rejection.
  const finished = Promise.all([retry, tracks]);
  finished.catch(() => {});
  await app.inject({ method: 'POST', url: '/link/plex/library',
    headers: { cookie: login.headers['set-cookie'].split(';')[0] },
    payload: { libraryChoice: encodeChoicePayload({ id: '1', title: 'Music' }) },
  });
  await finished;
  assert.equal(artistRequests, 2);
});

test('stream failures return Subsonic errors after a real POST body has completed', async (t) => {
  const { app, params } = await createFixture(t, (request) => request.socket.destroy());
  await app.listen({ host: '127.0.0.1', port: 0 });
  const response = await fetch(`http://127.0.0.1:${app.server.address().port}/rest/stream`, {
    method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ ...params, id: '1' }), signal: AbortSignal.timeout(2000),
  });
  assert.equal(response.status, 200);
  assert.equal((await response.json())['subsonic-response'].error.code, 70);
});

test('failed background refresh leaves usable stale data and can be retried', async (t) => {
  const events = new EventEmitter();
  let refreshRequests = 0;
  const { app, params, cacheKey } = await createFixture(t, (request, response) => {
    const url = new URL(request.url, 'http://fixture');
    if (url.pathname === '/library/sections') {
      response.end(JSON.stringify({ MediaContainer: { Directory: [{ key: '1', type: 'artist' }] } }));
    } else if (url.searchParams.get('type') === '8') {
      refreshRequests += 1;
      response.writeHead(503).end('offline');
      events.emit('failed');
    } else {
      response.end(JSON.stringify({ MediaContainer: { totalSize: 0, Metadata: [] } }));
    }
  });
  app.cacheDb.prepare(`INSERT INTO plex_library_cache_state
    (cache_key, last_fingerprint, last_synced_at, updated_at) VALUES (?, 'old', ?, ?)`)
    .run(cacheKey, Math.floor(Date.now() / 1000), Math.floor(Date.now() / 1000));
  app.cacheDb.prepare(`INSERT INTO plex_library_cache_artists
    (cache_key, rating_key, title, updated_cache_at) VALUES (?, '1', 'Cached Artist', ?)`)
    .run(cacheKey, Math.floor(Date.now() / 1000));
  const failed = once(events, 'failed', { signal: AbortSignal.timeout(2000) });
  const url = `/rest/getArtists?${new URLSearchParams(params)}`;
  assert.equal((await app.inject(url)).json()['subsonic-response'].status, 'ok');
  await failed;
  assert.equal((await app.inject(url)).json()['subsonic-response'].status, 'ok');
  assert.equal(app.cacheDb.prepare('SELECT dirty FROM plex_library_cache_state WHERE cache_key = ?').get(cacheKey).dirty, 1);
  assert.ok(refreshRequests >= 1);
});

test('random-song limits and genre pages operate on distinct cached songs', async (t) => {
  const { app, params, cacheKey } = await createFixture(t, (_, response) => response.writeHead(500).end());
  const now = Math.floor(Date.now() / 1000);
  app.cacheDb.prepare(`INSERT INTO plex_library_cache_state
    (cache_key, last_synced_at, last_checked_at, updated_at) VALUES (?, ?, ?, ?)`)
    .run(cacheKey, now, Date.now(), now);
  const insert = app.cacheDb.prepare(`INSERT INTO plex_library_cache_tracks
    (cache_key, rating_key, title, updated_cache_at) VALUES (?, ?, ?, ?)`);
  app.cacheDb.transaction(() => {
    for (let i = 0; i < 100; i += 1) insert.run(cacheKey, String(i), `Track ${i}`, now);
  })();
  for (const genre of ['Rock', 'rock']) {
    app.cacheDb.prepare(`INSERT INTO plex_library_cache_track_genres
      (cache_key, track_rating_key, genre_name) VALUES (?, '0', ?)`)
      .run(cacheKey, genre);
  }
  const random = await app.inject({ method: 'POST', url: '/rest/getRandomSongs',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    payload: new URLSearchParams({ ...params, size: '7' }).toString(),
  });
  const songs = random.json()['subsonic-response'].randomSongs.song;
  assert.equal(songs.length, 7);
  assert.equal(new Set(songs.map((song) => song.id)).size, 7);
  const genres = await app.inject(`/rest/getSongsByGenre?${new URLSearchParams({ ...params, genre: 'rock' })}`);
  assert.equal(genres.headers['x-total-count'], '1');
  assert.equal(genres.json()['subsonic-response'].songsByGenre.song.length, 1);
});
