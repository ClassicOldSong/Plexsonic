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
import { once } from 'node:events';
import { createServer } from 'node:http';
import test from 'node:test';
import { listArtists, listPlexPlaylistItems, listPlexPlaylists } from '../src/plex.js';

test('Plex paging follows totalSize when the server caps pages and preserves playlist occurrences', async (t) => {
  const entries = Array.from({ length: 5 }, (_, i) => ({
    ratingKey: String(i % 2), playlistItemID: String(i + 10),
  }));
  const starts = [];
  const server = createServer((request, response) => {
    const url = new URL(request.url, 'http://fixture');
    const start = Number(url.searchParams.get('X-Plex-Container-Start') || 0);
    starts.push(start);
    response.setHeader('content-type', 'application/json');
    const items = url.pathname.endsWith('/items')
      ? entries : entries.map((entry) => ({ ratingKey: entry.playlistItemID }));
    response.end(JSON.stringify({ MediaContainer: { totalSize: 5, Metadata: items.slice(start, start + 2) } }));
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const options = { baseUrl: `http://127.0.0.1:${server.address().port}`, plexToken: 'fixture', sectionId: '1', playlistId: '1' };
  for (const loader of [listArtists, listPlexPlaylists, listPlexPlaylistItems]) {
    starts.length = 0;
    const items = await loader(options);
    assert.equal(items.length, 5);
    assert.deepEqual(starts, [0, 2, 4]);
    if (loader === listPlexPlaylistItems) {
      assert.deepEqual(items, entries);
    }
  }
});
