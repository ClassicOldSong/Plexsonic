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
import { watch } from 'node:fs';
import fs from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';
import { loadConfig } from '../src/config.js';
import { buildServer } from '../src/server.js';

test('transcode cleanup removes empty cache directories and keeps live files', async (t) => {
  await fs.mkdir('data', { recursive: true });
  const root = await fs.mkdtemp(path.resolve('data/review-cache-'));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  await fs.mkdir(path.join(root, 'empty'));
  await fs.mkdir(path.join(root, 'live'));
  await fs.writeFile(path.join(root, 'live', 'track.flac'), 'active');
  const watcher = watch(root);
  t.after(() => watcher.close());
  const removed = new Promise((resolve, reject) => {
    watcher.on('change', async (_, filename) => {
      if (filename !== 'empty') return;
      // macOS may deliver a queued creation event after watch() starts.
      // Only the observed deletion completes the wait; the assertion below is unchanged.
      try {
        await fs.stat(path.join(root, 'empty'));
      } catch (error) {
        if (error.code === 'ENOENT') resolve();
        else reject(error);
      }
    });
    watcher.on('error', reject);
    AbortSignal.timeout(2000).addEventListener('abort', () => reject(new Error('Empty directory was not removed')), { once: true });
  });
  removed.catch(() => {});
  const app = await buildServer(loadConfig({
    SQLITE_PATH: ':memory:', CACHE_SQLITE_PATH: ':memory:', LOG_LEVEL: 'silent',
    TRANSCODE_CACHE_PATH: root, TRANSCODE_CLEANUP_INTERVAL_SEC: '3600', TRANSCODE_ARTIFACT_MAX_AGE_SEC: '60',
  }));
  t.after(() => app.close());
  await removed;
  await assert.rejects(fs.stat(path.join(root, 'empty')), { code: 'ENOENT' });
  assert.equal(await fs.readFile(path.join(root, 'live', 'track.flac'), 'utf8'), 'active');
});
