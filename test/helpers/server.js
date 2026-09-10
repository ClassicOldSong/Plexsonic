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

import { createHash } from 'node:crypto';
import { once } from 'node:events';
import { createServer } from 'node:http';
import argon2 from 'argon2';
import { loadConfig } from '../../src/config.js';
import { buildServer } from '../../src/server.js';
import { createTokenCipher } from '../../src/token-crypto.js';

export async function createFixture(t, handler, configOverrides = {}) {
  const upstream = createServer(handler);
  upstream.listen(0, '127.0.0.1');
  await once(upstream, 'listening');
  t.after(() => new Promise((resolve) => {
    upstream.closeAllConnections();
    upstream.close(resolve);
  }));
  const config = { ...loadConfig({
    SQLITE_PATH: ':memory:', CACHE_SQLITE_PATH: ':memory:',
    TRANSCODE_CACHE_PATH: '.', TRANSCODE_CLEANUP_INTERVAL_SEC: '0', LOG_LEVEL: 'silent',
  }), ...configOverrides };
  const app = await buildServer(config);
  t.after(() => app.close());
  const cipher = createTokenCipher({ fallbackSeed: config.sessionSecret });
  app.repo.createAccount({
    id: 'test', username: 'tester', passwordHash: await argon2.hash('password'),
    subsonicPasswordEnc: cipher.encrypt('password'),
  });
  const baseUrl = `http://127.0.0.1:${upstream.address().port}`;
  app.repo.upsertSelectedServer({
    accountId: 'test', machineId: 'fixture', name: 'fixture', baseUrl,
    encryptedServerToken: cipher.encrypt('fixture-token'),
  });
  app.repo.upsertSelectedLibrary({ accountId: 'test', musicSectionId: '1' });
  const params = {
    u: 'tester', t: createHash('md5').update('passwordsalt').digest('hex'), s: 'salt',
    f: 'json', v: '1.16.1', c: 'test',
  };
  const cacheKey = `plex-${createHash('md5').update('fixture-token').digest('hex')}:fixture:1`;
  return { app, baseUrl, params, cacheKey };
}
