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
import test from 'node:test';
import { buildPmsAssetUrl } from '../src/plex.js';

test('Plex asset paths cannot send the token to another origin', () => {
  for (const path of ['///untrusted.invalid/art', '//\\untrusted.invalid/art', 'https://untrusted.invalid/art']) {
    assert.throws(() => buildPmsAssetUrl('https://plex.example/base', 'secret', path), /origin/);
  }
});

test('Plex URL construction preserves reverse-proxy prefixes, escaping, and query parameters', () => {
  const url = buildPmsAssetUrl('https://plex.example/base', 'a&b', '/library/metadata/12/thumb/123?size=200');
  assert.equal(url.origin, 'https://plex.example');
  assert.equal(url.pathname, '/base/library/metadata/12/thumb/123');
  assert.equal(url.searchParams.get('size'), '200');
  assert.equal(url.searchParams.get('X-Plex-Token'), 'a&b');
});
