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

import { createHash, createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';

const VERSION = 1;
const IV_LENGTH = 12;
const TAG_LENGTH = 16;

function decodeKey(raw) {
  if (!raw) {
    return null;
  }

  if (/^[0-9a-fA-F]{64}$/.test(raw)) {
    return Buffer.from(raw, 'hex');
  }

  try {
    const decoded = Buffer.from(raw, 'base64');
    if (decoded.length === 32) {
      return decoded;
    }
  } catch {
    // ignored
  }

  return null;
}

function keyFromSeed(seed) {
  return createHash('sha256').update(seed).digest();
}

export function createTokenCipher({ rawKey, fallbackSeed }) {
  const key = decodeKey(rawKey) || keyFromSeed(fallbackSeed);

  return {
    hasExplicitKey: Boolean(decodeKey(rawKey)),

    encrypt(plainText) {
      const iv = randomBytes(IV_LENGTH);
      const cipher = createCipheriv('aes-256-gcm', key, iv);
      const ciphertext = Buffer.concat([cipher.update(String(plainText), 'utf8'), cipher.final()]);
      const tag = cipher.getAuthTag();

      return Buffer.concat([Buffer.from([VERSION]), iv, tag, ciphertext]);
    },

    decrypt(blob) {
      const input = Buffer.isBuffer(blob) ? blob : Buffer.from(blob);
      const version = input.readUInt8(0);
      if (version !== VERSION) {
        throw new Error('Unsupported token blob version');
      }

      const iv = input.subarray(1, 1 + IV_LENGTH);
      const tag = input.subarray(1 + IV_LENGTH, 1 + IV_LENGTH + TAG_LENGTH);
      const ciphertext = input.subarray(1 + IV_LENGTH + TAG_LENGTH);

      const decipher = createDecipheriv('aes-256-gcm', key, iv);
      decipher.setAuthTag(tag);

      return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8');
    },
  };
}
