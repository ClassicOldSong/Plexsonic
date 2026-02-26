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

import 'dotenv/config';
import { createHash } from 'node:crypto';
import path from 'node:path';

const DEFAULT_PORT = 3127;
const DEFAULT_HOST = '127.0.0.1';
const DEFAULT_PLEX_PRODUCT = 'Plexsonic Bridge';
const DEFAULT_SESSION_SECRET = 'dev-session-secret-change-me-before-production-plexsonic';
const DEFAULT_LOG_LEVEL = 'warn';
const DEFAULT_LOG_REQUESTS = false;
const DEFAULT_TRANSCODE_CLEANUP_INTERVAL_SECONDS = 3600;
const DEFAULT_TRANSCODE_ARTIFACT_MAX_AGE_SECONDS = 604800;

function parsePort(rawPort) {
  const value = Number.parseInt(rawPort ?? `${DEFAULT_PORT}`, 10);
  if (!Number.isInteger(value) || value < 1 || value > 65535) {
    throw new Error(`Invalid PORT: ${rawPort}`);
  }
  return value;
}

function deriveClientIdentifier(seed) {
  return createHash('sha256').update(seed).digest('hex').slice(0, 32);
}

function normalizeSessionSecret(rawSecret) {
  const secret = rawSecret || DEFAULT_SESSION_SECRET;
  if (secret.length >= 32) {
    return secret;
  }
  return createHash('sha256').update(secret).digest('hex');
}

function parseBoolean(value, fallback = false) {
  if (value == null || value === '') {
    return fallback;
  }
  const normalized = String(value).trim().toLowerCase();
  return ['1', 'true', 'yes', 'on'].includes(normalized);
}

function parseNonNegativeInt(value, fallback) {
  if (value == null || value === '') {
    return fallback;
  }
  const parsed = Number.parseInt(String(value), 10);
  if (!Number.isFinite(parsed) || parsed < 0) {
    return fallback;
  }
  return parsed;
}

function normalizeOptionalBaseUrl(rawBaseUrl) {
  const value = String(rawBaseUrl || '').trim();
  if (!value) {
    return null;
  }
  try {
    const parsed = new URL(value);
    const normalizedPath = parsed.pathname.replace(/\/+$/, '');
    const pathname = normalizedPath && normalizedPath !== '/' ? normalizedPath : '';
    return `${parsed.protocol}//${parsed.host}${pathname}`;
  } catch {
    throw new Error(`Invalid BASE_URL: ${rawBaseUrl}`);
  }
}

export function loadConfig(env = process.env) {
  const port = parsePort(env.PORT);
  const bindHost = env.BIND_HOST || DEFAULT_HOST;
  const baseUrl = normalizeOptionalBaseUrl(env.BASE_URL);
  const sqlitePath = env.SQLITE_PATH || './data/app.db';
  const cacheSqlitePath = env.CACHE_SQLITE_PATH || './data/cache.db';
  const transcodeCachePath = env.TRANSCODE_CACHE_PATH || './data/transcodes';
  const transcodeCleanupIntervalSeconds = parseNonNegativeInt(
    env.TRANSCODE_CLEANUP_INTERVAL_SEC,
    DEFAULT_TRANSCODE_CLEANUP_INTERVAL_SECONDS,
  );
  const transcodeArtifactMaxAgeSeconds = parseNonNegativeInt(
    env.TRANSCODE_ARTIFACT_MAX_AGE_SEC,
    DEFAULT_TRANSCODE_ARTIFACT_MAX_AGE_SECONDS,
  );

  return {
    bindHost,
    baseUrl,
    port,
    sqlitePath,
    cacheSqlitePath,
    transcodeCachePath,
    transcodeCleanupIntervalSeconds,
    transcodeArtifactMaxAgeSeconds,
    sessionSecret: normalizeSessionSecret(env.SESSION_SECRET),
    tokenEncKey: env.TOKEN_ENC_KEY || null,
    plexInsecureTls: env.PLEX_INSECURE_TLS === '1',
    plexProduct: env.PLEX_PRODUCT || DEFAULT_PLEX_PRODUCT,
    plexClientIdentifier:
      env.PLEX_CLIENT_IDENTIFIER || deriveClientIdentifier(path.resolve(sqlitePath)),
    plexWebhookToken: env.PLEX_WEBHOOK_TOKEN || '',
    licenseEmail: env.LICENSE_EMAIL || '',
    logLevel: env.LOG_LEVEL || DEFAULT_LOG_LEVEL,
    logRequests: parseBoolean(env.LOG_REQUESTS, DEFAULT_LOG_REQUESTS),
  };
}
