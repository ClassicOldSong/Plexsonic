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

import { spawn } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import path from 'node:path';
import { PassThrough, Readable } from 'node:stream';
import Fastify from 'fastify';
import argon2 from 'argon2';
import fastifyCookie from '@fastify/cookie';
import fastifyFormbody from '@fastify/formbody';
import fastifyMultipart from '@fastify/multipart';
import fastifySession from '@fastify/session';
import { loadConfig } from './config.js';
import { createRepositories, migrate, migrateCache, openDatabase } from './db.js';
import {
  decodeChoicePayload,
  encodeChoicePayload,
  linkedPlexPage,
  linkPlexPage,
  loginPage,
  plexLibraryPage,
  plexPinPage,
  plexServerPage,
  signupPage,
  testPage,
} from './html.js';
import {
  addItemsToPlexPlaylist,
  buildPmsAssetUrl,
  createPlexPlaylist,
  createPlexPin,
  deletePlexPlaylist,
  fetchPlexTrackLyricsCandidates,
  getAlbum,
  getArtist,
  getTrack,
  listAlbums,
  listAlbumTracks,
  listArtistAlbums,
  listArtistTracks,
  listArtists,
  listPlexPlaylistItems,
  listPlexPlaylists,
  listPlexSectionFolder,
  listTracks,
  listMusicSections,
  listPlexServers,
  pollPlexPin,
  probeSectionFingerprint,
  ratePlexItem,
  removePlexPlaylistItems,
  renamePlexPlaylist,
  searchSectionHubs,
  searchSectionMetadata,
  scrobblePlexItem,
  startPlexSectionScan,
  updatePlexPlaybackStatus,
} from './plex.js';
import { createTokenCipher } from './token-crypto.js';
import { failedResponse, failedResponseJson, okResponse, okResponseJson } from './subsonic-xml.js';

const USERNAME_PATTERN = /^[A-Za-z0-9_.-]{3,32}$/;
const DEFAULT_CORS_ALLOW_HEADERS = [
  'Accept',
  'Authorization',
  'Content-Type',
  'X-Requested-With',
  'X-Plex-Token',
  'X-Plex-Client-Identifier',
  'X-Plex-Product',
  'X-Plex-Version',
  'X-Plex-Platform',
  'X-Plex-Device',
  'X-Plex-Device-Name',
  'X-Plex-Model',
].join(', ');
const DEFAULT_CORS_ALLOW_METHODS = 'GET, POST, PUT, PATCH, DELETE, OPTIONS';
const DEFAULT_CORS_EXPOSE_HEADERS = 'content-type, content-length, content-range, accept-ranges, etag, last-modified';
const CACHE_INVALIDATING_PLEX_MEDIA_EVENTS = new Set([
  'media.add',
  'media.delete',
]);
const CACHE_PATCHABLE_PLEX_MEDIA_EVENTS = new Set([
  'media.rate',
  'media.unrate',
]);
const TRANSCODE_SUPPORTED_FORMATS = new Set(['mp3', 'aac', 'opus', 'flac']);
const TRANSCODE_DEFAULT_BITRATE_KBPS = {
  mp3: 192,
  aac: 256,
  opus: 128,
};
const TRANSCODE_BITRATE_LIMITS_KBPS = {
  mp3: { min: 32, max: 320 },
  aac: { min: 32, max: 320 },
  opus: { min: 24, max: 256 },
};
const TRANSCODE_CACHE_VERSION = 'v1';
const RANGE_NOT_SATISFIABLE_BODY = 'invalid range: failed to overlap\n';
const DEFAULT_UPSTREAM_HEADERS_TIMEOUT_MS = 15000;
const UPSTREAM_HEADERS_TIMEOUT_REASON = Symbol('upstream-headers-timeout');

function applyCorsHeaders(request, reply) {
  const origin = firstForwardedValue(request.headers?.origin);
  if (origin) {
    reply.header('access-control-allow-origin', origin);
    reply.header('vary', 'Origin');
  } else {
    reply.header('access-control-allow-origin', '*');
  }

  reply.header('access-control-allow-methods', DEFAULT_CORS_ALLOW_METHODS);

  const requestedHeaders = firstForwardedValue(request.headers?.['access-control-request-headers']);
  reply.header('access-control-allow-headers', requestedHeaders || DEFAULT_CORS_ALLOW_HEADERS);
  reply.header('access-control-expose-headers', DEFAULT_CORS_EXPOSE_HEADERS);
  reply.header('access-control-max-age', '86400');
}

function normalizeUsername(value) {
  return String(value || '').trim();
}

function normalizePassword(value) {
  return String(value || '');
}

function logFailedLoginAttempt(request, { username = '', route = '', mechanism = 'password', reason = '', hasPassword = false }) {
  const normalizedRoute = route || String(request.url || '').split('?')[0] || 'unknown';
  request.log.warn({
    event: 'auth_failed',
    route: normalizedRoute,
    username: username || '(missing)',
    mechanism,
    reason,
    password: hasPassword ? '[REDACTED]' : '[MISSING]',
    ip: request.ip,
    userAgent: request.headers?.['user-agent'] || '',
  }, 'Authentication failed');
}

function sqliteIsUniqueViolation(error) {
  return error?.code === 'SQLITE_CONSTRAINT_UNIQUE';
}

function getRouteNotice(request) {
  const notice = request.query?.notice;
  return typeof notice === 'string' ? notice : '';
}

function getQueryString(request, key) {
  const value = request.query?.[key];
  return typeof value === 'string' ? value : '';
}

function getQueryFirst(request, key) {
  const value = request.query?.[key];
  if (typeof value === 'string') {
    return value;
  }
  if (Array.isArray(value) && typeof value[0] === 'string') {
    return value[0];
  }
  return '';
}

function getBodyString(request, key) {
  const value = request.body?.[key];
  return typeof value === 'string' ? value : '';
}

function getBodyFirst(request, key) {
  const value = request.body?.[key];
  if (typeof value === 'string') {
    return value;
  }
  if (Array.isArray(value) && typeof value[0] === 'string') {
    return value[0];
  }
  return '';
}

function getBodyFieldValue(body, key) {
  const value = body?.[key];
  if (typeof value === 'string') {
    return value;
  }
  if (value && typeof value === 'object' && typeof value.value === 'string') {
    return value.value;
  }
  return '';
}

function parsePlexWebhookPayload(body) {
  const parseMaybeJson = (value) => {
    if (!value || typeof value !== 'string') {
      return null;
    }

    try {
      return JSON.parse(value);
    } catch {
      return null;
    }
  };

  if (!body) {
    return null;
  }

  if (typeof body === 'string') {
    return parseMaybeJson(body);
  }

  if (typeof body !== 'object') {
    return null;
  }

  const payloadField = getBodyFieldValue(body, 'payload');
  const parsedPayload = parseMaybeJson(payloadField);
  if (parsedPayload && typeof parsedPayload === 'object') {
    return parsedPayload;
  }

  if (body.event || body.Metadata || body.Account || body.Server) {
    return body;
  }

  return null;
}

function isMusicWebhookPayload(payload) {
  const metadata = payload?.Metadata || payload?.metadata || null;
  if (!metadata) {
    return true;
  }

  const sectionType = safeLower(metadata.librarySectionType);
  if (sectionType) {
    return sectionType === 'music' || sectionType === 'artist';
  }

  const metadataType = safeLower(metadata.type);
  if (!metadataType) {
    return true;
  }

  return metadataType === 'track' ||
    metadataType === 'album' ||
    metadataType === 'artist' ||
    metadataType === 'playlist';
}

function shouldInvalidateCacheForPlexWebhook(payload) {
  if (!payload || !isMusicWebhookPayload(payload)) {
    return false;
  }

  const event = safeLower(payload.event);
  if (!event) {
    return false;
  }

  if (event.startsWith('library.')) {
    return true;
  }

  return CACHE_INVALIDATING_PLEX_MEDIA_EVENTS.has(event);
}

function isRatingPatchableWebhookEvent(event) {
  return CACHE_PATCHABLE_PLEX_MEDIA_EVENTS.has(safeLower(event));
}

function extractRatingPatchFromWebhook(payload) {
  if (!payload) {
    return null;
  }

  const event = safeLower(payload.event);
  if (!isRatingPatchableWebhookEvent(event)) {
    return null;
  }

  const metadata = payload.Metadata || payload.metadata || {};
  const ratingKey = String(metadata.ratingKey || '').trim();
  if (!ratingKey) {
    return null;
  }

  if (event === 'media.unrate') {
    return {
      itemIds: [ratingKey],
      userRating: 0,
    };
  }

  const explicitRating = normalizePlexRating(
    metadata.userRating ?? metadata.rating ?? payload.userRating ?? payload.rating,
  );
  if (explicitRating != null) {
    return {
      itemIds: [ratingKey],
      userRating: explicitRating,
    };
  }

  return null;
}

function getRequestParam(request, key) {
  const fromQuery = getQueryFirst(request, key);
  if (fromQuery) {
    return fromQuery;
  }
  return getBodyFirst(request, key);
}

function getRequestParamValues(request, key) {
  const normalizeMultiValue = (value) => {
    if (Array.isArray(value)) {
      return value
        .flatMap((entry) => String(entry).split(','))
        .map((entry) => entry.trim())
        .filter(Boolean);
    }
    if (typeof value === 'string') {
      return value
        .split(',')
        .map((entry) => entry.trim())
        .filter(Boolean);
    }
    return [];
  };

  const fromQuery = request.query?.[key];
  const queryValues = normalizeMultiValue(fromQuery);
  if (queryValues.length > 0) {
    return queryValues;
  }

  const fromBody = request.body?.[key];
  const bodyValues = normalizeMultiValue(fromBody);
  if (bodyValues.length > 0) {
    return bodyValues;
  }

  return [];
}

function normalizeRestViewPath(urlPath) {
  const raw = String(urlPath || '');
  if (!raw.startsWith('/rest/')) {
    return raw;
  }

  const [pathname, query = ''] = raw.split('?', 2);
  const restSegment = pathname.slice('/rest/'.length);
  if (!restSegment || restSegment === '*') {
    return raw;
  }

  const normalizedSegment = restSegment.endsWith('/') ? restSegment.slice(0, -1) : restSegment;
  if (!normalizedSegment || normalizedSegment.includes('/') || normalizedSegment.endsWith('.view')) {
    return raw;
  }

  const rewrittenPath = `/rest/${normalizedSegment}.view`;
  return query ? `${rewrittenPath}?${query}` : rewrittenPath;
}

function uniqueNonEmptyValues(values) {
  return [...new Set(values.map((value) => String(value || '').trim()).filter(Boolean))];
}

function firstForwardedValue(headerValue) {
  if (Array.isArray(headerValue)) {
    for (const value of headerValue) {
      const first = firstForwardedValue(value);
      if (first) {
        return first;
      }
    }
    return '';
  }
  return String(headerValue || '')
    .split(',')[0]
    .trim();
}

function requestPublicOrigin(request, config) {
  if (config.baseUrl) {
    return config.baseUrl;
  }

  const forwardedProto = firstForwardedValue(request.headers?.['x-forwarded-proto']);
  const forwardedHost = firstForwardedValue(request.headers?.['x-forwarded-host']);
  const forwardedPort = firstForwardedValue(request.headers?.['x-forwarded-port']);

  const protocol = forwardedProto || request.protocol || 'http';
  let host = forwardedHost || String(request.headers?.host || '').trim();

  if (!host) {
    const refererHeader =
      firstForwardedValue(request.headers?.referer) || firstForwardedValue(request.headers?.referrer);
    if (refererHeader) {
      try {
        host = new URL(refererHeader).host || '';
      } catch { }
    }
  }

  if (!host) {
    const fallbackHost = config.bindHost && config.bindHost !== '0.0.0.0' ? config.bindHost : 'localhost';
    host = `${fallbackHost}:${config.port}`;
  }

  if (forwardedPort && !host.includes(':')) {
    host = `${host}:${forwardedPort}`;
  }

  return `${protocol}://${host}`;
}

function wantsXmlSubsonic(request) {
  const format = safeLower(getRequestParam(request, 'f'));
  if (format === 'xml') {
    return true;
  }
  if (format === 'json') {
    return false;
  }

  const accept = safeLower(request.headers?.accept || '');
  if (accept.includes('application/json')) {
    return false;
  }
  if (accept.includes('application/xml') || accept.includes('text/xml')) {
    return true;
  }

  // Default to XML unless query/body explicitly requests JSON or Accept prefers JSON.
  return true;
}

function sendSubsonicError(reply, code, message, statusCode = 200) {
  if (!wantsXmlSubsonic(reply.request)) {
    const payload = JSON.stringify(failedResponseJson(code, message));
    return reply
      .code(statusCode)
      .type('application/json; charset=utf-8')
      .header('content-length', String(Buffer.byteLength(payload)))
      .header('connection', 'close')
      .send(payload);
  }
  const payload = failedResponse(code, message);

  return reply
    .code(statusCode)
    .type('application/xml; charset=utf-8')
    .header('content-length', String(Buffer.byteLength(payload)))
    .header('connection', 'close')
    .send(payload);
}

function sendSubsonicOk(reply, inner) {
  if (!wantsXmlSubsonic(reply.request)) {
    const payload = JSON.stringify(okResponseJson(inner));
    return reply
      .type('application/json; charset=utf-8')
      .header('content-length', String(Buffer.byteLength(payload)))
      .header('connection', 'close')
      .send(payload);
  }
  const payload = okResponse(inner);
  return reply
    .type('application/xml; charset=utf-8')
    .header('content-length', String(Buffer.byteLength(payload)))
    .header('connection', 'close')
    .send(payload);
}

async function requireWebSessionAccount(request, reply, repo) {
  const accountId = request.session.accountId;
  if (!accountId) {
    if (repo.hasAnyAccount()) {
      reply.redirect('/login?notice=Sign%20in%20first');
      return null;
    }
    reply.redirect('/signup?notice=Create%20an%20account%20first');
    return null;
  }

  const account = repo.getAccountById(accountId);
  if (!account) {
    await request.session.destroy();
    reply.redirect('/signup?notice=Session%20expired');
    return null;
  }

  return account;
}

function md5HexUtf8(value) {
  return createHash('md5').update(value, 'utf8').digest('hex');
}

function decodePasswordParam(rawPassword) {
  if (!rawPassword.startsWith('enc:')) {
    return rawPassword;
  }

  const hex = rawPassword.slice(4);
  if (!hex || hex.length % 2 !== 0 || !/^[0-9a-fA-F]+$/.test(hex)) {
    return null;
  }

  try {
    return Buffer.from(hex, 'hex').toString('utf8');
  } catch {
    return null;
  }
}

function syncStoredSubsonicPassword(repo, tokenCipher, account, clearPassword) {
  const normalizedPassword = String(clearPassword || '');
  if (!account || !account.id || !normalizedPassword) {
    return;
  }

  let shouldUpdate = false;
  if (!account.subsonic_password_enc) {
    shouldUpdate = true;
  } else {
    try {
      const decrypted = tokenCipher.decrypt(account.subsonic_password_enc);
      if (decrypted !== normalizedPassword) {
        shouldUpdate = true;
      }
    } catch {
      shouldUpdate = true;
    }
  }

  if (shouldUpdate) {
    repo.updateSubsonicPasswordEnc(account.id, tokenCipher.encrypt(normalizedPassword));
  }
}

async function authenticateSubsonicRequest(request, reply, repo, tokenCipher) {
  const username = normalizeUsername(getRequestParam(request, 'u'));
  const passwordRaw = normalizePassword(getRequestParam(request, 'p'));
  const token = getRequestParam(request, 't');
  const salt = getRequestParam(request, 's');
  const apiKey = getRequestParam(request, 'apiKey');

  const hasTokenAuth = token !== '' || salt !== '';
  // Some clients send both legacy and token params together; prefer token auth when present.
  const hasPasswordAuth = !hasTokenAuth && passwordRaw !== '';
  const hasApiKeyAuth = apiKey !== '';
  const authMechanisms = [hasPasswordAuth, hasTokenAuth, hasApiKeyAuth].filter(Boolean).length;

  if (authMechanisms === 0) {
    sendSubsonicError(reply, 10, 'Required credential parameters are missing');
    return null;
  }

  if (authMechanisms > 1) {
    sendSubsonicError(reply, 43, 'Multiple conflicting authentication mechanisms provided');
    return null;
  }

  if (hasApiKeyAuth) {
    sendSubsonicError(reply, 42, 'Provided authentication mechanism not supported');
    return null;
  }

  if (!username) {
    sendSubsonicError(reply, 10, 'Required parameter is missing');
    return null;
  }

  const account = repo.getAccountByUsername(username);
  if (!account || account.enabled !== 1) {
    logFailedLoginAttempt(request, {
      username,
      route: '/rest/*',
      mechanism: hasPasswordAuth ? 'password' : 'token',
      reason: 'account_not_found_or_disabled',
      hasPassword: hasPasswordAuth,
    });
    sendSubsonicError(reply, 40, 'Wrong username or password');
    return null;
  }

  if (hasPasswordAuth) {
    const decodedPassword = decodePasswordParam(passwordRaw);
    if (decodedPassword == null) {
      logFailedLoginAttempt(request, {
        username,
        route: '/rest/*',
        mechanism: 'password',
        reason: 'password_decode_failed',
        hasPassword: true,
      });
      sendSubsonicError(reply, 40, 'Wrong username or password');
      return null;
    }

    const valid = await argon2.verify(account.password_hash, decodedPassword);
    if (!valid) {
      logFailedLoginAttempt(request, {
        username,
        route: '/rest/*',
        mechanism: 'password',
        reason: 'password_mismatch',
        hasPassword: true,
      });
      sendSubsonicError(reply, 40, 'Wrong username or password');
      return null;
    }

    syncStoredSubsonicPassword(repo, tokenCipher, account, decodedPassword);

    return account;
  }

  if (!token || !salt) {
    sendSubsonicError(reply, 10, 'Required parameter is missing');
    return null;
  }

  if (!account.subsonic_password_enc) {
    sendSubsonicError(
      reply,
      41,
      'Token authentication is unavailable for this account until one successful password login.',
    );
    return null;
  }

  let clearPassword;
  try {
    clearPassword = tokenCipher.decrypt(account.subsonic_password_enc);
  } catch {
    sendSubsonicError(
      reply,
      41,
      'Token authentication is unavailable for this account until one successful password login.',
    );
    return null;
  }

  const expectedToken = md5HexUtf8(`${clearPassword}${salt}`);
  if (expectedToken !== token.toLowerCase()) {
    logFailedLoginAttempt(request, {
      username,
      route: '/rest/*',
      mechanism: 'token',
      reason: 'token_mismatch',
      hasPassword: false,
    });
    sendSubsonicError(reply, 40, 'Wrong username or password');
    return null;
  }

  return account;
}

function decodePlexTokenOrThrow(tokenCipher, encryptedBlob) {
  return tokenCipher.decrypt(encryptedBlob);
}

function groupArtistsForSubsonic(artists) {
  const groups = new Map();

  for (const artist of artists) {
    const id = String(artist.ratingKey ?? '');
    const name = String(artist.title ?? 'Unknown Artist');

    if (!id) {
      continue;
    }

    const first = name[0]?.toUpperCase() || '#';
    const indexName = /^[A-Z]$/.test(first) ? first : '#';

    if (!groups.has(indexName)) {
      groups.set(indexName, []);
    }

    groups.get(indexName).push({ id, name, artist });
  }

  const keys = [...groups.keys()].sort((a, b) => {
    if (a === '#') {
      return -1;
    }
    if (b === '#') {
      return 1;
    }
    return a.localeCompare(b);
  });

  return keys.map((key) => {
    const artistItems = groups
      .get(key)
      .sort((a, b) => a.name.localeCompare(b.name))
      .map((artist) => ({
        id: artist.id,
        name: artist.name,
        albumCount: artistAlbumCountValue(artist.artist),
        coverArt: artist.id,
        roles: ['artist'],
        ...subsonicRatingAttrs(artist.artist),
      }));

    return {
      name: key,
      artist: artistItems,
    };
  });
}

function groupNamedEntriesForSubsonic(entries) {
  const groups = new Map();

  for (const entry of entries) {
    const id = String(entry.id ?? '');
    const name = String(entry.name ?? 'Unknown');
    if (!id || !name) {
      continue;
    }

    const first = name[0]?.toUpperCase() || '#';
    const indexName = /^[A-Z]$/.test(first) ? first : '#';

    if (!groups.has(indexName)) {
      groups.set(indexName, []);
    }

    groups.get(indexName).push({ id, name, coverArt: entry.coverArt || undefined });
  }

  const keys = [...groups.keys()].sort((a, b) => {
    if (a === '#') {
      return -1;
    }
    if (b === '#') {
      return 1;
    }
    return a.localeCompare(b);
  });

  return keys.map((key) => {
    const items = groups
      .get(key)
      .sort((a, b) => a.name.localeCompare(b.name))
      .map((item) => ({
        id: item.id,
        name: item.name,
        coverArt: item.coverArt,
      }));

    return {
      name: key,
      artist: items,
    };
  });
}

function mediaFromTrack(track) {
  return Array.isArray(track.Media) ? track.Media[0] : null;
}

function partFromTrack(track) {
  const media = mediaFromTrack(track);
  return Array.isArray(media?.Part) ? media.Part[0] : null;
}

function audioStreamFromTrack(track) {
  const part = partFromTrack(track);
  const streams = Array.isArray(part?.Stream) ? part.Stream : [];
  if (streams.length === 0) {
    return null;
  }

  const audioStream = streams.find((stream) => parseNonNegativeInt(stream?.streamType, -1) === 2);
  return audioStream || streams[0] || null;
}

function detectAudioSuffix(track) {
  const media = mediaFromTrack(track);
  const container = String(media?.container || '').toLowerCase();
  if (container) {
    return container;
  }

  const part = partFromTrack(track);
  const file = String(part?.file || '');
  const idx = file.lastIndexOf('.');
  if (idx !== -1) {
    return file.slice(idx + 1).toLowerCase();
  }

  return 'mp3';
}

function detectContentType(track) {
  const suffix = detectAudioSuffix(track);

  switch (suffix) {
    case 'mp3':
      return 'audio/mpeg';
    case 'flac':
      return 'audio/flac';
    case 'm4a':
    case 'mp4':
      return 'audio/mp4';
    case 'aac':
      return 'audio/aac';
    case 'ogg':
      return 'audio/ogg';
    case 'opus':
      return 'audio/opus';
    case 'wav':
      return 'audio/wav';
    default:
      return 'audio/mpeg';
  }
}

function parseBooleanParam(value, fallback = false) {
  if (value == null || value === '') {
    return fallback;
  }
  const normalized = safeLower(String(value).trim());
  if (['1', 'true', 'yes', 'on'].includes(normalized)) {
    return true;
  }
  if (['0', 'false', 'no', 'off'].includes(normalized)) {
    return false;
  }
  return fallback;
}

function normalizeSourceAudioFormat(value) {
  const normalized = safeLower(String(value || '').trim());
  switch (normalized) {
    case 'm4a':
    case 'mp4':
      return 'aac';
    case 'ogg':
      return 'opus';
    default:
      return normalized;
  }
}

function normalizeRequestedTranscodeFormat(value) {
  const normalized = safeLower(String(value || '').trim());
  return TRANSCODE_SUPPORTED_FORMATS.has(normalized) ? normalized : '';
}

function defaultTranscodeBitrateKbps(format) {
  return Number(TRANSCODE_DEFAULT_BITRATE_KBPS[format] || 0);
}

function normalizeTranscodeBitrateKbps(format, value) {
  const limits = TRANSCODE_BITRATE_LIMITS_KBPS[format];
  const fallback = defaultTranscodeBitrateKbps(format);
  if (!limits) {
    return fallback > 0 ? fallback : null;
  }

  const parsed = parsePositiveInt(value, fallback || limits.min);
  const bounded = Math.min(limits.max, Math.max(limits.min, parsed));
  return Number.isFinite(bounded) ? bounded : null;
}

function transcodeContentTypeForFormat(format) {
  switch (format) {
    case 'mp3':
      return 'audio/mpeg';
    case 'aac':
      // Navidrome reports AAC transcodes as audio/mp4 even when encoded as ADTS.
      return 'audio/mp4';
    case 'opus':
      return 'audio/ogg';
    case 'flac':
      return 'audio/flac';
    default:
      return 'audio/mpeg';
  }
}

function transcodeSuffixForFormat(format) {
  switch (format) {
    case 'opus':
      return 'ogg';
    default:
      return format || 'mp3';
  }
}

function estimateTrackBitrateKbps(track) {
  const partSizeBytes = parseNonNegativeInt(partFromTrack(track)?.size, 0);
  const durationMs = parseNonNegativeInt(track?.duration, 0);
  if (partSizeBytes <= 0 || durationMs <= 0) {
    return 0;
  }

  const durationSeconds = durationMs / 1000;
  if (!Number.isFinite(durationSeconds) || durationSeconds <= 0) {
    return 0;
  }

  const estimated = Math.round((partSizeBytes * 8) / durationSeconds / 1000);
  if (!Number.isFinite(estimated) || estimated <= 0) {
    return 0;
  }
  return estimated;
}

function detectSourceBitrateKbps(track) {
  const fromMedia = parseNonNegativeInt(mediaFromTrack(track)?.bitrate, 0);
  if (fromMedia > 0) {
    return fromMedia;
  }
  return estimateTrackBitrateKbps(track);
}

function formatContentDurationHeader(durationMs) {
  const parsed = Number(durationMs || 0);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    return '';
  }
  return (parsed / 1000).toFixed(3).replace(/\.?0+$/, '');
}

function estimateTranscodedContentLengthBytes({
  format,
  bitrateKbps,
  durationMs,
  sourceSize,
}) {
  const normalizedDuration = Number(durationMs || 0);
  if (!Number.isFinite(normalizedDuration) || normalizedDuration <= 0) {
    return null;
  }

  if (format === 'flac') {
    const fallbackSize = parsePositiveInt(sourceSize, 0);
    return fallbackSize > 0 ? fallbackSize : null;
  }

  const normalizedBitrate = Number(bitrateKbps || 0);
  if (!Number.isFinite(normalizedBitrate) || normalizedBitrate <= 0) {
    return null;
  }

  const seconds = normalizedDuration / 1000;
  const baseline = seconds * normalizedBitrate * 125;
  const overheadFactor = (() => {
    switch (format) {
      case 'mp3':
        return 1.02;
      case 'aac':
        return 1.06;
      case 'opus':
        return 1.08;
      default:
        return 1.1;
    }
  })();
  const estimated = Math.ceil((baseline * overheadFactor) + 4096);
  if (!Number.isFinite(estimated) || estimated <= 0) {
    return null;
  }
  return estimated;
}

function resolveStreamTranscodePlan({ request, track }) {
  const requestedFormat = normalizeRequestedTranscodeFormat(getRequestParam(request, 'format'));
  const requestedMaxBitRate = parsePositiveInt(getRequestParam(request, 'maxBitRate'), 0);
  const estimateContentLength = parseBooleanParam(getRequestParam(request, 'estimateContentLength'), false);

  const sourceFormat = normalizeSourceAudioFormat(detectAudioSuffix(track));
  const sourceBitrateKbps = detectSourceBitrateKbps(track);

  let targetFormat = '';
  let bitrateKbps = null;
  let shouldTranscode = false;

  if (requestedFormat) {
    targetFormat = requestedFormat;

    if (targetFormat === 'flac') {
      shouldTranscode = sourceFormat !== 'flac';
    } else {
      const targetBitrate = normalizeTranscodeBitrateKbps(
        targetFormat,
        requestedMaxBitRate > 0 ? requestedMaxBitRate : defaultTranscodeBitrateKbps(targetFormat),
      );
      bitrateKbps = targetBitrate;

      if (sourceFormat !== targetFormat) {
        shouldTranscode = true;
      } else if (requestedMaxBitRate > 0) {
        shouldTranscode = sourceBitrateKbps <= 0 || sourceBitrateKbps > (targetBitrate || requestedMaxBitRate);
      }
    }
  } else if (requestedMaxBitRate > 0) {
    const shouldLimitByBitrate = sourceBitrateKbps <= 0 || sourceBitrateKbps > requestedMaxBitRate;
    if (shouldLimitByBitrate) {
      targetFormat = 'opus';
      bitrateKbps = normalizeTranscodeBitrateKbps('opus', requestedMaxBitRate);
      shouldTranscode = true;
    }
  }

  if (!shouldTranscode || !targetFormat) {
    return null;
  }

  return {
    targetFormat,
    fileSuffix: transcodeSuffixForFormat(targetFormat),
    contentType: transcodeContentTypeForFormat(targetFormat),
    bitrateKbps,
    estimateContentLength,
  };
}

function buildTranscodeCacheKey({ plexState, part, track, trackId, plan }) {
  const mediaFingerprint = [
    TRANSCODE_CACHE_VERSION,
    String(plexState?.machineId || ''),
    String(part?.key || ''),
    String(part?.size || ''),
    String(track?.updatedAt || ''),
    String(track?.duration || ''),
    String(trackId || ''),
    String(plan?.targetFormat || ''),
    String(plan?.bitrateKbps || ''),
  ].join('|');

  return createHash('sha256').update(mediaFingerprint).digest('hex');
}

function buildTranscodeCachePaths(cacheRoot, cacheKey, fileSuffix) {
  const bucket = cacheKey.slice(0, 2) || '00';
  const directory = path.join(cacheRoot, bucket);
  return {
    directory,
    filePath: path.join(directory, `${cacheKey}.${fileSuffix}`),
    metaPath: path.join(directory, `${cacheKey}.json`),
  };
}

async function readTranscodeCacheMetadata(metaPath) {
  try {
    const raw = await fsp.readFile(metaPath, 'utf8');
    const parsed = JSON.parse(raw);
    return parsed && typeof parsed === 'object' ? parsed : null;
  } catch {
    return null;
  }
}

async function readReadyTranscodeCacheEntry({
  cacheRoot,
  cacheKey,
  fileSuffix,
}) {
  const paths = buildTranscodeCachePaths(cacheRoot, cacheKey, fileSuffix);

  try {
    const stat = await fsp.stat(paths.filePath);
    if (!stat.isFile() || stat.size <= 0) {
      return { ...paths, size: 0, metadata: null, lastModified: '' };
    }

    const metadata = await readTranscodeCacheMetadata(paths.metaPath);
    const lastModified = (() => {
      const fromMeta = String(metadata?.lastModified || '').trim();
      if (fromMeta) {
        return fromMeta;
      }
      return stat.mtime instanceof Date ? stat.mtime.toUTCString() : '';
    })();

    return {
      ...paths,
      size: stat.size,
      metadata,
      lastModified,
    };
  } catch {
    return {
      ...paths,
      size: 0,
      metadata: null,
      lastModified: '',
    };
  }
}

function parseSingleByteRange(rangeHeader, totalSize) {
  const normalizedSize = Number(totalSize || 0);
  if (!Number.isFinite(normalizedSize) || normalizedSize <= 0) {
    return { unsatisfiable: true };
  }

  const raw = String(rangeHeader || '').trim();
  if (!raw) {
    return null;
  }

  if (!/^bytes=/i.test(raw)) {
    return { unsatisfiable: true };
  }

  const firstSegment = raw.slice(raw.indexOf('=') + 1).split(',')[0]?.trim() || '';
  const match = firstSegment.match(/^(\d*)-(\d*)$/);
  if (!match) {
    return { unsatisfiable: true };
  }

  const startRaw = match[1] || '';
  const endRaw = match[2] || '';
  if (!startRaw && !endRaw) {
    return { unsatisfiable: true };
  }

  if (!startRaw) {
    const suffixLength = Number.parseInt(endRaw, 10);
    if (!Number.isFinite(suffixLength) || suffixLength <= 0) {
      return { unsatisfiable: true };
    }
    const start = Math.max(0, normalizedSize - suffixLength);
    const end = normalizedSize - 1;
    if (start > end) {
      return { unsatisfiable: true };
    }
    return { start, end };
  }

  const start = Number.parseInt(startRaw, 10);
  if (!Number.isFinite(start) || start < 0) {
    return { unsatisfiable: true };
  }
  const parsedEnd = endRaw ? Number.parseInt(endRaw, 10) : normalizedSize - 1;
  if (!Number.isFinite(parsedEnd) || parsedEnd < 0) {
    return { unsatisfiable: true };
  }

  if (start >= normalizedSize || start > parsedEnd) {
    return { unsatisfiable: true };
  }

  const end = Math.min(parsedEnd, normalizedSize - 1);
  if (start > end) {
    return { unsatisfiable: true };
  }

  return { start, end };
}

function waitForChildProcessSpawn(child) {
  return new Promise((resolve, reject) => {
    let settled = false;

    const handleSpawn = () => {
      if (settled) {
        return;
      }
      settled = true;
      child.off('error', handleError);
      resolve();
    };

    const handleError = (error) => {
      if (settled) {
        return;
      }
      settled = true;
      child.off('spawn', handleSpawn);
      reject(error);
    };

    child.once('spawn', handleSpawn);
    child.once('error', handleError);
  });
}

function waitForWritableFinish(stream) {
  return new Promise((resolve, reject) => {
    if (!stream) {
      resolve();
      return;
    }
    if (stream.writableFinished || stream.destroyed) {
      resolve();
      return;
    }

    const handleFinish = () => {
      stream.off('error', handleError);
      resolve();
    };
    const handleError = (error) => {
      stream.off('finish', handleFinish);
      reject(error);
    };

    stream.once('finish', handleFinish);
    stream.once('error', handleError);
  });
}

function buildFfmpegTranscodeArgs(plan) {
  const args = [
    '-hide_banner',
    '-loglevel', 'error',
    '-nostdin',
    '-i', 'pipe:0',
    '-map', '0:a:0',
    '-map_metadata', '0',
    '-vn',
  ];

  if (plan.targetFormat === 'mp3') {
    const bitrate = normalizeTranscodeBitrateKbps('mp3', plan.bitrateKbps);
    args.push(
      '-c:a', 'libmp3lame',
      '-b:a', `${bitrate}k`,
      '-minrate', `${bitrate}k`,
      '-maxrate', `${bitrate}k`,
      '-bufsize', `${Math.max(64, bitrate * 2)}k`,
      '-id3v2_version', '4',
      '-write_xing', '0',
      '-f', 'mp3',
      'pipe:1',
    );
    return args;
  }

  if (plan.targetFormat === 'aac') {
    const bitrate = normalizeTranscodeBitrateKbps('aac', plan.bitrateKbps);
    args.push(
      '-c:a', 'aac',
      '-b:a', `${bitrate}k`,
      '-f', 'adts',
      'pipe:1',
    );
    return args;
  }

  if (plan.targetFormat === 'opus') {
    const bitrate = normalizeTranscodeBitrateKbps('opus', plan.bitrateKbps);
    args.push(
      '-c:a', 'libopus',
      '-b:a', `${bitrate}k`,
      '-vbr', 'on',
      '-application', 'audio',
      '-f', 'ogg',
      'pipe:1',
    );
    return args;
  }

  args.push(
    '-c:a', 'flac',
    '-compression_level', '5',
    '-f', 'flac',
    'pipe:1',
  );
  return args;
}

async function serveCachedTranscodeResponse({
  request,
  reply,
  cacheEntry,
  plan,
  durationHeader,
}) {
  const range = parseSingleByteRange(request.headers.range, cacheEntry.size);

  if (range?.unsatisfiable) {
    if (durationHeader) {
      reply.header('x-content-duration', durationHeader);
    }
    reply.header('content-range', `bytes */${cacheEntry.size}`);
    const payload = RANGE_NOT_SATISFIABLE_BODY;
    return reply
      .code(416)
      .type('text/plain; charset=utf-8')
      .header('content-length', String(Buffer.byteLength(payload)))
      .send(payload);
  }

  if (durationHeader) {
    reply.header('x-content-duration', durationHeader);
  }
  if (cacheEntry.lastModified) {
    reply.header('last-modified', cacheEntry.lastModified);
  }
  reply.header('content-type', plan.contentType);
  reply.header('accept-ranges', 'bytes');

  if (range) {
    const contentLength = (range.end - range.start) + 1;
    reply.code(206);
    reply.header('content-length', String(contentLength));
    reply.header('content-range', `bytes ${range.start}-${range.end}/${cacheEntry.size}`);
    return reply.send(fs.createReadStream(cacheEntry.filePath, {
      start: range.start,
      end: range.end,
    }));
  }

  reply.code(200);
  reply.header('content-length', String(cacheEntry.size));
  return reply.send(fs.createReadStream(cacheEntry.filePath));
}

async function streamTrackWithLocalTranscode({
  request,
  reply,
  plexState,
  track,
  trackId,
  part,
  partKey,
  plan,
  cacheRoot,
}) {
  const durationHeader = formatContentDurationHeader(track?.duration);
  const cacheKey = buildTranscodeCacheKey({
    plexState,
    part,
    track,
    trackId,
    plan,
  });
  const cacheEntry = await readReadyTranscodeCacheEntry({
    cacheRoot,
    cacheKey,
    fileSuffix: plan.fileSuffix,
  });

  if (cacheEntry.size > 0) {
    return serveCachedTranscodeResponse({
      request,
      reply,
      cacheEntry,
      plan,
      durationHeader,
    });
  }

  const streamUrl = buildPmsAssetUrl(plexState.baseUrl, plexState.plexToken, partKey);
  const upstreamController = new AbortController();
  let ffmpeg = null;
  let transcodeAborted = false;

  const abortTranscode = () => {
    if (transcodeAborted) {
      return;
    }
    transcodeAborted = true;

    if (!upstreamController.signal.aborted) {
      upstreamController.abort();
    }

    if (ffmpeg?.stdin && !ffmpeg.stdin.destroyed) {
      try {
        ffmpeg.stdin.destroy();
      } catch { }
    }

    if (ffmpeg && ffmpeg.exitCode == null && ffmpeg.signalCode == null) {
      try {
        ffmpeg.kill('SIGKILL');
      } catch { }
    }
  };

  const abortTranscodeOnDisconnect = () => {
    if (request.raw.aborted || !reply.raw.writableEnded) {
      abortTranscode();
    }
  };
  request.raw.once('aborted', abortTranscodeOnDisconnect);
  reply.raw.once('close', abortTranscodeOnDisconnect);

  const upstream = await fetchWithRetry({
    url: streamUrl,
    options: {
      signal: upstreamController.signal,
    },
    request,
    context: 'track transcode source',
    maxAttempts: 3,
    baseDelayMs: 250,
  });

  if (!upstream.ok || !upstream.body) {
    request.log.warn({ status: upstream.status, trackId }, 'Failed to read track source for transcoding');
    return sendSubsonicError(reply, 70, 'Track stream unavailable');
  }

  const ffmpegArgs = buildFfmpegTranscodeArgs(plan);
  try {
    ffmpeg = spawn('ffmpeg', ffmpegArgs, {
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    await waitForChildProcessSpawn(ffmpeg);
  } catch (error) {
    abortTranscode();
    request.log.error({ err: error, trackId }, 'Failed to start ffmpeg transcode process');
    return sendSubsonicError(reply, 10, 'Transcode process unavailable');
  }

  const responseBody = new PassThrough();
  const outputTee = new PassThrough();
  const sourceLastModified = String(upstream.headers.get('last-modified') || '').trim();

  let ffmpegErrorTail = '';
  ffmpeg.stderr.on('data', (chunk) => {
    ffmpegErrorTail = `${ffmpegErrorTail}${String(chunk)}`.slice(-4096);
  });

  let cacheTempPath = '';
  let cacheWriteStream = null;
  try {
    await fsp.mkdir(cacheEntry.directory, { recursive: true });
    cacheTempPath = `${cacheEntry.filePath}.tmp-${randomUUID()}`;
    cacheWriteStream = fs.createWriteStream(cacheTempPath);
    outputTee.pipe(cacheWriteStream);
  } catch (error) {
    request.log.debug(
      { err: error, trackId, cacheFile: cacheEntry.filePath },
      'Failed to initialize transcode cache writer',
    );
    cacheTempPath = '';
    cacheWriteStream = null;
  }

  const cleanupTempCacheFile = async () => {
    if (!cacheTempPath) {
      return;
    }
    try {
      await fsp.rm(cacheTempPath, { force: true });
    } catch { }
  };

  if (cacheWriteStream) {
    cacheWriteStream.on('error', (streamError) => {
      request.log.debug(
        { err: streamError, trackId, cacheFile: cacheEntry.filePath },
        'Transcode cache write stream failed; disabling cache write for this request',
      );
      if (!outputTee.destroyed) {
        outputTee.unpipe(cacheWriteStream);
      }
      if (!cacheWriteStream.destroyed) {
        cacheWriteStream.destroy();
      }
      cacheWriteStream = null;
      void cleanupTempCacheFile();
    });
  }

  ffmpeg.once('close', (code, signal) => {
    void (async () => {
      const finishedSuccessfully = code === 0 && !transcodeAborted;

      if (cacheWriteStream && !cacheWriteStream.writableEnded && !cacheWriteStream.destroyed) {
        cacheWriteStream.end();
      }

      if (finishedSuccessfully && cacheWriteStream && cacheTempPath) {
        try {
          await waitForWritableFinish(cacheWriteStream);
          await fsp.rename(cacheTempPath, cacheEntry.filePath);
          cacheTempPath = '';

          const cacheMetadata = {
            version: TRANSCODE_CACHE_VERSION,
            createdAt: Date.now(),
            targetFormat: plan.targetFormat,
            contentType: plan.contentType,
            bitrateKbps: plan.bitrateKbps,
            lastModified: sourceLastModified,
            durationHeader: durationHeader || null,
          };
          await fsp.writeFile(cacheEntry.metaPath, `${JSON.stringify(cacheMetadata)}\n`, 'utf8');
        } catch (error) {
          request.log.debug(
            { err: error, trackId, cacheFile: cacheEntry.filePath },
            'Failed to persist transcoded cache entry',
          );
          await cleanupTempCacheFile();
        }
      } else {
        await cleanupTempCacheFile();
      }

      if (finishedSuccessfully) {
        if (!responseBody.destroyed) {
          responseBody.end();
        }
        return;
      }

      if (isClientDisconnected(request, reply) || transcodeAborted) {
        if (!responseBody.destroyed) {
          responseBody.end();
        }
        return;
      }

      request.log.warn(
        { trackId, code, signal, ffmpegError: ffmpegErrorTail.trim() || undefined },
        'ffmpeg transcode process failed',
      );
      if (!responseBody.destroyed) {
        responseBody.destroy(new Error('Transcode process failed'));
      }
    })();
  });

  ffmpeg.on('error', (error) => {
    if (isClientDisconnected(request, reply) || transcodeAborted) {
      return;
    }
    request.log.warn(error, 'ffmpeg process error while transcoding track');
    responseBody.destroy(error);
  });

  const sourceReadable = Readable.fromWeb(upstream.body);
  sourceReadable.on('error', (streamError) => {
    if (isAbortError(streamError) || isUpstreamTerminationError(streamError) || isClientDisconnected(request, reply)) {
      responseBody.end();
      abortTranscode();
      return;
    }
    request.log.warn(streamError, 'Upstream stream error while transcoding track');
    responseBody.destroy(streamError);
    abortTranscode();
  });

  ffmpeg.stdout.on('error', (streamError) => {
    if (isAbortError(streamError) || isUpstreamTerminationError(streamError) || isClientDisconnected(request, reply)) {
      responseBody.end();
      return;
    }
    request.log.warn(streamError, 'ffmpeg output stream error while transcoding track');
    responseBody.destroy(streamError);
  });

  ffmpeg.stdin.on('error', (streamError) => {
    if (isClientDisconnected(request, reply) || transcodeAborted) {
      return;
    }
    const code = String(streamError?.code || '').toUpperCase();
    if (code === 'EPIPE' || code === 'ECONNRESET') {
      return;
    }
    request.log.debug(streamError, 'ffmpeg input stream error while transcoding track');
  });

  responseBody.on('error', (streamError) => {
    if (isAbortError(streamError) || isUpstreamTerminationError(streamError) || isClientDisconnected(request, reply)) {
      return;
    }
    request.log.warn(streamError, 'Response stream error while transcoding track');
    abortTranscode();
  });

  outputTee.on('error', (streamError) => {
    if (isAbortError(streamError) || isUpstreamTerminationError(streamError) || isClientDisconnected(request, reply)) {
      responseBody.end();
      abortTranscode();
      return;
    }
    request.log.warn(streamError, 'Transcode tee stream error while streaming track');
    responseBody.destroy(streamError);
    abortTranscode();
  });

  ffmpeg.stdout.pipe(outputTee);
  outputTee.pipe(responseBody);
  sourceReadable.pipe(ffmpeg.stdin);

  reply.code(200);
  reply.header('content-type', plan.contentType);
  reply.header('accept-ranges', 'none');
  if (durationHeader) {
    reply.header('x-content-duration', durationHeader);
  }

  let shouldForceCloseAfterBodyEnd = false;
  if (plan.estimateContentLength) {
    const estimatedLength = estimateTranscodedContentLengthBytes({
      format: plan.targetFormat,
      bitrateKbps: plan.bitrateKbps,
      durationMs: track?.duration,
      sourceSize: part?.size,
    });
    if (estimatedLength != null) {
      reply.header('content-length', String(estimatedLength));
      shouldForceCloseAfterBodyEnd = true;
    }
  }

  if (shouldForceCloseAfterBodyEnd) {
    responseBody.once('end', () => {
      try {
        if (reply.raw.socket && !reply.raw.socket.destroyed) {
          reply.raw.socket.destroy();
        }
      } catch { }
    });
    responseBody.once('error', () => {
      try {
        if (reply.raw.socket && !reply.raw.socket.destroyed) {
          reply.raw.socket.destroy();
        }
      } catch { }
    });
    reply.raw.once('close', () => {
      try {
        if (reply.raw.socket && !reply.raw.socket.destroyed) {
          reply.raw.socket.destroy();
        }
      } catch { }
    });
    }

  return reply.send(responseBody);
}

async function pruneExpiredTranscodeArtifacts({
  rootDir,
  maxAgeMs,
  nowMs = Date.now(),
}) {
  const normalizedRoot = String(rootDir || '').trim();
  if (!normalizedRoot || !Number.isFinite(maxAgeMs) || maxAgeMs <= 0) {
    return { removedFiles: 0, removedDirectories: 0 };
  }

  const cutoffMs = nowMs - maxAgeMs;
  let removedFiles = 0;
  let removedDirectories = 0;

  const walk = async (dirPath, { isRoot = false } = {}) => {
    let entries = [];
    try {
      entries = await fsp.readdir(dirPath, { withFileTypes: true });
    } catch {
      return;
    }

    for (const entry of entries) {
      const fullPath = path.join(dirPath, entry.name);
      if (entry.isDirectory()) {
        await walk(fullPath);
        continue;
      }
      if (!entry.isFile()) {
        continue;
      }

      try {
        const stats = await fsp.stat(fullPath);
        if (stats.mtimeMs <= cutoffMs) {
          await fsp.rm(fullPath, { force: true });
          removedFiles += 1;
        }
      } catch { }
    }

    if (isRoot) {
      return;
    }

    try {
      const remaining = await fsp.readdir(dirPath);
      if (remaining.length === 0) {
        await fsp.rm(dirPath, { recursive: false });
        removedDirectories += 1;
      }
    } catch { }
  };

  await walk(normalizedRoot, { isRoot: true });
  return { removedFiles, removedDirectories };
}

function startTranscodeArtifactCleanupScheduler({
  rootDir,
  intervalMs,
  maxAgeMs,
  logger,
}) {
  const normalizedIntervalMs = Number(intervalMs || 0);
  const normalizedMaxAgeMs = Number(maxAgeMs || 0);
  if (
    !Number.isFinite(normalizedIntervalMs) ||
    normalizedIntervalMs <= 0 ||
    !Number.isFinite(normalizedMaxAgeMs) ||
    normalizedMaxAgeMs <= 0
  ) {
    return null;
  }

  const run = async () => {
    try {
      const result = await pruneExpiredTranscodeArtifacts({
        rootDir,
        maxAgeMs: normalizedMaxAgeMs,
      });
      if (result.removedFiles > 0 || result.removedDirectories > 0) {
        logger.info(
          {
            removedFiles: result.removedFiles,
            removedDirectories: result.removedDirectories,
            rootDir,
            maxAgeMs: normalizedMaxAgeMs,
          },
          'Removed expired transcode artifacts',
        );
      }
    } catch (error) {
      logger.warn({ err: error, rootDir, maxAgeMs: normalizedMaxAgeMs }, 'Transcode artifact cleanup failed');
    }
  };

  void run();
  const timer = setInterval(() => {
    void run();
  }, normalizedIntervalMs);
  if (typeof timer.unref === 'function') {
    timer.unref();
  }
  return timer;
}

function durationSeconds(ms) {
  const value = Number(ms || 0);
  if (!Number.isFinite(value) || value <= 0) {
    return 0;
  }
  return Math.floor(value / 1000);
}

function toIsoFromEpochSeconds(value) {
  const sec = Number(value || 0);
  if (!Number.isFinite(sec) || sec <= 0) {
    return undefined;
  }
  return new Date(sec * 1000).toISOString();
}

function firstNonEmptyText(candidates, fallback = '') {
  for (const candidate of candidates) {
    if (candidate == null) {
      continue;
    }
    const text = String(candidate).trim();
    if (text) {
      return text;
    }
  }
  if (arguments.length >= 2) {
    return fallback;
  }
  return '';
}

function normalizePlexRating(value) {
  const parsed = Number.parseFloat(String(value ?? ''));
  if (!Number.isFinite(parsed)) {
    return null;
  }
  return Math.max(0, Math.min(parsed, 10));
}

function normalizePlexRatingInt(value) {
  const normalized = normalizePlexRating(value);
  if (normalized == null) {
    return null;
  }
  return Math.round(normalized);
}

function isPlexLiked(value) {
  const normalized = normalizePlexRatingInt(value);
  return normalized != null && normalized >= 2 && normalized % 2 === 0;
}

function normalizePlainText(value) {
  return String(value || '')
    .replace(/<br\s*\/?>/gi, '\n')
    .replace(/<\/p>/gi, '\n')
    .replace(/<[^>]*>/g, '')
    .replace(/\r\n/g, '\n')
    .replace(/\n{3,}/g, '\n\n')
    .trim();
}

function asArray(value) {
  if (Array.isArray(value)) {
    return value;
  }
  if (value == null) {
    return [];
  }
  return [value];
}

function plexGuidIds(item) {
  const candidates = [];

  for (const guid of asArray(item?.Guid)) {
    if (typeof guid === 'string') {
      candidates.push(guid);
      continue;
    }
    if (guid && typeof guid === 'object' && typeof guid.id === 'string') {
      candidates.push(guid.id);
    }
  }

  for (const raw of [item?.guid, item?.guids]) {
    if (typeof raw === 'string') {
      candidates.push(raw);
    } else if (Array.isArray(raw)) {
      for (const entry of raw) {
        if (typeof entry === 'string') {
          candidates.push(entry);
        } else if (entry && typeof entry === 'object' && typeof entry.id === 'string') {
          candidates.push(entry.id);
        }
      }
    }
  }

  return uniqueNonEmptyValues(candidates);
}

function extractMusicBrainzArtistId(item) {
  const guidIds = plexGuidIds(item);
  const uuidPattern = /([0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})/i;

  for (const guid of guidIds) {
    const lower = safeLower(guid);

    if (lower.startsWith('mbid://')) {
      const id = guid.slice('mbid://'.length).split(/[/?#]/, 1)[0].trim();
      if (id) {
        return id;
      }
    }

    if (lower.startsWith('musicbrainz://')) {
      const id = guid
        .slice('musicbrainz://'.length)
        .replace(/^artist\//i, '')
        .split(/[?#]/, 1)[0]
        .replace(/^\/+/, '')
        .trim();
      if (id) {
        return id;
      }
    }

    if (lower.includes('musicbrainz.org/artist/')) {
      const match = guid.match(/musicbrainz\.org\/artist\/([^/?#]+)/i);
      if (match?.[1]) {
        return match[1];
      }
    }

    if (lower.includes('musicbrainz')) {
      const uuid = guid.match(uuidPattern)?.[1];
      if (uuid) {
        return uuid;
      }
    }
  }

  return '';
}

function artistBioFromPlex(item) {
  return firstNonEmptyText(
    [
      normalizePlainText(item?.summary),
      normalizePlainText(item?.tagline),
      normalizePlainText(item?.description),
    ],
    '',
  );
}

function subsonicRatingToPlexRating(value, { liked = false } = {}) {
  const rating = Number.parseInt(String(value ?? ''), 10);
  if (!Number.isFinite(rating) || rating <= 0) {
    return 0;
  }
  const bounded = Math.max(1, Math.min(5, rating));
  const stars = liked ? Math.max(1, bounded) : bounded;
  return liked ? stars * 2 : (stars * 2) - 1;
}

function toLikedPlexRating(value) {
  const normalized = normalizePlexRatingInt(value);
  if (normalized == null || normalized <= 0) {
    return 10;
  }
  const stars = Math.max(1, Math.min(5, Math.ceil(normalized / 2)));
  return stars * 2;
}

function toUnlikedPlexRating(value) {
  const normalized = normalizePlexRatingInt(value);
  if (normalized == null || normalized <= 0) {
    return 0;
  }
  const stars = Math.max(1, Math.min(5, Math.ceil(normalized / 2)));
  return (stars * 2) - 1;
}

function plexRatingToSubsonic(value) {
  const normalized = normalizePlexRatingInt(value);
  if (normalized == null) {
    return undefined;
  }
  if (normalized <= 0) {
    return 0;
  }
  return Math.max(1, Math.min(5, Math.ceil(normalized / 2)));
}

function subsonicRatingAttrs(item) {
  const plexRating = normalizePlexRating(item?.userRating);
  if (plexRating == null) {
    return {};
  }

  const attrs = {
    userRating: plexRatingToSubsonic(plexRating),
  };

  if (isPlexLiked(plexRating)) {
    attrs.starred = toIsoFromEpochSeconds(item?.updatedAt || item?.addedAt);
  }

  return attrs;
}

function albumAttrs(album, fallbackArtistId = null, fallbackArtistName = null) {
  const albumId = String(album?.ratingKey || '').trim();
  const title = firstNonEmptyText(
    [album?.title, album?.originalTitle, album?.titleSort, album?.parentTitle],
    albumId ? `Album ${albumId}` : 'Unknown Album',
  );
  const artistName = firstNonEmptyText(
    [album?.parentTitle, fallbackArtistName],
    'Unknown Artist',
  );
  const albumGenreTags = allGenreTags(album);
  const genre = albumGenreTags[0] || undefined;
  const genres = genreObjects(albumGenreTags);

  return {
    id: albumId,
    parent: album.parentRatingKey || fallbackArtistId || undefined,
    isDir: true,
    title,
    name: title,
    album: title,
    artist: artistName,
    displayArtist: artistName,
    artistId: album.parentRatingKey || fallbackArtistId || undefined,
    coverArt: albumId || undefined,
    songCount: album.leafCount || album.childCount || undefined,
    duration: durationSeconds(album.duration),
    created: toIsoFromEpochSeconds(album.addedAt),
    year: album.year,
    genre,
    genres,
    ...subsonicRatingAttrs(album),
  };
}

function buildArtistEntry(idCandidate, nameCandidate) {
  const name = firstNonEmptyText([nameCandidate], '');
  if (!name) {
    return null;
  }
  const id = String(idCandidate || '').trim();
  return {
    id: id || undefined,
    name,
  };
}

function albumArtistEntries(album, fallbackArtistId = null, fallbackArtistName = null) {
  const artistId = firstNonEmptyText(
    [album?.parentRatingKey, album?.artistId, fallbackArtistId, album?.grandparentRatingKey],
    '',
  );
  const artistName = firstNonEmptyText(
    [album?.parentTitle, album?.artist, fallbackArtistName, album?.grandparentTitle],
    '',
  );
  const entry = buildArtistEntry(artistId, artistName);
  return entry ? [entry] : [];
}

function renderArtistList(listName, entries) {
  if (!entries || entries.length === 0) {
    return null;
  }
  return entries.map((entry) => ({ id: entry.id, name: entry.name }));
}

function albumJson(album, attrs, fallbackArtistId = null, fallbackArtistName = null) {
  const artistEntries = albumArtistEntries(album, fallbackArtistId, fallbackArtistName);
  const artists = renderArtistList('artists', artistEntries);
  if (!artists || artists.length === 0) {
    return attrs;
  }
  return {
    ...attrs,
    artists,
  };
}

function artistAlbumCountValue(artist) {
  return parseNonNegativeInt(
    artist?.albumCount ?? artist?.childCount ?? artist?.album_count ?? artist?.leafCount,
    0,
  );
}

function albumPlayCountValue(album) {
  return parseNonNegativeInt(album?.playCount ?? album?.viewCount, 0);
}

function albumId3Attrs(album, fallbackArtistId = null, fallbackArtistName = null) {
  const albumId = String(album?.ratingKey || '').trim();
  const name = firstNonEmptyText(
    [album?.title, album?.originalTitle, album?.titleSort, album?.parentTitle],
    albumId ? `Album ${albumId}` : 'Unknown Album',
  );
  const artistName = firstNonEmptyText(
    [album?.parentTitle, fallbackArtistName],
    'Unknown Artist',
  );
  const songCount = parseNonNegativeInt(album?.leafCount ?? album?.childCount, 0);
  const playCount = albumPlayCountValue(album);
  const albumGenreTags = allGenreTags(album);
  const genre = albumGenreTags[0] || undefined;
  const genres = genreObjects(albumGenreTags);
  const played = toIsoFromEpochSeconds(album?.lastViewedAt);

  return {
    id: albumId,
    name,
    artist: artistName,
    displayArtist: artistName,
    artistId: album.parentRatingKey || fallbackArtistId || undefined,
    coverArt: albumId || undefined,
    songCount: songCount || undefined,
    duration: durationSeconds(album.duration),
    playCount: playCount || undefined,
    played,
    created: toIsoFromEpochSeconds(album.addedAt),
    year: album.year,
    genre,
    genres,
    ...subsonicRatingAttrs(album),
  };
}

function deriveAlbumsFromTracks(tracks, fallbackArtistId, fallbackArtistName) {
  const map = new Map();

  for (const track of tracks) {
    const albumId = String(track.parentRatingKey || '');
    const albumTitle = String(track.parentTitle || '');
    if (!albumId || !albumTitle) {
      continue;
    }

    const existing = map.get(albumId);
    if (existing) {
      existing.leafCount += 1;
      existing.duration = Number(existing.duration || 0) + Number(track.duration || 0);
      continue;
    }

    map.set(albumId, {
      ratingKey: albumId,
      title: albumTitle,
      parentRatingKey: track.grandparentRatingKey || fallbackArtistId || undefined,
      parentTitle: track.grandparentTitle || fallbackArtistName || undefined,
      leafCount: 1,
      duration: Number(track.duration || 0),
      year: track.parentYear || track.year || undefined,
      addedAt: track.addedAt || undefined,
    });
  }

  return [...map.values()].sort((a, b) => String(a.title || '').localeCompare(String(b.title || '')));
}

function songAttrs(track, albumTitle = null, albumCoverArt = null, albumMetadata = null) {
  const media = mediaFromTrack(track);
  const part = partFromTrack(track);
  const audioStream = audioStreamFromTrack(track);
  const trackId = String(track?.ratingKey || '').trim();
  const albumId = firstNonEmptyText(
    [track?.parentRatingKey, typeof albumCoverArt === 'string' ? albumCoverArt : null],
    undefined,
  );
  const title = firstNonEmptyText(
    [track?.title, track?.originalTitle, track?.titleSort],
    trackId ? `Track ${trackId}` : 'Unknown Track',
  );
  const normalizedAlbumTitle = firstNonEmptyText(
    [albumTitle, track?.parentTitle],
    'Unknown Album',
  );
  const normalizedArtist = firstNonEmptyText(
    [track?.originalTitle, track?.grandparentTitle],
    'Unknown Artist',
  );
  const displayAlbumArtist = firstNonEmptyText(
    [albumMetadata?.artist, albumMetadata?.parentTitle, track?.artist, track?.grandparentTitle],
    normalizedArtist,
  );
  const composer = metadataFieldText(
    [track, albumMetadata],
    ['Composer', 'composer', 'Composers', 'composers', 'Writer', 'writer'],
  );
  const displayComposer = firstNonEmptyText([composer], '');
  const coverArt = firstNonEmptyText(
    [albumCoverArt, track?.parentRatingKey, track?.ratingKey],
    undefined,
  );
  const albumGenreTags = albumMetadata ? allGenreTags(albumMetadata) : [];
  const genreTagsRaw = allGenreTags(track);
  const genreTags = genreTagsRaw.length > 0 ? genreTagsRaw : albumGenreTags;
  const genre = genreTags[0] || undefined;
  const genres = genreObjects(genreTags);
  const styleValues = metadataFieldValues([track, albumMetadata], ['Style', 'style']);
  const style = styleValues[0] || undefined;
  const styles = styleValues.length > 0 ? styleValues.join('; ') : undefined;
  const discNumber = parsePositiveInt(track?.parentIndex ?? track?.discNumber, 0) || undefined;
  const discSubtitle = firstNonEmptyText(
    [track?.parentSubtitle, track?.discSubtitle, track?.parentOriginalTitle],
    undefined,
  );
  const partStreams = Array.isArray(part?.Stream) ? part.Stream : [];
  const streamLanguage = firstNonEmptyText(
    partStreams.map((stream) =>
      firstNonEmptyText([stream?.languageTag, stream?.languageCode, stream?.language], ''),
    ),
    undefined,
  );
  const country = metadataFieldText([track, albumMetadata], ['Country', 'country']);
  const moodValues = metadataFieldValues([track, albumMetadata], ['Mood', 'mood']);
  const mood = moodValues[0] || undefined;
  const moods = moodValues.length > 0 ? moodValues.join('; ') : undefined;
  const recordLabelValues = metadataFieldValues(
    [track, albumMetadata],
    ['RecordLabel', 'recordLabel', 'recordlabel', 'Label', 'label', 'Studio', 'studio'],
  );
  const recordLabel = recordLabelValues[0] || undefined;
  const recordLabels = recordLabelValues.length > 0 ? recordLabelValues.join('; ') : undefined;
  const language =
    metadataFieldText([track, albumMetadata], ['Language', 'language', 'Lang', 'lang']) || streamLanguage;
  const albumType = metadataFieldText(
    [albumMetadata, track],
    ['albumType', 'AlbumType', 'subtype', 'subType', 'parentSubtype', 'format'],
  );
  const compilationValues = metadataFieldValues(
    [track, albumMetadata],
    ['Compilation', 'compilation', 'isCompilation', 'iscompilation'],
  );
  const soundtrackValues = metadataFieldValues(
    [track, albumMetadata],
    ['Soundtrack', 'soundtrack', 'isSoundtrack', 'issoundtrack'],
  );
  const compilation = compilationValues.length > 0
    ? parseBooleanLike(compilationValues[0], false)
    : safeLower(albumType).includes('compilation');
  const soundtrack = soundtrackValues.length > 0
    ? parseBooleanLike(soundtrackValues[0], false)
    : safeLower(albumType).includes('soundtrack');
  const sampleRate = parsePositiveInt(
    audioStream?.samplingRate ?? audioStream?.sampleRate ?? audioStream?.audioSamplingRate,
    0,
  ) || undefined;
  const bitDepth = parsePositiveInt(audioStream?.bitDepth ?? audioStream?.bitsPerSample, 0) || undefined;
  const path = firstNonEmptyText([part?.file], undefined);
  const trackNumber = parsePositiveInt(track?.index ?? track?.track, 0);
  const playCount = parseNonNegativeInt(track?.viewCount ?? track?.playCount, 0);
  const played = toIsoFromEpochSeconds(track?.lastViewedAt);
  const year = parsePositiveInt(track?.year ?? track?.parentYear ?? albumMetadata?.year, 0) || undefined;

  return {
    id: trackId,
    parent: albumId,
    isDir: false,
    title,
    name: title,
    album: normalizedAlbumTitle,
    albumId,
    artist: normalizedArtist,
    displayArtist: normalizedArtist,
    displayAlbumArtist,
    displayComposer,
    artistId: track.grandparentRatingKey || track.artistId || undefined,
    type: 'music',
    duration: durationSeconds(track.duration),
    track: trackNumber,
    discNumber,
    discSubtitle,
    contentType: detectContentType(track),
    suffix: detectAudioSuffix(track),
    size: part?.size,
    bitRate: media?.bitrate,
    sampleRate,
    bitDepth,
    path,
    coverArt,
    genre,
    genres,
    country,
    style,
    styles,
    mood,
    moods,
    recordLabel,
    recordLabels,
    language,
    albumType,
    compilation: compilation || undefined,
    soundtrack: soundtrack || undefined,
    year,
    played,
    created: toIsoFromEpochSeconds(track.addedAt),
    playCount: playCount || undefined,
    ...subsonicRatingAttrs(track),
  };
}

function trackArtistEntries(track) {
  const artistId = firstNonEmptyText(
    [track?.grandparentRatingKey, track?.artistId, track?.guid],
    '',
  );
  const artistName = firstNonEmptyText(
    [track?.originalTitle, track?.artist, track?.grandparentTitle],
    '',
  );
  const entry = buildArtistEntry(artistId, artistName);
  return entry ? [entry] : [];
}

function trackAlbumArtistEntries(track, albumMetadata = null) {
  const albumArtistId = firstNonEmptyText(
    [albumMetadata?.parentRatingKey, track?.grandparentRatingKey, albumMetadata?.artistId, track?.artistId],
    '',
  );
  const albumArtistName = firstNonEmptyText(
    [albumMetadata?.artist, albumMetadata?.parentTitle, track?.artist, track?.grandparentTitle],
    '',
  );
  const entry = buildArtistEntry(albumArtistId, albumArtistName);
  return entry ? [entry] : [];
}

function buildSongArtistChildren(track, albumMetadata = null) {
  const artists = renderArtistList('artists', trackArtistEntries(track));
  const albumArtists = renderArtistList('albumArtists', trackAlbumArtistEntries(track, albumMetadata));
  const out = {};
  if (artists && artists.length > 0) {
    out.artists = artists;
  }
  if (albumArtists && albumArtists.length > 0) {
    out.albumArtists = albumArtists;
  }
  return out;
}

function songJson(track, albumTitle = null, albumCoverArt = null, albumMetadata = null) {
  const attrs = songAttrs(track, albumTitle, albumCoverArt, albumMetadata);
  return {
    ...attrs,
    ...buildSongArtistChildren(track, albumMetadata),
  };
}

function songChildJson(track, albumTitle = null, albumCoverArt = null, albumMetadata = null, extraAttrs = {}) {
  const attrs = { ...songAttrs(track, albumTitle, albumCoverArt, albumMetadata), ...extraAttrs };
  return {
    ...attrs,
    ...buildSongArtistChildren(track, albumMetadata),
  };
}

function sortTracksByDiscAndIndex(tracks) {
  return [...(Array.isArray(tracks) ? tracks : [])].sort((a, b) => {
    const discA = parsePositiveInt(a?.parentIndex ?? a?.discNumber, 1);
    const discB = parsePositiveInt(b?.parentIndex ?? b?.discNumber, 1);
    if (discA !== discB) {
      return discA - discB;
    }

    const trackA = parsePositiveInt(a?.index ?? a?.track, 0);
    const trackB = parsePositiveInt(b?.index ?? b?.track, 0);
    if (trackA !== trackB) {
      return trackA - trackB;
    }

    const titleA = String(a?.title || '').toLowerCase();
    const titleB = String(b?.title || '').toLowerCase();
    const byTitle = titleA.localeCompare(titleB);
    if (byTitle !== 0) {
      return byTitle;
    }

    return String(a?.ratingKey || '').localeCompare(String(b?.ratingKey || ''));
  });
}

function sortTracksForLibraryBrowse(tracks) {
  return [...(Array.isArray(tracks) ? tracks : [])].sort((a, b) => {
    const artistA = String(a?.grandparentTitle || '').toLowerCase();
    const artistB = String(b?.grandparentTitle || '').toLowerCase();
    const byArtist = artistA.localeCompare(artistB);
    if (byArtist !== 0) {
      return byArtist;
    }

    const albumA = String(a?.parentTitle || '').toLowerCase();
    const albumB = String(b?.parentTitle || '').toLowerCase();
    const byAlbum = albumA.localeCompare(albumB);
    if (byAlbum !== 0) {
      return byAlbum;
    }

    const discA = parsePositiveInt(a?.parentIndex ?? a?.discNumber, 1);
    const discB = parsePositiveInt(b?.parentIndex ?? b?.discNumber, 1);
    if (discA !== discB) {
      return discA - discB;
    }

    const trackA = parsePositiveInt(a?.index ?? a?.track, 0);
    const trackB = parsePositiveInt(b?.index ?? b?.track, 0);
    if (trackA !== trackB) {
      return trackA - trackB;
    }

    const titleA = String(a?.title || '').toLowerCase();
    const titleB = String(b?.title || '').toLowerCase();
    const byTitle = titleA.localeCompare(titleB);
    if (byTitle !== 0) {
      return byTitle;
    }

    return String(a?.ratingKey || '').localeCompare(String(b?.ratingKey || ''));
  });
}

async function hydrateTracksWithGenre({ baseUrl, plexToken, tracks, request = null }) {
  const entries = Array.isArray(tracks) ? tracks : [];
  if (entries.length === 0) {
    return [];
  }

  return Promise.all(
    entries.map(async (track) => {
      if (firstGenreTag(track)) {
        return track;
      }

      const trackId = String(track?.ratingKey || '').trim();
      if (!trackId) {
        return track;
      }

      try {
        const detailed = await getTrack({
          baseUrl,
          plexToken,
          trackId,
        });
        if (!detailed) {
          return track;
        }

        const merged = { ...track };
        if (!merged.Media && detailed?.Media) {
          merged.Media = detailed.Media;
        }
        if (Array.isArray(detailed?.Genre) && detailed.Genre.length > 0) {
          merged.Genre = detailed.Genre;
        }
        if (detailed?.genre != null) {
          merged.genre = detailed.genre;
        }
        for (const key of [
          'Country',
          'country',
          'Style',
          'style',
          'Compilation',
          'compilation',
          'isCompilation',
          'iscompilation',
          'Soundtrack',
          'soundtrack',
          'isSoundtrack',
          'issoundtrack',
          'RecordLabel',
          'recordLabel',
          'recordlabel',
          'Label',
          'label',
          'Studio',
          'studio',
          'Mood',
          'mood',
          'Language',
          'language',
          'Lang',
          'lang',
          'year',
          'parentYear',
          'albumType',
          'AlbumType',
          'parentSubtype',
          'subtype',
        ]) {
          if (detailed?.[key] != null) {
            merged[key] = detailed[key];
          }
        }
        return merged;
      } catch (error) {
        request?.log?.debug?.(error, 'Failed to hydrate track genre from detailed metadata');
        return track;
      }
    }),
  );
}

function parseBooleanLike(value, fallback = false) {
  if (typeof value === 'boolean') {
    return value;
  }
  if (typeof value === 'number') {
    return value !== 0;
  }

  const normalized = safeLower(value);
  if (normalized === '1' || normalized === 'true' || normalized === 'yes') {
    return true;
  }
  if (normalized === '0' || normalized === 'false' || normalized === 'no') {
    return false;
  }
  return fallback;
}

function parseLyricLineStart(value) {
  const parsed = Number.parseFloat(String(value ?? ''));
  if (!Number.isFinite(parsed) || parsed < 0) {
    return undefined;
  }
  return Math.trunc(parsed);
}

function parseLyricOffset(value) {
  const parsed = Number.parseFloat(String(value ?? ''));
  if (!Number.isFinite(parsed)) {
    return undefined;
  }
  return Math.trunc(parsed);
}

function splitLyricsTextLines(text) {
  const normalized = String(text ?? '')
    .replaceAll('\r\n', '\n')
    .replaceAll('\r', '\n')
    .trim();

  if (!normalized) {
    return [];
  }

  return normalized
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean)
    .map((value) => ({ value }));
}

function normalizeLyricsLines(rawLines) {
  const lines = [];
  for (const rawLine of rawLines) {
    if (typeof rawLine === 'string') {
      lines.push(...splitLyricsTextLines(rawLine));
      continue;
    }

    if (!rawLine || typeof rawLine !== 'object') {
      continue;
    }

    const value = firstNonEmptyText([rawLine.value, rawLine.text, rawLine.line, rawLine.lyric], '');
    if (!value) {
      continue;
    }

    const start = parseLyricLineStart(rawLine.start ?? rawLine.time ?? rawLine.timestamp);
    if (start === undefined) {
      lines.push({ value });
    } else {
      lines.push({ value, start });
    }
  }

  return lines;
}

function extractStructuredLyricsFromTrack(track, extraCandidates = []) {
  const displayArtist = firstNonEmptyText(
    [track?.grandparentTitle, track?.originalTitle],
    'Unknown Artist',
  );
  const trackId = String(track?.ratingKey || '').trim();
  const displayTitle = firstNonEmptyText(
    [track?.title, track?.originalTitle, track?.titleSort],
    trackId ? `Track ${trackId}` : 'Unknown Track',
  );

  const candidates = [];
  const pushCandidate = (value) => {
    if (value == null) {
      return;
    }
    if (Array.isArray(value)) {
      for (const entry of value) {
        pushCandidate(entry);
      }
      return;
    }
    candidates.push(value);
  };

  pushCandidate(track?.lyrics);
  pushCandidate(track?.lyric);
  pushCandidate(track?.Lyrics);
  pushCandidate(track?.Lyric);
  pushCandidate(extraCandidates);

  const entries = [];
  const seen = new Set();
  const pushEntry = ({ lines, synced = false, lang = 'und', offset = undefined }) => {
    if (!Array.isArray(lines) || lines.length === 0) {
      return;
    }

    const normalizedLang = firstNonEmptyText([lang], 'und');
    const normalizedLines = lines
      .map((line) => ({
        value: String(line?.value || ''),
        start: Number.isFinite(line?.start) ? Math.trunc(line.start) : undefined,
      }))
      .filter((line) => Boolean(line.value));
    if (normalizedLines.length === 0) {
      return;
    }

    const normalizedSynced = synced || normalizedLines.some((line) => Number.isFinite(line.start));
    const effectiveLines = normalizedSynced
      ? normalizedLines.filter((line) => Number.isFinite(line.start) && line.start >= 0)
      : normalizedLines;
    if (effectiveLines.length === 0) {
      return;
    }

    const signature = JSON.stringify({
      lang: normalizedLang,
      synced: normalizedSynced,
      offset: Number.isFinite(offset) ? Math.trunc(offset) : null,
      lines: effectiveLines.map((line) => ({
        value: line.value,
        start: Number.isFinite(line.start) ? line.start : null,
      })),
    });
    if (seen.has(signature)) {
      return;
    }
    seen.add(signature);

    entries.push({
      displayArtist,
      displayTitle,
      lang: normalizedLang,
      synced: normalizedSynced,
      offset: Number.isFinite(offset) ? Math.trunc(offset) : undefined,
      lines: effectiveLines.map((line) => {
        const start = Number.isFinite(line.start) ? line.start : undefined;
        if (start === undefined) {
          return { value: line.value };
        }
        return { value: line.value, start };
      }),
    });
  };

  for (const candidate of candidates) {
    if (typeof candidate === 'string') {
      pushEntry({
        lines: splitLyricsTextLines(candidate),
      });
      continue;
    }

    if (!candidate || typeof candidate !== 'object') {
      continue;
    }

    const candidateLines = normalizeLyricsLines([
      ...(Array.isArray(candidate.lines) ? candidate.lines : []),
      ...(Array.isArray(candidate.Line) ? candidate.Line : []),
    ]);

    if (candidateLines.length > 0) {
      pushEntry({
        lines: candidateLines,
        synced: parseBooleanLike(candidate.synced, false),
        lang: candidate.lang ?? candidate.language ?? 'und',
        offset: parseLyricOffset(candidate.offset),
      });
      continue;
    }

    const textValue = firstNonEmptyText(
      [candidate.text, candidate.value, candidate.lyrics, candidate.lyric],
      '',
    );
    if (!textValue) {
      continue;
    }

    const textLines = splitLyricsTextLines(textValue);
    const start = parseLyricLineStart(candidate.start ?? candidate.time ?? candidate.timestamp);
    if (textLines.length === 1 && start !== undefined) {
      textLines[0].start = start;
    }

    pushEntry({
      lines: textLines,
      synced: parseBooleanLike(candidate.synced, start !== undefined),
      lang: candidate.lang ?? candidate.language ?? 'und',
      offset: parseLyricOffset(candidate.offset),
    });
  }

  return entries;
}

function buildPlainLyricsFromStructuredLyrics(entries) {
  if (!Array.isArray(entries) || entries.length === 0) {
    return {
      artist: undefined,
      title: undefined,
      value: '',
    };
  }

  const preferred = entries.find((entry) => entry?.synced === false) || entries[0];
  const lines = Array.isArray(preferred?.lines) ? preferred.lines : [];

  return {
    artist: preferred?.displayArtist,
    title: preferred?.displayTitle,
    value: lines
      .map((line) => String(line?.value || ''))
      .filter(Boolean)
      .join('\n'),
  };
}

function playlistAttrs(playlist, owner, fallbackIso) {
  const coverArt = firstNonEmptyText([playlist?.thumb, playlist?.art], undefined);
  return {
    id: playlist.ratingKey,
    name: playlist.title || `Playlist ${playlist.ratingKey}`,
    owner,
    public: false,
    readonly: false,
    songCount: playlist.leafCount || 0,
    duration: durationSeconds(playlist.duration),
    coverArt,
    created: toIsoFromEpochSeconds(playlist.addedAt) || fallbackIso,
    changed: toIsoFromEpochSeconds(playlist.updatedAt) || fallbackIso,
  };
}

function plexFolderRootId(sectionId) {
  return String(sectionId || '1');
}

function isPlexFolderPathId(value, sectionId) {
  const id = String(value || '');
  return id.startsWith(`/library/sections/${encodeURIComponent(String(sectionId))}/folder`);
}

function buildPlexFolderPathWithParent(sectionId, parentId) {
  const normalized = String(parentId || '').trim();
  if (!normalized) {
    return null;
  }

  return `/library/sections/${encodeURIComponent(String(sectionId))}/folder?parent=${encodeURIComponent(normalized)}`;
}

function encodePlexFolderId(folderPath, sectionId) {
  const path = String(folderPath || '');
  if (!isPlexFolderPathId(path, sectionId)) {
    return null;
  }

  try {
    const url = new URL(path, 'http://local.invalid');
    const parent = url.searchParams.get('parent');
    if (parent) {
      return `pf:${parent}`;
    }
    return `pfk:${Buffer.from(path, 'utf8').toString('base64url')}`;
  } catch {
    return `pfk:${Buffer.from(path, 'utf8').toString('base64url')}`;
  }
}

function decodePlexFolderId(id, sectionId) {
  const raw = String(id || '');

  if (raw.startsWith('pf:')) {
    return buildPlexFolderPathWithParent(sectionId, raw.slice(3));
  }

  if (raw.startsWith('pfk:')) {
    try {
      const decoded = Buffer.from(raw.slice(4), 'base64url').toString('utf8');
      if (isPlexFolderPathId(decoded, sectionId)) {
        return decoded;
      }
    } catch {
      return null;
    }
    return null;
  }

  return null;
}

function isLikelyPlexTrack(item) {
  return String(item?.type || '').toLowerCase() === 'track' && String(item?.ratingKey || '').length > 0;
}

function isLikelyPlexAlbum(item) {
  return String(item?.type || '').toLowerCase() === 'album' && String(item?.ratingKey || '').length > 0;
}

function parsePositiveInt(value, fallback) {
  const parsed = Number.parseInt(String(value ?? ''), 10);
  if (!Number.isFinite(parsed) || parsed < 1) {
    return fallback;
  }
  return parsed;
}

function parseNonNegativeInt(value, fallback) {
  const parsed = Number.parseInt(String(value ?? ''), 10);
  if (!Number.isFinite(parsed) || parsed < 0) {
    return fallback;
  }
  return parsed;
}

function parseSearchCount(value, fallback = 20, max = 500) {
  const raw = String(value ?? '').trim();
  if (!raw) {
    return Math.min(fallback, max);
  }
  const parsed = Number.parseInt(raw, 10);
  if (!Number.isFinite(parsed) || parsed < 0) {
    return Math.min(fallback, max);
  }
  return Math.min(parsed, max);
}

function searchWindowSize(offset, count, max = 500) {
  const normalizedOffset = Math.max(0, Number.parseInt(String(offset ?? 0), 10) || 0);
  const normalizedCount = Math.max(0, Number.parseInt(String(count ?? 0), 10) || 0);
  if (normalizedCount === 0) {
    return 0;
  }
  return Math.min(max, normalizedOffset + normalizedCount);
}

function mergeByRatingKey(primary = [], secondary = []) {
  const seen = new Set();
  const merged = [];

  for (const item of [...primary, ...secondary]) {
    const ratingKey = String(item?.ratingKey ?? '');
    if (!ratingKey || seen.has(ratingKey)) {
      continue;
    }
    seen.add(ratingKey);
    merged.push(item);
  }

  return merged;
}

async function runPlexSearch({
  plexState,
  query,
  artistWindow,
  albumWindow,
  songWindow,
  signal,
}) {
  let artists = [];
  let albums = [];
  let tracks = [];

  const hubLimit = Math.min(500, Math.max(artistWindow, albumWindow, songWindow) * 4);
  try {
    const hubResults = await searchSectionHubs({
      baseUrl: plexState.baseUrl,
      plexToken: plexState.plexToken,
      sectionId: plexState.musicSectionId,
      query,
      limit: hubLimit,
      signal,
    });
    artists = hubResults.artists;
    albums = hubResults.albums;
    tracks = hubResults.tracks;
  } catch (error) {
    if (error?.name === 'AbortError' || error?.code === 'ABORT_ERR') {
      throw error;
    }
  }

  const missingArtist = artists.length < artistWindow;
  const missingAlbum = albums.length < albumWindow;
  const missingTrack = tracks.length < songWindow;

  if (missingArtist || missingAlbum || missingTrack) {
    const [extraArtists, extraAlbums, extraTracks] = await Promise.all([
      missingArtist
        ? searchSectionMetadata({
          baseUrl: plexState.baseUrl,
          plexToken: plexState.plexToken,
          sectionId: plexState.musicSectionId,
          type: 8,
          query,
          offset: 0,
          limit: artistWindow,
          signal,
        })
        : [],
      missingAlbum
        ? searchSectionMetadata({
          baseUrl: plexState.baseUrl,
          plexToken: plexState.plexToken,
          sectionId: plexState.musicSectionId,
          type: 9,
          query,
          offset: 0,
          limit: albumWindow,
          signal,
        })
        : [],
      missingTrack
        ? searchSectionMetadata({
          baseUrl: plexState.baseUrl,
          plexToken: plexState.plexToken,
          sectionId: plexState.musicSectionId,
          type: 10,
          query,
          offset: 0,
          limit: songWindow,
          signal,
        })
        : [],
    ]);

    artists = mergeByRatingKey(artists, extraArtists);
    albums = mergeByRatingKey(albums, extraAlbums);
    tracks = mergeByRatingKey(tracks, extraTracks);
  }

  return { artists, albums, tracks };
}

function isAbortError(error) {
  return error?.name === 'AbortError' || error?.code === 'ABORT_ERR';
}

function isNumericRatingKey(value) {
  return /^\d+$/.test(String(value || '').trim());
}

function metadataPathRatingKey(value) {
  const raw = String(value || '').trim();
  if (!raw) {
    return '';
  }
  const match = raw.match(/\/library\/metadata\/(\d+)(?:$|[/?#])/i);
  if (!match) {
    return '';
  }
  return String(match[1] || '').trim();
}

function comparableIdVariants(value) {
  const raw = String(value || '').trim();
  if (!raw) {
    return new Set();
  }
  const decoded = (() => {
    try {
      return decodeURIComponent(raw);
    } catch {
      return raw;
    }
  })();

  const variants = new Set();
  const push = (candidate) => {
    const text = String(candidate || '').trim();
    if (!text) {
      return;
    }
    const normalized = safeLower(text.replace(/\/+$/, ''));
    if (normalized) {
      variants.add(normalized);
    }
  };

  push(raw);
  push(decoded);
  push(raw.replace('://', '/'));
  push(decoded.replace('://', '/'));

  const metadataId = metadataPathRatingKey(raw) || metadataPathRatingKey(decoded);
  if (metadataId) {
    push(metadataId);
  }
  const trailingNumericId = (decoded.match(/(?:^|[/:])(\d+)(?:$|[/?#])/i) || [])[1];
  if (trailingNumericId) {
    push(trailingNumericId);
  }

  return variants;
}

function itemHasMatchingId(item, requestedId) {
  const requested = comparableIdVariants(requestedId);
  if (requested.size === 0 || !item || typeof item !== 'object') {
    return false;
  }

  const candidateValues = [];
  const pushCandidate = (value) => {
    if (value == null) {
      return;
    }
    if (Array.isArray(value)) {
      for (const entry of value) {
        pushCandidate(entry);
      }
      return;
    }
    if (typeof value === 'object') {
      pushCandidate(value.id);
      pushCandidate(value.guid);
      pushCandidate(value.key);
      return;
    }
    candidateValues.push(String(value));
  };

  pushCandidate(item.ratingKey);
  pushCandidate(item.guid);
  pushCandidate(item.key);
  pushCandidate(item.sourceUri);
  pushCandidate(item.sourceURI);
  pushCandidate(item.Guid);

  for (const value of candidateValues) {
    const variants = comparableIdVariants(value);
    for (const variant of variants) {
      if (requested.has(variant)) {
        return true;
      }
    }
  }

  return false;
}

function findItemByRequestedId(items, requestedId) {
  const source = Array.isArray(items) ? items : [];
  const normalizedRequested = String(requestedId || '').trim();
  if (!normalizedRequested) {
    return null;
  }

  const exact = source.find((item) => String(item?.ratingKey || '').trim() === normalizedRequested);
  if (exact) {
    return exact;
  }

  return source.find((item) => itemHasMatchingId(item, normalizedRequested)) || null;
}

function isUpstreamTerminationError(error) {
  if (!error) {
    return false;
  }

  const message = String(error?.message || '').toLowerCase();
  const causeMessage = String(error?.cause?.message || '').toLowerCase();
  const code = String(error?.code || error?.cause?.code || '').toUpperCase();
  const causeName = String(error?.cause?.name || '').toLowerCase();

  return (
    code === 'ECONNRESET' ||
    code === 'EPIPE' ||
    message.includes('terminated') ||
    message.includes('other side closed') ||
    causeMessage.includes('other side closed') ||
    causeName.includes('socketerror')
  );
}

function isClientDisconnected(request, reply) {
  return Boolean(
    request?.raw?.aborted ||
    request?.raw?.destroyed ||
    reply?.raw?.destroyed ||
    reply?.raw?.writableEnded,
  );
}

const RETRYABLE_UPSTREAM_STATUSES = new Set([408, 429, 500, 502, 503, 504]);

function waitMs(ms) {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

function composeAbortSignals(signals) {
  const filtered = signals.filter((signal) => signal && typeof signal === 'object');
  if (filtered.length === 0) {
    return undefined;
  }
  if (filtered.length === 1) {
    return filtered[0];
  }
  if (typeof AbortSignal?.any === 'function') {
    return AbortSignal.any(filtered);
  }

  const fallbackController = new AbortController();
  const abortFallback = (event) => {
    const signal = event?.target;
    if (!fallbackController.signal.aborted) {
      try {
        fallbackController.abort(signal?.reason);
      } catch {
        fallbackController.abort();
      }
    }
  };
  for (const signal of filtered) {
    if (signal.aborted) {
      try {
        fallbackController.abort(signal.reason);
      } catch {
        fallbackController.abort();
      }
      break;
    }
    signal.addEventListener('abort', abortFallback, { once: true });
  }
  return fallbackController.signal;
}

async function fetchWithRetry({
  url,
  options = {},
  request = null,
  context = 'upstream request',
  maxAttempts = 3,
  baseDelayMs = 200,
  attemptHeadersTimeoutMs = DEFAULT_UPSTREAM_HEADERS_TIMEOUT_MS,
}) {
  let lastError = null;

  for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
    const externalSignal = options?.signal;
    const attemptController = new AbortController();
    let timeoutId = null;
    let timedOut = false;

    if (Number.isFinite(attemptHeadersTimeoutMs) && attemptHeadersTimeoutMs > 0) {
      timeoutId = setTimeout(() => {
        timedOut = true;
        try {
          attemptController.abort(UPSTREAM_HEADERS_TIMEOUT_REASON);
        } catch {
          attemptController.abort();
        }
      }, attemptHeadersTimeoutMs);
      if (typeof timeoutId.unref === 'function') {
        timeoutId.unref();
      }
    }

    try {
      const response = await fetch(url, {
        ...options,
        signal: composeAbortSignals([externalSignal, attemptController.signal]),
      });
      if (timeoutId) {
        clearTimeout(timeoutId);
      }
      if (!RETRYABLE_UPSTREAM_STATUSES.has(response.status) || attempt >= maxAttempts) {
        return response;
      }

      request?.log?.warn(
        { context, status: response.status, attempt, maxAttempts },
        'Transient upstream failure, retrying',
      );

      try {
        await response.body?.cancel?.();
      } catch { }
    } catch (error) {
      if (timeoutId) {
        clearTimeout(timeoutId);
      }

      if (externalSignal?.aborted) {
        throw error;
      }

      const abortedForHeadersTimeout = timedOut || attemptController.signal.reason === UPSTREAM_HEADERS_TIMEOUT_REASON;
      if (isAbortError(error) && !abortedForHeadersTimeout && attempt >= maxAttempts) {
        throw error;
      }
      lastError = error;
      if (attempt >= maxAttempts) {
        throw error;
      }

      request?.log?.warn(
        {
          context,
          attempt,
          maxAttempts,
          message: error?.message || String(error),
          headersTimeoutMs: attemptHeadersTimeoutMs,
          headersTimeout: abortedForHeadersTimeout,
        },
        'Transient upstream error, retrying',
      );
    }

    await waitMs(baseDelayMs * attempt);
  }

  if (lastError) {
    throw lastError;
  }

  throw new Error(`${context} failed after retries`);
}

function isPlexNotFoundError(error) {
  return String(error?.message || '').includes('(404)');
}

function safeLower(value) {
  return String(value || '').toLowerCase();
}

function includesText(haystack, needle) {
  return safeLower(haystack).includes(safeLower(needle));
}

function trackPrimaryArtistName(track) {
  return firstNonEmptyText(
    [track?.artist, track?.originalTitle, track?.grandparentTitle],
    '',
  );
}

function trackPrimaryArtistId(track) {
  return firstNonEmptyText(
    [track?.grandparentRatingKey, track?.artistId, track?.guid],
    '',
  );
}

function matchesArtistSearchQuery(artist, query) {
  return includesText(artist?.title, query) || includesText(artist?.name, query);
}

function matchesAlbumSearchQuery(album, query) {
  return includesText(album?.title, query) ||
    includesText(album?.parentTitle, query) ||
    includesText(album?.originalTitle, query);
}

function matchesTrackSearchQuery(track, query) {
  return includesText(track?.title, query) ||
    includesText(track?.grandparentTitle, query) ||
    includesText(track?.parentTitle, query) ||
    includesText(trackPrimaryArtistName(track), query);
}

function pickPagedSearchSource(filteredItems, fallbackItems, offset, count) {
  const filtered = Array.isArray(filteredItems) ? filteredItems : [];
  const fallback = Array.isArray(fallbackItems) ? fallbackItems : [];
  if (count <= 0) {
    return filtered.length > 0 ? filtered : fallback;
  }
  if (filtered.length > offset) {
    return filtered;
  }
  return fallback;
}

function deriveVirtualArtistsFromTracks(tracks, query = '') {
  const source = Array.isArray(tracks) ? tracks : [];
  const grouped = new Map();

  for (const track of source) {
    const artistId = String(trackPrimaryArtistId(track) || '').trim();
    const artistName = String(trackPrimaryArtistName(track) || '').trim();
    if (!artistId || !artistName) {
      continue;
    }
    if (query && !includesText(artistName, query)) {
      continue;
    }

    const key = `${safeLower(artistId)}::${safeLower(artistName)}`;
    const current = grouped.get(key) || {
      ratingKey: artistId,
      title: artistName,
      albumIds: new Set(),
      addedAt: 0,
      updatedAt: 0,
      thumb: '',
    };
    const albumId = String(track?.parentRatingKey || '').trim();
    if (albumId) {
      current.albumIds.add(albumId);
    }
    current.addedAt = Math.max(Number(current.addedAt || 0), Number(track?.addedAt || 0));
    current.updatedAt = Math.max(Number(current.updatedAt || 0), Number(track?.updatedAt || 0));
    if (!current.thumb) {
      current.thumb = String(track?.grandparentRatingKey || track?.parentRatingKey || '').trim();
    }
    grouped.set(key, current);
  }

  return [...grouped.values()]
    .map((entry) => ({
      ratingKey: entry.ratingKey,
      title: entry.title,
      albumCount: entry.albumIds.size,
      leafCount: entry.albumIds.size,
      addedAt: entry.addedAt || undefined,
      updatedAt: entry.updatedAt || undefined,
      thumb: entry.thumb || undefined,
    }))
    .sort((a, b) => String(a?.title || '').localeCompare(String(b?.title || '')));
}

function normalizeSearchQuery(value) {
  const raw = String(value || '').trim();
  if (!raw) {
    return '';
  }

  if (raw === '""' || raw === "''") {
    return '';
  }

  if (
    (raw.startsWith('"') && raw.endsWith('"')) ||
    (raw.startsWith("'") && raw.endsWith("'"))
  ) {
    const unwrapped = raw.slice(1, -1).trim();
    if (!unwrapped) {
      return '';
    }
    return unwrapped;
  }

  return raw;
}

function takePage(items, offset, size) {
  return items.slice(offset, offset + size);
}

function assignNonEmptyBucket(target, key, items) {
  if (Array.isArray(items) && items.length > 0) {
    target[key] = items;
  }
}

function shuffleInPlace(items) {
  for (let i = items.length - 1; i > 0; i -= 1) {
    const j = Math.floor(Math.random() * (i + 1));
    [items[i], items[j]] = [items[j], items[i]];
  }
  return items;
}

const SUPPORTED_ALBUM_LIST_TYPES = new Set([
  'random',
  'newest',
  'highest',
  'frequent',
  'recent',
  'alphabeticalbyname',
  'alphabeticalbyartist',
  'starred',
  'byyear',
  'bygenre',
]);

function albumTimestampValue(album, keys = []) {
  for (const key of keys) {
    const parsed = Number.parseInt(String(album?.[key] ?? ''), 10);
    if (Number.isFinite(parsed) && parsed > 0) {
      return parsed;
    }
  }
  return 0;
}

function albumCountValue(album, keys = []) {
  for (const key of keys) {
    const parsed = Number.parseFloat(String(album?.[key] ?? ''));
    if (Number.isFinite(parsed) && parsed > 0) {
      return parsed;
    }
  }
  return 0;
}

function normalizeAlbumListType(rawType) {
  return safeLower(String(rawType || '').trim());
}

function sliceAlbumPage(items, offset, size) {
  const normalizedOffset = Math.max(0, Number.parseInt(String(offset ?? 0), 10) || 0);
  const normalizedSize = Math.max(1, Math.min(Number.parseInt(String(size ?? 10), 10) || 10, 500));
  return items.slice(normalizedOffset, normalizedOffset + normalizedSize);
}

function albumTitleSortValue(album) {
  return String(album?.titleSort || album?.title || '').toLowerCase();
}

function albumArtistSortValue(album) {
  return String(album?.parentTitle || '').toLowerCase();
}

function sortAlbumsByName(albums) {
  return [...albums].sort((a, b) => {
    const byTitle = albumTitleSortValue(a).localeCompare(albumTitleSortValue(b));
    if (byTitle !== 0) {
      return byTitle;
    }
    return String(a?.ratingKey || '').localeCompare(String(b?.ratingKey || ''));
  });
}

function filterAndSortAlbumList(albums, { type, fromYear, toYear, genre }) {
  let list = [...albums];

  switch (type) {
    case 'random':
      list = shuffleInPlace(list.slice());
      break;
    case 'newest':
      list.sort((a, b) => {
        const tsA = albumTimestampValue(a, ['addedAt']);
        const tsB = albumTimestampValue(b, ['addedAt']);
        if (tsA !== tsB) {
          return tsB - tsA;
        }
        return albumTitleSortValue(a).localeCompare(albumTitleSortValue(b));
      });
      break;
    case 'highest':
      list = list.filter((album) => {
        const rating = normalizePlexRating(album?.userRating);
        return rating != null && rating > 0;
      });
      list.sort((a, b) => {
        const ratingA = normalizePlexRating(a?.userRating) ?? 0;
        const ratingB = normalizePlexRating(b?.userRating) ?? 0;
        if (ratingA !== ratingB) {
          return ratingB - ratingA;
        }
        const tsA = albumTimestampValue(a, ['updatedAt', 'addedAt']);
        const tsB = albumTimestampValue(b, ['updatedAt', 'addedAt']);
        if (tsA !== tsB) {
          return tsB - tsA;
        }
        return albumTitleSortValue(a).localeCompare(albumTitleSortValue(b));
      });
      break;
    case 'frequent':
      list = list.filter((album) => albumCountValue(album, ['viewCount', 'playCount']) > 0);
      list.sort((a, b) => {
        const countA = albumCountValue(a, ['viewCount', 'playCount']);
        const countB = albumCountValue(b, ['viewCount', 'playCount']);
        if (countA !== countB) {
          return countB - countA;
        }
        const tsA = albumTimestampValue(a, ['lastViewedAt', 'updatedAt', 'addedAt']);
        const tsB = albumTimestampValue(b, ['lastViewedAt', 'updatedAt', 'addedAt']);
        if (tsA !== tsB) {
          return tsB - tsA;
        }
        return albumTitleSortValue(a).localeCompare(albumTitleSortValue(b));
      });
      break;
    case 'recent':
      list = list.filter((album) => albumTimestampValue(album, ['lastViewedAt']) > 0);
      list.sort((a, b) => {
        const tsA = albumTimestampValue(a, ['lastViewedAt']);
        const tsB = albumTimestampValue(b, ['lastViewedAt']);
        if (tsA !== tsB) {
          return tsB - tsA;
        }
        return albumTitleSortValue(a).localeCompare(albumTitleSortValue(b));
      });
      break;
    case 'alphabeticalbyname':
      list = sortAlbumsByName(list);
      break;
    case 'alphabeticalbyartist':
      list.sort((a, b) => {
        const byArtist = albumArtistSortValue(a).localeCompare(albumArtistSortValue(b));
        if (byArtist !== 0) {
          return byArtist;
        }
        const byTitle = albumTitleSortValue(a).localeCompare(albumTitleSortValue(b));
        if (byTitle !== 0) {
          return byTitle;
        }
        return String(a?.ratingKey || '').localeCompare(String(b?.ratingKey || ''));
      });
      break;
    case 'starred':
      list = list.filter((album) => isPlexLiked(album?.userRating));
      list.sort((a, b) => {
        const tsA = albumTimestampValue(a, ['updatedAt', 'addedAt']);
        const tsB = albumTimestampValue(b, ['updatedAt', 'addedAt']);
        if (tsA !== tsB) {
          return tsB - tsA;
        }
        return albumTitleSortValue(a).localeCompare(albumTitleSortValue(b));
      });
      break;
    case 'byyear': {
      const low = Math.min(fromYear, toYear);
      const high = Math.max(fromYear, toYear);
      list = list.filter((album) => {
        const year = Number.parseInt(String(album?.year ?? ''), 10);
        return Number.isFinite(year) && year >= low && year <= high;
      });
      const descending = fromYear > toYear;
      list.sort((a, b) => {
        const yearA = Number.parseInt(String(a?.year ?? ''), 10) || 0;
        const yearB = Number.parseInt(String(b?.year ?? ''), 10) || 0;
        if (yearA !== yearB) {
          return descending ? yearB - yearA : yearA - yearB;
        }
        return albumTitleSortValue(a).localeCompare(albumTitleSortValue(b));
      });
      break;
    }
    case 'bygenre':
      list = list.filter((album) =>
        allGenreTags(album).some((tag) => safeLower(tag) === safeLower(genre)),
      );
      list = sortAlbumsByName(list);
      break;
    default:
      break;
  }

  return list;
}

function allGenreTags(item) {
  const tags = [];
  const splitGenreParts = (value) =>
    String(value || '')
      .split(/[;,]/)
      .map((part) => part.trim())
      .filter(Boolean);
  const pushTag = (value) => {
    const text = String(value || '').trim();
    if (!text) {
      return;
    }
    for (const part of splitGenreParts(text)) {
      tags.push(part);
    }
  };

  const genreEntries = Array.isArray(item?.Genre) ? item.Genre : [];
  for (const entry of genreEntries) {
    if (typeof entry === 'string') {
      pushTag(entry);
      continue;
    }
    if (!entry || typeof entry !== 'object') {
      continue;
    }
    pushTag(entry.tag ?? entry.name ?? entry.title ?? entry.value);
  }

  const plainGenre = item?.genre;
  if (Array.isArray(plainGenre)) {
    for (const entry of plainGenre) {
      pushTag(entry);
    }
  } else if (plainGenre != null) {
    pushTag(plainGenre);
  }

  return [...new Set(tags)];
}

function genreObjects(tags) {
  const normalized = [...new Set(
    (Array.isArray(tags) ? tags : [])
      .map((tag) => String(tag || '').trim())
      .filter(Boolean),
  )];
  if (normalized.length === 0) {
    return undefined;
  }
  return normalized.map((name) => ({ name }));
}

function buildAlbumGenreTagMap(albums) {
  const map = new Map();
  for (const album of Array.isArray(albums) ? albums : []) {
    const albumId = String(album?.ratingKey || '').trim();
    if (!albumId) {
      continue;
    }
    map.set(albumId, allGenreTags(album));
  }
  return map;
}

function resolvedGenreTagsForTrack(track, albumGenreTagMap) {
  const directTags = allGenreTags(track);
  if (directTags.length > 0) {
    return directTags;
  }

  const albumId = String(track?.parentRatingKey || '').trim();
  if (!albumId) {
    return [];
  }

  const albumTags = albumGenreTagMap.get(albumId);
  return Array.isArray(albumTags) ? albumTags : [];
}

function withResolvedTrackGenres(track, albumGenreTagMap) {
  const resolvedTags = resolvedGenreTagsForTrack(track, albumGenreTagMap);
  if (resolvedTags.length === 0) {
    return track;
  }

  const currentTags = allGenreTags(track);
  if (currentTags.length > 0) {
    return track;
  }

  return {
    ...track,
    Genre: resolvedTags.map((tag) => ({ tag })),
    genre: resolvedTags.join('; '),
  };
}

function firstGenreTag(item) {
  const tags = allGenreTags(item);
  return tags[0] || null;
}

function splitMetadataTextValues(value) {
  const text = String(value || '').trim();
  if (!text) {
    return [];
  }
  if (!text.includes(';')) {
    return [text];
  }
  return text
    .split(';')
    .map((entry) => entry.trim())
    .filter(Boolean);
}

function normalizeMetadataTagValues(value) {
  if (value == null) {
    return [];
  }
  if (Array.isArray(value)) {
    return [...new Set(value.flatMap((entry) => normalizeMetadataTagValues(entry)))];
  }
  if (typeof value === 'object') {
    const text = firstNonEmptyText(
      [value.tag, value.name, value.title, value.value, value.text, value.label],
      '',
    );
    if (!text) {
      return [];
    }
    return splitMetadataTextValues(text);
  }
  return splitMetadataTextValues(value);
}

function metadataFieldText(sources, keys) {
  const values = metadataFieldValues(sources, keys);
  if (values.length > 0) {
    return values.join('; ');
  }
  return undefined;
}

function metadataFieldValues(sources, keys) {
  for (const source of sources) {
    if (!source || typeof source !== 'object') {
      continue;
    }
    for (const key of keys) {
      const values = normalizeMetadataTagValues(source[key]);
      if (values.length > 0) {
        return values;
      }
    }
  }
  return [];
}

function buildPlexStateFromContext(plexContext, tokenCipher) {
  const plexTokenCandidates = [];
  if (plexContext.server_token_enc) {
    try {
      const serverToken = decodePlexTokenOrThrow(tokenCipher, plexContext.server_token_enc);
      plexTokenCandidates.push(serverToken);
    } catch { }
  }
  if (plexContext.plex_token_enc) {
    try {
      const accountToken = decodePlexTokenOrThrow(tokenCipher, plexContext.plex_token_enc);
      plexTokenCandidates.push(accountToken);
    } catch { }
  }

  const plexToken = uniqueNonEmptyValues(plexTokenCandidates);
  if (plexToken.length === 0) {
    return null;
  }

  return {
    accountId: plexContext.account_id,
    username: plexContext.username,
    plexToken,
    baseUrl: plexContext.server_base_url,
    machineId: plexContext.machine_id,
    musicSectionId: plexContext.music_section_id,
    musicSectionName: plexContext.music_section_name || null,
    serverName: plexContext.server_name || 'Plex Music',
  };
}

function hasPlexSelectionContext(plexContext) {
  return Boolean(
    plexContext &&
    (plexContext.plex_token_enc || plexContext.server_token_enc) &&
    plexContext.server_base_url &&
    plexContext.machine_id &&
    plexContext.music_section_id,
  );
}

function chooseRecoverableMusicSection(sections, preferredId, preferredName) {
  const source = Array.isArray(sections) ? sections : [];
  if (source.length === 0) {
    return null;
  }
  const preferredIdText = String(preferredId || '').trim();
  if (preferredIdText) {
    const exact = source.find((section) => String(section?.id || '').trim() === preferredIdText);
    if (exact) {
      return exact;
    }
  }
  const preferredNameText = safeLower(String(preferredName || '').trim());
  if (preferredNameText) {
    const byName = source.find((section) => safeLower(String(section?.title || '').trim()) === preferredNameText);
    if (byName) {
      return byName;
    }
  }
  if (source.length === 1) {
    return source[0];
  }
  return null;
}

function requiredPlexStateForSubsonic(reply, plexContext, tokenCipher) {
  if (!plexContext?.plex_token_enc && !plexContext?.server_token_enc) {
    sendSubsonicError(reply, 10, 'Plex not linked');
    return null;
  }

  if (!plexContext.server_base_url) {
    sendSubsonicError(reply, 10, 'No server selected');
    return null;
  }

  if (!plexContext.machine_id) {
    sendSubsonicError(reply, 10, 'No server selected');
    return null;
  }

  if (!plexContext.music_section_id) {
    sendSubsonicError(reply, 10, 'No library selected');
    return null;
  }

  const plexState = buildPlexStateFromContext(plexContext, tokenCipher);
  if (!plexState) {
    sendSubsonicError(reply, 10, 'Stored Plex token is unreadable');
    return null;
  }
  return plexState;
}

function createSqliteSessionStore(db, logger) {
  const upsertStmt = db.prepare(`
    INSERT INTO web_sessions (session_id, session_json, expires_at, updated_at)
    VALUES (@session_id, @session_json, @expires_at, @updated_at)
    ON CONFLICT(session_id)
    DO UPDATE SET
      session_json = excluded.session_json,
      expires_at = excluded.expires_at,
      updated_at = excluded.updated_at
  `);
  const getStmt = db.prepare(`
    SELECT session_json, expires_at
    FROM web_sessions
    WHERE session_id = ?
  `);
  const deleteStmt = db.prepare(`
    DELETE FROM web_sessions
    WHERE session_id = ?
  `);

  return {
    set(sessionId, session, callback) {
      try {
        const cookieExpiresAt =
          session?.cookie?.expires instanceof Date
            ? session.cookie.expires.getTime()
            : typeof session?.cookie?.expires === 'string'
              ? Date.parse(session.cookie.expires)
              : null;
        const cookieMaxAge = Number(session?.cookie?.maxAge);
        const maxAgeExpiresAt =
          Number.isFinite(cookieMaxAge) && cookieMaxAge > 0 ? Date.now() + cookieMaxAge : null;
        const expiresAt = Number.isFinite(cookieExpiresAt) ? cookieExpiresAt : maxAgeExpiresAt;

        upsertStmt.run({
          session_id: String(sessionId),
          session_json: JSON.stringify(session || {}),
          expires_at: Number.isFinite(expiresAt) ? Math.trunc(expiresAt) : null,
          updated_at: Date.now(),
        });
        callback();
      } catch (error) {
        logger?.error(error, 'Failed to persist web session');
        callback(error);
      }
    },

    get(sessionId, callback) {
      try {
        const row = getStmt.get(String(sessionId));
        if (!row) {
          callback(null, null);
          return;
        }

        if (Number.isFinite(row.expires_at) && row.expires_at > 0 && row.expires_at <= Date.now()) {
          deleteStmt.run(String(sessionId));
          callback(null, null);
          return;
        }

        const parsed = JSON.parse(String(row.session_json || '{}'));
        callback(null, parsed);
      } catch (error) {
        logger?.error(error, 'Failed to load web session');
        callback(error);
      }
    },

    destroy(sessionId, callback) {
      try {
        deleteStmt.run(String(sessionId));
        callback();
      } catch (error) {
        logger?.error(error, 'Failed to destroy web session');
        callback(error);
      }
    },
  };
}

export async function buildServer(config = loadConfig()) {
  const db = openDatabase(config.sqlitePath);
  migrate(db);
  const cacheDb = openDatabase(config.cacheSqlitePath || config.sqlitePath);
  migrateCache(cacheDb);

  const repo = createRepositories(db);
  const tokenCipher = createTokenCipher({
    rawKey: config.tokenEncKey,
    fallbackSeed: config.sessionSecret,
  });

  const app = Fastify({
    logger: {
      level: config.logLevel,
      transport: {
        target: 'pino-pretty',
        options: {
          colorize: true,
          translateTime: 'SYS:standard',
          ignore: 'pid,hostname',
        },
      },
    },
    disableRequestLogging: !config.logRequests,
    rewriteUrl(req) {
      return normalizeRestViewPath(req.url);
    },
  });

  app.addHook('onRoute', (routeOptions) => {
    if (!String(routeOptions.url || '').startsWith('/rest/')) {
      return;
    }

    if (routeOptions.method === 'GET') {
      routeOptions.method = ['GET', 'POST'];
      return;
    }

    if (Array.isArray(routeOptions.method) && routeOptions.method.includes('GET') && !routeOptions.method.includes('POST')) {
      routeOptions.method = [...routeOptions.method, 'POST'];
    }
  });

  app.decorate('config', config);
  app.decorate('repo', repo);
  app.decorate('db', db);
  app.decorate('cacheDb', cacheDb);

  const transcodeCacheRoot = path.resolve(config.transcodeCachePath || './data/transcodes');
  try {
    await fsp.mkdir(transcodeCacheRoot, { recursive: true });
  } catch (error) {
    app.log.warn({ err: error, path: transcodeCacheRoot }, 'Failed to prepare transcode cache directory');
  }
  const transcodeCleanupIntervalMs = Math.max(
    0,
    Number(config.transcodeCleanupIntervalSeconds || 0) * 1000,
  );
  const transcodeArtifactMaxAgeMs = Math.max(
    0,
    Number(config.transcodeArtifactMaxAgeSeconds || 0) * 1000,
  );
  const transcodeArtifactCleanupTimer = startTranscodeArtifactCleanupScheduler({
    rootDir: transcodeCacheRoot,
    intervalMs: transcodeCleanupIntervalMs,
    maxAgeMs: transcodeArtifactMaxAgeMs,
    logger: app.log,
  });

  if (!tokenCipher.hasExplicitKey) {
    app.log.warn('TOKEN_ENC_KEY missing or invalid. Falling back to hash of SESSION_SECRET for token encryption.');
  }

  await app.register(fastifyCookie);
  await app.register(fastifyFormbody);
  await app.register(fastifyMultipart, {
    attachFieldsToBody: true,
  });
  const sessionStore = createSqliteSessionStore(db, app.log);
  await app.register(fastifySession, {
    secret: config.sessionSecret,
    cookieName: 'plexsonic.sid',
    store: sessionStore,
    saveUninitialized: false,
    cookie: {
      path: '/',
      httpOnly: true,
      sameSite: 'lax',
      secure: false,
    },
  });

  app.addHook('onRequest', async (request, reply) => {
    applyCorsHeaders(request, reply);
    if (request.method === 'OPTIONS') {
      return reply.code(204).send();
    }
  });

  app.addHook('onClose', async () => {
    if (transcodeArtifactCleanupTimer) {
      clearInterval(transcodeArtifactCleanupTimer);
    }
    cacheDb.close();
    db.close();
  });

  const playbackSessions = new Map();
  const recentScrobblesByClient = new Map();
  const savedPlayQueues = new Map();
  const PLAYBACK_RECONCILE_INTERVAL_MS = 15000;
  const PLAYBACK_IDLE_TIMEOUT_MS = 120000;
  const STREAM_DISCONNECT_STOP_DELAY_MS = 4000;
  const PLAYBACK_MAX_DISCONNECT_WAIT_MS = 30 * 60 * 1000;
  const STREAM_PROGRESS_HEARTBEAT_MS = 10000;
  const STREAM_PRELOAD_SUPPRESS_AFTER_SCROBBLE_MS = 1500;
  const STREAM_SUPPRESSED_PROMOTE_DELAY_MS = 1200;
  const PLAYBACK_CONTINUITY_AFTER_SCROBBLE_MS = 15000;
  const PLAY_QUEUE_IDLE_TTL_MS = 6 * 60 * 60 * 1000;
  const activeSearchRequests = new Map();
  const cacheWarmupInFlight = new Map();
  const cacheCollectionLoadInFlight = new Map();
  const cacheRefreshInFlight = new Map();
  const cacheChangeCheckInFlight = new Map();
  const SEARCH_BROWSE_REVALIDATE_DEBOUNCE_MS = 15000;
  const SEARCH_BROWSE_CHANGE_CHECK_DEBOUNCE_MS = 15000;
  const SEARCH_BROWSE_COLLECTIONS = ['artists', 'albums', 'tracks'];
  const getLibraryCacheStateStmt = cacheDb.prepare(`
    SELECT cache_key, last_fingerprint, last_checked_at, last_synced_at, dirty, updated_at
    FROM plex_library_cache_state
    WHERE cache_key = ?
  `);
  const upsertLibraryCacheStateStmt = cacheDb.prepare(`
    INSERT INTO plex_library_cache_state (
      cache_key,
      last_fingerprint,
      last_checked_at,
      last_synced_at,
      dirty,
      updated_at
    )
    VALUES (
      @cache_key,
      @last_fingerprint,
      @last_checked_at,
      @last_synced_at,
      @dirty,
      @updated_at
    )
    ON CONFLICT(cache_key)
    DO UPDATE SET
      last_fingerprint = excluded.last_fingerprint,
      last_checked_at = excluded.last_checked_at,
      last_synced_at = excluded.last_synced_at,
      dirty = excluded.dirty,
      updated_at = excluded.updated_at
  `);
  const hasLibraryCacheDataStmt = cacheDb.prepare(`
    SELECT 1 AS exists_flag
    FROM (
      SELECT cache_key FROM plex_library_cache_artists WHERE cache_key = ?
      UNION ALL
      SELECT cache_key FROM plex_library_cache_albums WHERE cache_key = ?
      UNION ALL
      SELECT cache_key FROM plex_library_cache_tracks WHERE cache_key = ?
    )
    LIMIT 1
  `);
  const hasLibraryCacheArtistsStmt = cacheDb.prepare(`
    SELECT 1 AS exists_flag
    FROM plex_library_cache_artists
    WHERE cache_key = ?
    LIMIT 1
  `);
  const hasLibraryCacheAlbumsStmt = cacheDb.prepare(`
    SELECT 1 AS exists_flag
    FROM plex_library_cache_albums
    WHERE cache_key = ?
    LIMIT 1
  `);
  const hasLibraryCacheTracksStmt = cacheDb.prepare(`
    SELECT 1 AS exists_flag
    FROM plex_library_cache_tracks
    WHERE cache_key = ?
    LIMIT 1
  `);
  const selectLibraryCacheArtistRowsStmt = cacheDb.prepare(`
    SELECT *
    FROM plex_library_cache_artists
    WHERE cache_key = ?
    ORDER BY order_index ASC
  `);
  const selectLibraryCacheAlbumRowsStmt = cacheDb.prepare(`
    SELECT *
    FROM plex_library_cache_albums
    WHERE cache_key = ?
    ORDER BY order_index ASC
  `);
  const selectLibraryCacheTrackRowsStmt = cacheDb.prepare(`
    SELECT *
    FROM plex_library_cache_tracks
    WHERE cache_key = ?
    ORDER BY order_index ASC
  `);
  const selectAlbumGenreRowsStmt = cacheDb.prepare(`
    SELECT album_rating_key, genre_name
    FROM plex_library_cache_album_genres
    WHERE cache_key = ?
    ORDER BY order_index ASC
  `);
  const selectTrackGenreRowsStmt = cacheDb.prepare(`
    SELECT track_rating_key, genre_name
    FROM plex_library_cache_track_genres
    WHERE cache_key = ?
    ORDER BY order_index ASC
  `);
  const selectTrackArtistRowsStmt = cacheDb.prepare(`
    SELECT track_rating_key, artist_id, artist_name
    FROM plex_library_cache_track_artists
    WHERE cache_key = ?
    ORDER BY order_index ASC
  `);
  const selectTrackAlbumArtistRowsStmt = cacheDb.prepare(`
    SELECT track_rating_key, artist_id, artist_name
    FROM plex_library_cache_track_album_artists
    WHERE cache_key = ?
    ORDER BY order_index ASC
  `);
  const selectTrackGenresByTrackStmt = cacheDb.prepare(`
    SELECT genre_name
    FROM plex_library_cache_track_genres
    WHERE cache_key = ? AND track_rating_key = ?
    ORDER BY order_index ASC
  `);
  const selectTrackArtistsByTrackStmt = cacheDb.prepare(`
    SELECT artist_id, artist_name
    FROM plex_library_cache_track_artists
    WHERE cache_key = ? AND track_rating_key = ?
    ORDER BY order_index ASC
  `);
  const selectTrackAlbumArtistsByTrackStmt = cacheDb.prepare(`
    SELECT artist_id, artist_name
    FROM plex_library_cache_track_album_artists
    WHERE cache_key = ? AND track_rating_key = ?
    ORDER BY order_index ASC
  `);
  const selectAlbumGenresByAlbumStmt = cacheDb.prepare(`
    SELECT genre_name
    FROM plex_library_cache_album_genres
    WHERE cache_key = ? AND album_rating_key = ?
    ORDER BY order_index ASC
  `);
  const selectArtistRowByRatingKeyStmt = cacheDb.prepare(`
    SELECT *
    FROM plex_library_cache_artists
    WHERE cache_key = ? AND rating_key = ?
    LIMIT 1
  `);
  const selectArtistRowByTitleStmt = cacheDb.prepare(`
    SELECT *
    FROM plex_library_cache_artists
    WHERE cache_key = ? AND lower(COALESCE(title, '')) = lower(?)
    LIMIT 1
  `);
  const selectArtistRowByIdentityStmt = cacheDb.prepare(`
    SELECT *
    FROM plex_library_cache_artists
    WHERE cache_key = @cache_key
      AND (
        rating_key = @exact
        OR lower(COALESCE(guid, '')) = @lowered
        OR lower(COALESCE(key_path, '')) = @lowered
        OR lower(COALESCE(source_uri, '')) = @lowered
      )
    LIMIT 1
  `);
  const selectAlbumRowByRatingKeyStmt = cacheDb.prepare(`
    SELECT *
    FROM plex_library_cache_albums
    WHERE cache_key = ? AND rating_key = ?
    LIMIT 1
  `);
  const selectAlbumRowByIdentityStmt = cacheDb.prepare(`
    SELECT *
    FROM plex_library_cache_albums
    WHERE cache_key = @cache_key
      AND (
        rating_key = @exact
        OR lower(COALESCE(guid, '')) = @lowered
        OR lower(COALESCE(key_path, '')) = @lowered
        OR lower(COALESCE(source_uri, '')) = @lowered
      )
    LIMIT 1
  `);
  const selectTrackRowByRatingKeyStmt = cacheDb.prepare(`
    SELECT *
    FROM plex_library_cache_tracks
    WHERE cache_key = ? AND rating_key = ?
    LIMIT 1
  `);
  const selectTrackRowByIdentityStmt = cacheDb.prepare(`
    SELECT *
    FROM plex_library_cache_tracks
    WHERE cache_key = @cache_key
      AND (
        rating_key = @exact
        OR lower(COALESCE(guid, '')) = @lowered
        OR lower(COALESCE(key_path, '')) = @lowered
        OR lower(COALESCE(source_uri, '')) = @lowered
        OR lower(COALESCE(part_file, '')) = @lowered
      )
    LIMIT 1
  `);
  const selectAlbumsByParentRatingKeyStmt = cacheDb.prepare(`
    SELECT *
    FROM plex_library_cache_albums
    WHERE cache_key = ? AND parent_rating_key = ?
    ORDER BY sort_key ASC, rating_key ASC
  `);
  const selectAlbumsByParentTitleStmt = cacheDb.prepare(`
    SELECT *
    FROM plex_library_cache_albums
    WHERE cache_key = ? AND lower(parent_title) = lower(?)
    ORDER BY sort_key ASC, rating_key ASC
  `);
  const selectTracksByGrandparentRatingKeyStmt = cacheDb.prepare(`
    SELECT *
    FROM plex_library_cache_tracks
    WHERE cache_key = ? AND grandparent_rating_key = ?
    ORDER BY sort_key ASC, parent_index ASC, track_index ASC, rating_key ASC
  `);
  const selectTracksByGrandparentTitleStmt = cacheDb.prepare(`
    SELECT *
    FROM plex_library_cache_tracks
    WHERE cache_key = ? AND lower(grandparent_title) = lower(?)
    ORDER BY sort_key ASC, parent_index ASC, track_index ASC, rating_key ASC
  `);
  const selectTracksByParentRatingKeyStmt = cacheDb.prepare(`
    SELECT *
    FROM plex_library_cache_tracks
    WHERE cache_key = ? AND parent_rating_key = ?
    ORDER BY sort_key ASC, parent_index ASC, track_index ASC, rating_key ASC
  `);
  const selectTracksByGenreStmt = cacheDb.prepare(`
    SELECT t.*
    FROM plex_library_cache_tracks t
    INNER JOIN plex_library_cache_track_genres g
      ON g.cache_key = t.cache_key
     AND g.track_rating_key = t.rating_key
    WHERE t.cache_key = @cache_key
      AND lower(g.genre_name) = lower(@genre)
    ORDER BY
      lower(COALESCE(t.grandparent_title, '')) ASC,
      lower(COALESCE(t.parent_title, '')) ASC,
      COALESCE(t.parent_index, 1) ASC,
      COALESCE(t.track_index, 0) ASC,
      lower(COALESCE(t.title, '')) ASC,
      t.rating_key ASC
    LIMIT @limit OFFSET @offset
  `);
  const selectArtistsPageByQueryStmt = cacheDb.prepare(`
    SELECT *
    FROM plex_library_cache_artists
    WHERE cache_key = @cache_key
      AND (
        @query = '' OR
        lower(COALESCE(title, '')) LIKE @pattern OR
        lower(COALESCE(title_sort, '')) LIKE @pattern
      )
    ORDER BY sort_key ASC, rating_key ASC
    LIMIT @limit OFFSET @offset
  `);
  const selectAlbumsPageByQueryStmt = cacheDb.prepare(`
    SELECT *
    FROM plex_library_cache_albums
    WHERE cache_key = @cache_key
      AND (
        @query = '' OR
        lower(COALESCE(title, '')) LIKE @pattern OR
        lower(COALESCE(parent_title, '')) LIKE @pattern OR
        lower(COALESCE(original_title, '')) LIKE @pattern
      )
    ORDER BY sort_key ASC, rating_key ASC
    LIMIT @limit OFFSET @offset
  `);
  const selectTracksPageByQueryStmt = cacheDb.prepare(`
    SELECT t.*
    FROM plex_library_cache_tracks t
    WHERE t.cache_key = @cache_key
      AND (
        @query = '' OR
        lower(COALESCE(t.title, '')) LIKE @pattern OR
        lower(COALESCE(t.parent_title, '')) LIKE @pattern OR
        lower(COALESCE(t.grandparent_title, '')) LIKE @pattern OR
        EXISTS (
          SELECT 1
          FROM plex_library_cache_track_artists ta
          WHERE ta.cache_key = t.cache_key
            AND ta.track_rating_key = t.rating_key
            AND lower(COALESCE(ta.artist_name, '')) LIKE @pattern
        )
      )
    ORDER BY
      lower(COALESCE(t.grandparent_title, '')) ASC,
      lower(COALESCE(t.parent_title, '')) ASC,
      COALESCE(t.parent_index, 1) ASC,
      COALESCE(t.track_index, 0) ASC,
      lower(COALESCE(t.title, '')) ASC,
      t.rating_key ASC
    LIMIT @limit OFFSET @offset
  `);
  const countArtistsByQueryStmt = cacheDb.prepare(`
    SELECT COUNT(1) AS total
    FROM plex_library_cache_artists
    WHERE cache_key = @cache_key
      AND (
        @query = '' OR
        lower(COALESCE(title, '')) LIKE @pattern OR
        lower(COALESCE(title_sort, '')) LIKE @pattern
      )
  `);
  const countAlbumsByQueryStmt = cacheDb.prepare(`
    SELECT COUNT(1) AS total
    FROM plex_library_cache_albums
    WHERE cache_key = @cache_key
      AND (
        @query = '' OR
        lower(COALESCE(title, '')) LIKE @pattern OR
        lower(COALESCE(parent_title, '')) LIKE @pattern OR
        lower(COALESCE(original_title, '')) LIKE @pattern
      )
  `);
  const countTracksByQueryStmt = cacheDb.prepare(`
    SELECT COUNT(1) AS total
    FROM plex_library_cache_tracks t
    WHERE t.cache_key = @cache_key
      AND (
        @query = '' OR
        lower(COALESCE(t.title, '')) LIKE @pattern OR
        lower(COALESCE(t.parent_title, '')) LIKE @pattern OR
        lower(COALESCE(t.grandparent_title, '')) LIKE @pattern OR
        EXISTS (
          SELECT 1
          FROM plex_library_cache_track_artists ta
          WHERE ta.cache_key = t.cache_key
            AND ta.track_rating_key = t.rating_key
            AND lower(COALESCE(ta.artist_name, '')) LIKE @pattern
        )
      )
  `);
  const countTracksByGenreStmt = cacheDb.prepare(`
    SELECT COUNT(DISTINCT t.rating_key) AS total
    FROM plex_library_cache_tracks t
    INNER JOIN plex_library_cache_track_genres g
      ON g.cache_key = t.cache_key
     AND g.track_rating_key = t.rating_key
    WHERE t.cache_key = @cache_key
      AND lower(g.genre_name) = lower(@genre)
  `);
  const selectGenreSummaryRowsStmt = cacheDb.prepare(`
    SELECT
      MIN(g.genre_name) AS genre_name,
      COUNT(DISTINCT t.rating_key) AS song_count,
      COUNT(DISTINCT t.parent_rating_key) AS album_count
    FROM plex_library_cache_track_genres g
    INNER JOIN plex_library_cache_tracks t
      ON t.cache_key = g.cache_key
     AND t.rating_key = g.track_rating_key
    WHERE g.cache_key = ?
    GROUP BY lower(g.genre_name)
    ORDER BY lower(MIN(g.genre_name)) ASC
  `);
  const selectAlbumsAlphabeticalByNameStmt = cacheDb.prepare(`
    SELECT *
    FROM plex_library_cache_albums
    WHERE cache_key = @cache_key
    ORDER BY sort_key ASC, rating_key ASC
    LIMIT @limit OFFSET @offset
  `);
  const countAlbumsAlphabeticalByNameStmt = cacheDb.prepare(`
    SELECT COUNT(1) AS total
    FROM plex_library_cache_albums
    WHERE cache_key = @cache_key
  `);
  const selectAlbumsAlphabeticalByArtistStmt = cacheDb.prepare(`
    SELECT *
    FROM plex_library_cache_albums
    WHERE cache_key = @cache_key
    ORDER BY lower(COALESCE(parent_title, '')) ASC, sort_key ASC, rating_key ASC
    LIMIT @limit OFFSET @offset
  `);
  const countAlbumsAlphabeticalByArtistStmt = cacheDb.prepare(`
    SELECT COUNT(1) AS total
    FROM plex_library_cache_albums
    WHERE cache_key = @cache_key
  `);
  const selectAlbumsNewestStmt = cacheDb.prepare(`
    SELECT *
    FROM plex_library_cache_albums
    WHERE cache_key = @cache_key
    ORDER BY COALESCE(added_at, 0) DESC, sort_key ASC, rating_key ASC
    LIMIT @limit OFFSET @offset
  `);
  const countAlbumsNewestStmt = cacheDb.prepare(`
    SELECT COUNT(1) AS total
    FROM plex_library_cache_albums
    WHERE cache_key = @cache_key
  `);
  const selectAlbumsHighestStmt = cacheDb.prepare(`
    SELECT *
    FROM plex_library_cache_albums
    WHERE cache_key = @cache_key
      AND COALESCE(user_rating, 0) > 0
    ORDER BY COALESCE(user_rating, 0) DESC, COALESCE(updated_at, added_at, 0) DESC, sort_key ASC, rating_key ASC
    LIMIT @limit OFFSET @offset
  `);
  const countAlbumsHighestStmt = cacheDb.prepare(`
    SELECT COUNT(1) AS total
    FROM plex_library_cache_albums
    WHERE cache_key = @cache_key
      AND COALESCE(user_rating, 0) > 0
  `);
  const selectAlbumsFrequentStmt = cacheDb.prepare(`
    SELECT *
    FROM plex_library_cache_albums
    WHERE cache_key = @cache_key
      AND COALESCE(play_count, 0) > 0
    ORDER BY COALESCE(play_count, 0) DESC, COALESCE(last_viewed_at, updated_at, added_at, 0) DESC, sort_key ASC, rating_key ASC
    LIMIT @limit OFFSET @offset
  `);
  const countAlbumsFrequentStmt = cacheDb.prepare(`
    SELECT COUNT(1) AS total
    FROM plex_library_cache_albums
    WHERE cache_key = @cache_key
      AND COALESCE(play_count, 0) > 0
  `);
  const selectAlbumsRecentStmt = cacheDb.prepare(`
    SELECT *
    FROM plex_library_cache_albums
    WHERE cache_key = @cache_key
      AND COALESCE(last_viewed_at, 0) > 0
    ORDER BY COALESCE(last_viewed_at, 0) DESC, sort_key ASC, rating_key ASC
    LIMIT @limit OFFSET @offset
  `);
  const countAlbumsRecentStmt = cacheDb.prepare(`
    SELECT COUNT(1) AS total
    FROM plex_library_cache_albums
    WHERE cache_key = @cache_key
      AND COALESCE(last_viewed_at, 0) > 0
  `);
  const selectAlbumsStarredStmt = cacheDb.prepare(`
    SELECT *
    FROM plex_library_cache_albums
    WHERE cache_key = @cache_key
      AND user_rating IS NOT NULL
      AND CAST(user_rating AS INTEGER) >= 2
      AND (CAST(user_rating AS INTEGER) % 2) = 0
    ORDER BY COALESCE(updated_at, added_at, 0) DESC, sort_key ASC, rating_key ASC
    LIMIT @limit OFFSET @offset
  `);
  const countAlbumsStarredStmt = cacheDb.prepare(`
    SELECT COUNT(1) AS total
    FROM plex_library_cache_albums
    WHERE cache_key = @cache_key
      AND user_rating IS NOT NULL
      AND CAST(user_rating AS INTEGER) >= 2
      AND (CAST(user_rating AS INTEGER) % 2) = 0
  `);
  const selectAlbumsByYearAscStmt = cacheDb.prepare(`
    SELECT *
    FROM plex_library_cache_albums
    WHERE cache_key = @cache_key
      AND year >= @year_low
      AND year <= @year_high
    ORDER BY year ASC, sort_key ASC, rating_key ASC
    LIMIT @limit OFFSET @offset
  `);
  const selectAlbumsByYearDescStmt = cacheDb.prepare(`
    SELECT *
    FROM plex_library_cache_albums
    WHERE cache_key = @cache_key
      AND year >= @year_low
      AND year <= @year_high
    ORDER BY year DESC, sort_key ASC, rating_key ASC
    LIMIT @limit OFFSET @offset
  `);
  const countAlbumsByYearStmt = cacheDb.prepare(`
    SELECT COUNT(1) AS total
    FROM plex_library_cache_albums
    WHERE cache_key = @cache_key
      AND year >= @year_low
      AND year <= @year_high
  `);
  const selectAlbumsByGenreStmt = cacheDb.prepare(`
    SELECT a.*
    FROM plex_library_cache_albums a
    WHERE a.cache_key = @cache_key
      AND EXISTS (
        SELECT 1
        FROM plex_library_cache_album_genres g
        WHERE g.cache_key = a.cache_key
          AND g.album_rating_key = a.rating_key
          AND lower(g.genre_name) = lower(@genre)
      )
    ORDER BY a.sort_key ASC, a.rating_key ASC
    LIMIT @limit OFFSET @offset
  `);
  const countAlbumsByGenreStmt = cacheDb.prepare(`
    SELECT COUNT(1) AS total
    FROM plex_library_cache_albums a
    WHERE a.cache_key = @cache_key
      AND EXISTS (
        SELECT 1
        FROM plex_library_cache_album_genres g
        WHERE g.cache_key = a.cache_key
          AND g.album_rating_key = a.rating_key
          AND lower(g.genre_name) = lower(@genre)
      )
  `);
  const selectAlbumsRandomStmt = cacheDb.prepare(`
    SELECT *
    FROM plex_library_cache_albums
    WHERE cache_key = @cache_key
    ORDER BY random()
    LIMIT @limit OFFSET @offset
  `);
  const countAlbumsRandomStmt = cacheDb.prepare(`
    SELECT COUNT(1) AS total
    FROM plex_library_cache_albums
    WHERE cache_key = @cache_key
  `);
  const deleteLibraryCacheArtistsStmt = cacheDb.prepare(`
    DELETE FROM plex_library_cache_artists
    WHERE cache_key = ?
  `);
  const deleteLibraryCacheAlbumsStmt = cacheDb.prepare(`
    DELETE FROM plex_library_cache_albums
    WHERE cache_key = ?
  `);
  const deleteLibraryCacheAlbumGenresStmt = cacheDb.prepare(`
    DELETE FROM plex_library_cache_album_genres
    WHERE cache_key = ?
  `);
  const deleteLibraryCacheTracksStmt = cacheDb.prepare(`
    DELETE FROM plex_library_cache_tracks
    WHERE cache_key = ?
  `);
  const deleteLibraryCacheTrackGenresStmt = cacheDb.prepare(`
    DELETE FROM plex_library_cache_track_genres
    WHERE cache_key = ?
  `);
  const deleteLibraryCacheTrackArtistsStmt = cacheDb.prepare(`
    DELETE FROM plex_library_cache_track_artists
    WHERE cache_key = ?
  `);
  const deleteLibraryCacheTrackAlbumArtistsStmt = cacheDb.prepare(`
    DELETE FROM plex_library_cache_track_album_artists
    WHERE cache_key = ?
  `);
  const insertLibraryCacheArtistStmt = cacheDb.prepare(`
    INSERT INTO plex_library_cache_artists (
      cache_key,
      rating_key,
      order_index,
      sort_key,
      title,
      title_sort,
      summary,
      thumb,
      key_path,
      guid,
      source_uri,
      added_at,
      updated_at,
      user_rating,
      child_count,
      leaf_count,
      album_count,
      type,
      updated_cache_at
    )
    VALUES (
      @cache_key,
      @rating_key,
      @order_index,
      @sort_key,
      @title,
      @title_sort,
      @summary,
      @thumb,
      @key_path,
      @guid,
      @source_uri,
      @added_at,
      @updated_at,
      @user_rating,
      @child_count,
      @leaf_count,
      @album_count,
      @type,
      @updated_cache_at
    )
  `);
  const insertLibraryCacheAlbumStmt = cacheDb.prepare(`
    INSERT INTO plex_library_cache_albums (
      cache_key,
      rating_key,
      order_index,
      sort_key,
      title,
      title_sort,
      original_title,
      parent_rating_key,
      parent_title,
      thumb,
      key_path,
      guid,
      source_uri,
      added_at,
      updated_at,
      last_viewed_at,
      user_rating,
      play_count,
      child_count,
      leaf_count,
      duration,
      year,
      type,
      updated_cache_at
    )
    VALUES (
      @cache_key,
      @rating_key,
      @order_index,
      @sort_key,
      @title,
      @title_sort,
      @original_title,
      @parent_rating_key,
      @parent_title,
      @thumb,
      @key_path,
      @guid,
      @source_uri,
      @added_at,
      @updated_at,
      @last_viewed_at,
      @user_rating,
      @play_count,
      @child_count,
      @leaf_count,
      @duration,
      @year,
      @type,
      @updated_cache_at
    )
  `);
  const insertLibraryCacheAlbumGenreStmt = cacheDb.prepare(`
    INSERT INTO plex_library_cache_album_genres (
      cache_key,
      album_rating_key,
      order_index,
      genre_name
    )
    VALUES (
      @cache_key,
      @album_rating_key,
      @order_index,
      @genre_name
    )
  `);
  const insertLibraryCacheTrackStmt = cacheDb.prepare(`
    INSERT INTO plex_library_cache_tracks (
      cache_key,
      rating_key,
      order_index,
      sort_key,
      title,
      title_sort,
      original_title,
      parent_rating_key,
      parent_title,
      grandparent_rating_key,
      grandparent_title,
      artist_id,
      key_path,
      guid,
      source_uri,
      thumb,
      added_at,
      updated_at,
      last_viewed_at,
      user_rating,
      view_count,
      duration,
      track_index,
      parent_index,
      disc_number,
      parent_year,
      year,
      media_bitrate,
      media_container,
      part_size,
      part_file,
      audio_sampling_rate,
      audio_bit_depth,
      audio_stream_language,
      composer,
      country,
      style,
      mood,
      record_label,
      language,
      album_type,
      is_compilation,
      is_soundtrack,
      type,
      updated_cache_at
    )
    VALUES (
      @cache_key,
      @rating_key,
      @order_index,
      @sort_key,
      @title,
      @title_sort,
      @original_title,
      @parent_rating_key,
      @parent_title,
      @grandparent_rating_key,
      @grandparent_title,
      @artist_id,
      @key_path,
      @guid,
      @source_uri,
      @thumb,
      @added_at,
      @updated_at,
      @last_viewed_at,
      @user_rating,
      @view_count,
      @duration,
      @track_index,
      @parent_index,
      @disc_number,
      @parent_year,
      @year,
      @media_bitrate,
      @media_container,
      @part_size,
      @part_file,
      @audio_sampling_rate,
      @audio_bit_depth,
      @audio_stream_language,
      @composer,
      @country,
      @style,
      @mood,
      @record_label,
      @language,
      @album_type,
      @is_compilation,
      @is_soundtrack,
      @type,
      @updated_cache_at
    )
  `);
  const insertLibraryCacheTrackGenreStmt = cacheDb.prepare(`
    INSERT INTO plex_library_cache_track_genres (
      cache_key,
      track_rating_key,
      order_index,
      genre_name
    )
    VALUES (
      @cache_key,
      @track_rating_key,
      @order_index,
      @genre_name
    )
  `);
  const insertLibraryCacheTrackArtistStmt = cacheDb.prepare(`
    INSERT INTO plex_library_cache_track_artists (
      cache_key,
      track_rating_key,
      order_index,
      artist_id,
      artist_name
    )
    VALUES (
      @cache_key,
      @track_rating_key,
      @order_index,
      @artist_id,
      @artist_name
    )
  `);
  const insertLibraryCacheTrackAlbumArtistStmt = cacheDb.prepare(`
    INSERT INTO plex_library_cache_track_album_artists (
      cache_key,
      track_rating_key,
      order_index,
      artist_id,
      artist_name
    )
    VALUES (
      @cache_key,
      @track_rating_key,
      @order_index,
      @artist_id,
      @artist_name
    )
  `);
  const selectDistinctCacheKeysByRatingKeyStmt = cacheDb.prepare(`
    SELECT DISTINCT cache_key
    FROM (
      SELECT cache_key FROM plex_library_cache_tracks WHERE rating_key = ?
      UNION ALL
      SELECT cache_key FROM plex_library_cache_albums WHERE rating_key = ?
      UNION ALL
      SELECT cache_key FROM plex_library_cache_artists WHERE rating_key = ?
    )
  `);
  const selectCachedItemRatingStmt = cacheDb.prepare(`
    SELECT user_rating, updated_at
    FROM (
      SELECT user_rating, updated_at, 0 AS priority
      FROM plex_library_cache_tracks
      WHERE cache_key = @cache_key AND rating_key = @rating_key
      UNION ALL
      SELECT user_rating, updated_at, 1 AS priority
      FROM plex_library_cache_albums
      WHERE cache_key = @cache_key AND rating_key = @rating_key
      UNION ALL
      SELECT user_rating, updated_at, 2 AS priority
      FROM plex_library_cache_artists
      WHERE cache_key = @cache_key AND rating_key = @rating_key
    )
    ORDER BY priority ASC
    LIMIT 1
  `);
  const updateArtistRatingStmt = cacheDb.prepare(`
    UPDATE plex_library_cache_artists
    SET user_rating = @user_rating,
        updated_at = @updated_at,
        updated_cache_at = @updated_cache_at
    WHERE cache_key = @cache_key
      AND rating_key = @rating_key
  `);
  const updateAlbumRatingStmt = cacheDb.prepare(`
    UPDATE plex_library_cache_albums
    SET user_rating = @user_rating,
        updated_at = @updated_at,
        updated_cache_at = @updated_cache_at
    WHERE cache_key = @cache_key
      AND rating_key = @rating_key
  `);
  const updateTrackRatingStmt = cacheDb.prepare(`
    UPDATE plex_library_cache_tracks
    SET user_rating = @user_rating,
        updated_at = @updated_at,
        updated_cache_at = @updated_cache_at
    WHERE cache_key = @cache_key
      AND rating_key = @rating_key
  `);
  const markLibraryCacheDirtyByKeyStmt = cacheDb.prepare(`
    INSERT INTO plex_library_cache_state (
      cache_key,
      last_fingerprint,
      last_checked_at,
      last_synced_at,
      dirty,
      updated_at
    )
    VALUES (
      @cache_key,
      '',
      0,
      0,
      1,
      @updated_at
    )
    ON CONFLICT(cache_key)
    DO UPDATE SET
      last_synced_at = 0,
      dirty = 1,
      updated_at = excluded.updated_at
  `);
  const markAllLibraryCachesDirtyStmt = cacheDb.prepare(`
    UPDATE plex_library_cache_state
    SET last_synced_at = 0,
        dirty = 1,
        updated_at = @updated_at
  `);
  const ensureStateRowsForCacheItemsStmt = cacheDb.prepare(`
    INSERT INTO plex_library_cache_state (
      cache_key,
      last_fingerprint,
      last_checked_at,
      last_synced_at,
      dirty,
      updated_at
    )
    SELECT DISTINCT cache_key, '', 0, 0, 1, @updated_at
    FROM (
      SELECT cache_key FROM plex_library_cache_artists
      UNION
      SELECT cache_key FROM plex_library_cache_albums
      UNION
      SELECT cache_key FROM plex_library_cache_tracks
    )
    WHERE 1
    ON CONFLICT(cache_key)
    DO UPDATE SET
      last_synced_at = 0,
      dirty = 1,
      updated_at = excluded.updated_at
  `);
  const replaceArtistCacheTx = cacheDb.transaction((cacheKey, rows, nowSeconds) => {
    deleteLibraryCacheArtistsStmt.run(cacheKey);
    for (const row of rows) {
      insertLibraryCacheArtistStmt.run(row);
    }
    const currentState = getLibraryCacheStateStmt.get(cacheKey);
    upsertLibraryCacheStateStmt.run({
      cache_key: cacheKey,
      last_fingerprint: String(currentState?.last_fingerprint || ''),
      last_checked_at: Number(currentState?.last_checked_at || 0),
      last_synced_at: nowSeconds,
      dirty: Number(currentState?.dirty || 0) ? 1 : 0,
      updated_at: nowSeconds,
    });
  });
  const replaceAlbumCacheTx = cacheDb.transaction((cacheKey, albumRows, genreRows, nowSeconds) => {
    deleteLibraryCacheAlbumGenresStmt.run(cacheKey);
    deleteLibraryCacheAlbumsStmt.run(cacheKey);
    for (const row of albumRows) {
      insertLibraryCacheAlbumStmt.run(row);
    }
    for (const row of genreRows) {
      insertLibraryCacheAlbumGenreStmt.run(row);
    }
    const currentState = getLibraryCacheStateStmt.get(cacheKey);
    upsertLibraryCacheStateStmt.run({
      cache_key: cacheKey,
      last_fingerprint: String(currentState?.last_fingerprint || ''),
      last_checked_at: Number(currentState?.last_checked_at || 0),
      last_synced_at: nowSeconds,
      dirty: Number(currentState?.dirty || 0) ? 1 : 0,
      updated_at: nowSeconds,
    });
  });
  const replaceTrackCacheTx = cacheDb.transaction((cacheKey, trackRows, genreRows, artistRows, albumArtistRows, nowSeconds) => {
    deleteLibraryCacheTrackAlbumArtistsStmt.run(cacheKey);
    deleteLibraryCacheTrackArtistsStmt.run(cacheKey);
    deleteLibraryCacheTrackGenresStmt.run(cacheKey);
    deleteLibraryCacheTracksStmt.run(cacheKey);
    for (const row of trackRows) {
      insertLibraryCacheTrackStmt.run(row);
    }
    for (const row of genreRows) {
      insertLibraryCacheTrackGenreStmt.run(row);
    }
    for (const row of artistRows) {
      insertLibraryCacheTrackArtistStmt.run(row);
    }
    for (const row of albumArtistRows) {
      insertLibraryCacheTrackAlbumArtistStmt.run(row);
    }
    const currentState = getLibraryCacheStateStmt.get(cacheKey);
    upsertLibraryCacheStateStmt.run({
      cache_key: cacheKey,
      last_fingerprint: String(currentState?.last_fingerprint || ''),
      last_checked_at: Number(currentState?.last_checked_at || 0),
      last_synced_at: nowSeconds,
      dirty: Number(currentState?.dirty || 0) ? 1 : 0,
      updated_at: nowSeconds,
    });
  });

  function resolvePlexAccountCacheScope(accountId, plexState) {
    const normalizedAccountId = String(accountId || '').trim();
    let accountToken = '';

    if (normalizedAccountId) {
      const context = repo.getAccountPlexContext(normalizedAccountId);
      if (context?.plex_token_enc) {
        try {
          accountToken = String(decodePlexTokenOrThrow(tokenCipher, context.plex_token_enc) || '').trim();
        } catch { }
      }
    }

    if (!accountToken) {
      const tokenCandidates = Array.isArray(plexState?.plexToken)
        ? plexState.plexToken
        : [];
      accountToken = String(
        tokenCandidates[tokenCandidates.length - 1] ||
        tokenCandidates[0] ||
        '',
      ).trim();
    }

    if (accountToken) {
      return `plex-${md5HexUtf8(accountToken)}`;
    }
    if (normalizedAccountId) {
      return `local-${normalizedAccountId}`;
    }
    return 'local-unknown';
  }

  function searchBrowseCacheKey(accountId, plexState) {
    const accountScope = resolvePlexAccountCacheScope(accountId, plexState);
    return `${accountScope}:${plexState.machineId}:${plexState.musicSectionId}`;
  }

  function emptyLibraryCacheState() {
    return {
      lastFingerprint: '',
      lastCheckedAt: 0,
      lastSyncedAt: 0,
      dirty: false,
    };
  }

  function getPersistedLibraryCacheState(cacheKey) {
    const row = getLibraryCacheStateStmt.get(cacheKey);
    if (!row) {
      return {
        cacheKey,
        ...emptyLibraryCacheState(),
      };
    }
    return {
      cacheKey,
      lastFingerprint: String(row.last_fingerprint || ''),
      lastCheckedAt: Number(row.last_checked_at || 0),
      lastSyncedAt: Number(row.last_synced_at || 0),
      dirty: Number(row.dirty || 0) === 1,
    };
  }

  function persistLibraryCacheState(cacheKey, state, nowSeconds = Math.floor(Date.now() / 1000)) {
    const source = state || emptyLibraryCacheState();
    upsertLibraryCacheStateStmt.run({
      cache_key: cacheKey,
      last_fingerprint: String(source.lastFingerprint || ''),
      last_checked_at: Number(source.lastCheckedAt || 0),
      last_synced_at: Number(source.lastSyncedAt || 0),
      dirty: source.dirty ? 1 : 0,
      updated_at: nowSeconds,
    });
  }

  function buildArtistCacheRows(cacheKey, artists, nowSeconds) {
    const rows = [];
    for (let i = 0; i < artists.length; i += 1) {
      const artist = artists[i];
      const ratingKey = String(artist?.ratingKey || '').trim();
      if (!ratingKey) {
        continue;
      }
      rows.push({
        cache_key: cacheKey,
        rating_key: ratingKey,
        order_index: i,
        sort_key: safeLower(artist?.title || artist?.name || ratingKey),
        title: firstNonEmptyText([artist?.title, artist?.name], null),
        title_sort: firstNonEmptyText([artist?.titleSort], null),
        summary: firstNonEmptyText([artist?.summary], null),
        thumb: firstNonEmptyText([artist?.thumb], null),
        key_path: firstNonEmptyText([artist?.key], null),
        guid: firstNonEmptyText([artist?.guid], null),
        source_uri: firstNonEmptyText([artist?.sourceUri, artist?.sourceURI], null),
        added_at: parseNonNegativeInt(artist?.addedAt, null),
        updated_at: parseNonNegativeInt(artist?.updatedAt, null),
        user_rating: normalizePlexRating(artist?.userRating),
        child_count: parseNonNegativeInt(artist?.childCount, null),
        leaf_count: parseNonNegativeInt(artist?.leafCount, null),
        album_count: parseNonNegativeInt(artist?.albumCount, null),
        type: firstNonEmptyText([artist?.type], 'artist'),
        updated_cache_at: nowSeconds,
      });
    }
    return rows;
  }

  function buildAlbumCachePayload(cacheKey, albums, nowSeconds) {
    const albumRows = [];
    const genreRows = [];
    for (let i = 0; i < albums.length; i += 1) {
      const album = albums[i];
      const ratingKey = String(album?.ratingKey || '').trim();
      if (!ratingKey) {
        continue;
      }
      albumRows.push({
        cache_key: cacheKey,
        rating_key: ratingKey,
        order_index: i,
        sort_key: safeLower(album?.title || album?.name || ratingKey),
        title: firstNonEmptyText([album?.title, album?.name], null),
        title_sort: firstNonEmptyText([album?.titleSort], null),
        original_title: firstNonEmptyText([album?.originalTitle], null),
        parent_rating_key: firstNonEmptyText([album?.parentRatingKey], null),
        parent_title: firstNonEmptyText([album?.parentTitle], null),
        thumb: firstNonEmptyText([album?.thumb], null),
        key_path: firstNonEmptyText([album?.key], null),
        guid: firstNonEmptyText([album?.guid], null),
        source_uri: firstNonEmptyText([album?.sourceUri, album?.sourceURI], null),
        added_at: parseNonNegativeInt(album?.addedAt, null),
        updated_at: parseNonNegativeInt(album?.updatedAt, null),
        last_viewed_at: parseNonNegativeInt(album?.lastViewedAt, null),
        user_rating: normalizePlexRating(album?.userRating),
        play_count: parseNonNegativeInt(album?.viewCount ?? album?.playCount, null),
        child_count: parseNonNegativeInt(album?.childCount, null),
        leaf_count: parseNonNegativeInt(album?.leafCount, null),
        duration: parseNonNegativeInt(album?.duration, null),
        year: parsePositiveInt(album?.year, null),
        type: firstNonEmptyText([album?.type], 'album'),
        updated_cache_at: nowSeconds,
      });
      const genres = allGenreTags(album);
      for (let g = 0; g < genres.length; g += 1) {
        genreRows.push({
          cache_key: cacheKey,
          album_rating_key: ratingKey,
          order_index: g,
          genre_name: genres[g],
        });
      }
    }
    return { albumRows, genreRows };
  }

  function buildTrackCachePayload(cacheKey, tracks, nowSeconds) {
    const trackRows = [];
    const genreRows = [];
    const artistRows = [];
    const albumArtistRows = [];
    for (let i = 0; i < tracks.length; i += 1) {
      const track = tracks[i];
      const ratingKey = String(track?.ratingKey || '').trim();
      if (!ratingKey) {
        continue;
      }
      const media = mediaFromTrack(track);
      const part = partFromTrack(track);
      const audioStream = audioStreamFromTrack(track);
      const composer = metadataFieldText(
        [track],
        ['Composer', 'composer', 'Composers', 'composers', 'Writer', 'writer'],
      );
      const country = metadataFieldText([track], ['Country', 'country']);
      const style = metadataFieldText([track], ['Style', 'style']);
      const mood = metadataFieldText([track], ['Mood', 'mood']);
      const recordLabel = metadataFieldText(
        [track],
        ['RecordLabel', 'recordLabel', 'recordlabel', 'Label', 'label', 'Studio', 'studio'],
      );
      const language = metadataFieldText([track], ['Language', 'language', 'Lang', 'lang']);
      const albumType = metadataFieldText(
        [track],
        ['albumType', 'AlbumType', 'subtype', 'subType', 'parentSubtype', 'format'],
      );
      const compilationValues = metadataFieldValues(
        [track],
        ['Compilation', 'compilation', 'isCompilation', 'iscompilation'],
      );
      const soundtrackValues = metadataFieldValues(
        [track],
        ['Soundtrack', 'soundtrack', 'isSoundtrack', 'issoundtrack'],
      );
      trackRows.push({
        cache_key: cacheKey,
        rating_key: ratingKey,
        order_index: i,
        sort_key: safeLower(track?.title || track?.name || ratingKey),
        title: firstNonEmptyText([track?.title, track?.name], null),
        title_sort: firstNonEmptyText([track?.titleSort], null),
        original_title: firstNonEmptyText([track?.originalTitle], null),
        parent_rating_key: firstNonEmptyText([track?.parentRatingKey], null),
        parent_title: firstNonEmptyText([track?.parentTitle], null),
        grandparent_rating_key: firstNonEmptyText([track?.grandparentRatingKey], null),
        grandparent_title: firstNonEmptyText([track?.grandparentTitle], null),
        artist_id: firstNonEmptyText([track?.artistId], null),
        key_path: firstNonEmptyText([track?.key], null),
        guid: firstNonEmptyText([track?.guid], null),
        source_uri: firstNonEmptyText([track?.sourceUri, track?.sourceURI], null),
        thumb: firstNonEmptyText([track?.thumb], null),
        added_at: parseNonNegativeInt(track?.addedAt, null),
        updated_at: parseNonNegativeInt(track?.updatedAt, null),
        last_viewed_at: parseNonNegativeInt(track?.lastViewedAt, null),
        user_rating: normalizePlexRating(track?.userRating),
        view_count: parseNonNegativeInt(track?.viewCount, null),
        duration: parseNonNegativeInt(track?.duration, null),
        track_index: parsePositiveInt(track?.index, null),
        parent_index: parsePositiveInt(track?.parentIndex, null),
        disc_number: parsePositiveInt(track?.discNumber, null),
        parent_year: parsePositiveInt(track?.parentYear, null),
        year: parsePositiveInt(track?.year, null),
        media_bitrate: parseNonNegativeInt(media?.bitrate, null),
        media_container: firstNonEmptyText([media?.container], null),
        part_size: parseNonNegativeInt(part?.size, null),
        part_file: firstNonEmptyText([part?.file], null),
        audio_sampling_rate: parsePositiveInt(
          audioStream?.samplingRate ?? audioStream?.sampleRate ?? audioStream?.audioSamplingRate,
          null,
        ),
        audio_bit_depth: parsePositiveInt(audioStream?.bitDepth ?? audioStream?.bitsPerSample, null),
        audio_stream_language: firstNonEmptyText(
          [audioStream?.languageTag, audioStream?.languageCode, audioStream?.language],
          null,
        ),
        composer,
        country,
        style,
        mood,
        record_label: recordLabel,
        language,
        album_type: albumType,
        is_compilation: compilationValues.length > 0 ? (parseBooleanLike(compilationValues[0], false) ? 1 : 0) : null,
        is_soundtrack: soundtrackValues.length > 0 ? (parseBooleanLike(soundtrackValues[0], false) ? 1 : 0) : null,
        type: firstNonEmptyText([track?.type], 'track'),
        updated_cache_at: nowSeconds,
      });
      const genres = allGenreTags(track);
      for (let g = 0; g < genres.length; g += 1) {
        genreRows.push({
          cache_key: cacheKey,
          track_rating_key: ratingKey,
          order_index: g,
          genre_name: genres[g],
        });
      }
      const trackArtists = trackArtistEntries(track);
      for (let a = 0; a < trackArtists.length; a += 1) {
        artistRows.push({
          cache_key: cacheKey,
          track_rating_key: ratingKey,
          order_index: a,
          artist_id: firstNonEmptyText([trackArtists[a]?.id], null),
          artist_name: firstNonEmptyText([trackArtists[a]?.name], ''),
        });
      }
      const trackAlbumArtists = trackAlbumArtistEntries(track);
      for (let a = 0; a < trackAlbumArtists.length; a += 1) {
        albumArtistRows.push({
          cache_key: cacheKey,
          track_rating_key: ratingKey,
          order_index: a,
          artist_id: firstNonEmptyText([trackAlbumArtists[a]?.id], null),
          artist_name: firstNonEmptyText([trackAlbumArtists[a]?.name], ''),
        });
      }
    }
    return { trackRows, genreRows, artistRows, albumArtistRows };
  }

  function hasSearchBrowseCollectionPersistedData(cacheKey) {
    return Boolean(hasLibraryCacheDataStmt.get(cacheKey, cacheKey, cacheKey));
  }

  function hasPersistedCollectionData(cacheKey, collection) {
    if (collection === 'artists') {
      return Boolean(hasLibraryCacheArtistsStmt.get(cacheKey));
    }
    if (collection === 'albums') {
      return Boolean(hasLibraryCacheAlbumsStmt.get(cacheKey));
    }
    if (collection === 'tracks') {
      return Boolean(hasLibraryCacheTracksStmt.get(cacheKey));
    }
    return false;
  }

  function artistFromCacheRow(row) {
    return {
      type: firstNonEmptyText([row?.type], 'artist'),
      ratingKey: String(row?.rating_key || ''),
      title: firstNonEmptyText([row?.title], ''),
      titleSort: firstNonEmptyText([row?.title_sort], undefined),
      summary: firstNonEmptyText([row?.summary], undefined),
      thumb: firstNonEmptyText([row?.thumb], undefined),
      key: firstNonEmptyText([row?.key_path], undefined),
      guid: firstNonEmptyText([row?.guid], undefined),
      sourceUri: firstNonEmptyText([row?.source_uri], undefined),
      sourceURI: firstNonEmptyText([row?.source_uri], undefined),
      addedAt: parseNonNegativeInt(row?.added_at, undefined),
      updatedAt: parseNonNegativeInt(row?.updated_at, undefined),
      userRating: normalizePlexRating(row?.user_rating),
      childCount: parseNonNegativeInt(row?.child_count, undefined),
      leafCount: parseNonNegativeInt(row?.leaf_count, undefined),
      albumCount: parseNonNegativeInt(row?.album_count, undefined),
    };
  }

  function albumFromCacheRow(row, genreNames = []) {
    const genres = (Array.isArray(genreNames) ? genreNames : [])
      .map((value) => String(value || '').trim())
      .filter(Boolean);
    return {
      type: firstNonEmptyText([row?.type], 'album'),
      ratingKey: String(row?.rating_key || ''),
      title: firstNonEmptyText([row?.title], ''),
      titleSort: firstNonEmptyText([row?.title_sort], undefined),
      originalTitle: firstNonEmptyText([row?.original_title], undefined),
      parentRatingKey: firstNonEmptyText([row?.parent_rating_key], undefined),
      parentTitle: firstNonEmptyText([row?.parent_title], undefined),
      thumb: firstNonEmptyText([row?.thumb], undefined),
      key: firstNonEmptyText([row?.key_path], undefined),
      guid: firstNonEmptyText([row?.guid], undefined),
      sourceUri: firstNonEmptyText([row?.source_uri], undefined),
      sourceURI: firstNonEmptyText([row?.source_uri], undefined),
      addedAt: parseNonNegativeInt(row?.added_at, undefined),
      updatedAt: parseNonNegativeInt(row?.updated_at, undefined),
      lastViewedAt: parseNonNegativeInt(row?.last_viewed_at, undefined),
      userRating: normalizePlexRating(row?.user_rating),
      viewCount: parseNonNegativeInt(row?.play_count, undefined),
      playCount: parseNonNegativeInt(row?.play_count, undefined),
      childCount: parseNonNegativeInt(row?.child_count, undefined),
      leafCount: parseNonNegativeInt(row?.leaf_count, undefined),
      duration: parseNonNegativeInt(row?.duration, undefined),
      year: parsePositiveInt(row?.year, undefined),
      Genre: genres.map((tag) => ({ tag })),
      genre: genres.length > 0 ? genres.join('; ') : undefined,
    };
  }

  function trackFromCacheRow(row, { genreNames = [], artists = [], albumArtists = [] } = {}) {
    const genres = (Array.isArray(genreNames) ? genreNames : [])
      .map((value) => String(value || '').trim())
      .filter(Boolean);
    const mediaContainer = firstNonEmptyText([row?.media_container], undefined);
    const partFile = firstNonEmptyText([row?.part_file], undefined);
    const partSize = parseNonNegativeInt(row?.part_size, undefined);
    const streamLanguage = firstNonEmptyText([row?.audio_stream_language], undefined);
    const media = (mediaContainer || partFile || partSize || row?.media_bitrate)
      ? [{
        bitrate: parseNonNegativeInt(row?.media_bitrate, undefined),
        container: mediaContainer,
        Part: [{
          size: partSize,
          file: partFile,
          Stream: [{
            streamType: 2,
            samplingRate: parsePositiveInt(row?.audio_sampling_rate, undefined),
            bitDepth: parsePositiveInt(row?.audio_bit_depth, undefined),
            language: streamLanguage,
          }],
        }],
      }]
      : undefined;
    return {
      type: firstNonEmptyText([row?.type], 'track'),
      ratingKey: String(row?.rating_key || ''),
      title: firstNonEmptyText([row?.title], ''),
      titleSort: firstNonEmptyText([row?.title_sort], undefined),
      originalTitle: firstNonEmptyText([row?.original_title], undefined),
      parentRatingKey: firstNonEmptyText([row?.parent_rating_key], undefined),
      parentTitle: firstNonEmptyText([row?.parent_title], undefined),
      grandparentRatingKey: firstNonEmptyText([row?.grandparent_rating_key], undefined),
      grandparentTitle: firstNonEmptyText([row?.grandparent_title], undefined),
      artistId: firstNonEmptyText([row?.artist_id], undefined),
      key: firstNonEmptyText([row?.key_path], undefined),
      guid: firstNonEmptyText([row?.guid], undefined),
      sourceUri: firstNonEmptyText([row?.source_uri], undefined),
      sourceURI: firstNonEmptyText([row?.source_uri], undefined),
      thumb: firstNonEmptyText([row?.thumb], undefined),
      addedAt: parseNonNegativeInt(row?.added_at, undefined),
      updatedAt: parseNonNegativeInt(row?.updated_at, undefined),
      lastViewedAt: parseNonNegativeInt(row?.last_viewed_at, undefined),
      userRating: normalizePlexRating(row?.user_rating),
      viewCount: parseNonNegativeInt(row?.view_count, undefined),
      duration: parseNonNegativeInt(row?.duration, undefined),
      index: parsePositiveInt(row?.track_index, undefined),
      parentIndex: parsePositiveInt(row?.parent_index, undefined),
      discNumber: parsePositiveInt(row?.disc_number, undefined),
      parentYear: parsePositiveInt(row?.parent_year, undefined),
      year: parsePositiveInt(row?.year, undefined),
      Media: media,
      Genre: genres.map((tag) => ({ tag })),
      genre: genres.length > 0 ? genres.join('; ') : undefined,
      artists: Array.isArray(artists) && artists.length > 0 ? artists : undefined,
      albumArtists: Array.isArray(albumArtists) && albumArtists.length > 0 ? albumArtists : undefined,
      Composer: firstNonEmptyText([row?.composer], undefined),
      composer: firstNonEmptyText([row?.composer], undefined),
      Country: firstNonEmptyText([row?.country], undefined),
      country: firstNonEmptyText([row?.country], undefined),
      Style: firstNonEmptyText([row?.style], undefined),
      style: firstNonEmptyText([row?.style], undefined),
      Mood: firstNonEmptyText([row?.mood], undefined),
      mood: firstNonEmptyText([row?.mood], undefined),
      RecordLabel: firstNonEmptyText([row?.record_label], undefined),
      recordLabel: firstNonEmptyText([row?.record_label], undefined),
      Language: firstNonEmptyText([row?.language], undefined),
      language: firstNonEmptyText([row?.language], undefined),
      albumType: firstNonEmptyText([row?.album_type], undefined),
      Compilation: row?.is_compilation == null ? undefined : Number(row.is_compilation) === 1,
      compilation: row?.is_compilation == null ? undefined : Number(row.is_compilation) === 1,
      Soundtrack: row?.is_soundtrack == null ? undefined : Number(row.is_soundtrack) === 1,
      soundtrack: row?.is_soundtrack == null ? undefined : Number(row.is_soundtrack) === 1,
    };
  }

  function trackRelationsByRatingKey(cacheKey, ratingKey) {
    const genres = selectTrackGenresByTrackStmt
      .all(cacheKey, ratingKey)
      .map((entry) => String(entry?.genre_name || '').trim())
      .filter(Boolean);
    const artists = selectTrackArtistsByTrackStmt
      .all(cacheKey, ratingKey)
      .map((entry) => ({
        id: firstNonEmptyText([entry?.artist_id], undefined),
        name: firstNonEmptyText([entry?.artist_name], ''),
      }))
      .filter((entry) => Boolean(entry.name));
    const albumArtists = selectTrackAlbumArtistsByTrackStmt
      .all(cacheKey, ratingKey)
      .map((entry) => ({
        id: firstNonEmptyText([entry?.artist_id], undefined),
        name: firstNonEmptyText([entry?.artist_name], ''),
      }))
      .filter((entry) => Boolean(entry.name));
    return { genres, artists, albumArtists };
  }

  function albumGenresByRatingKey(cacheKey, ratingKey) {
    return selectAlbumGenresByAlbumStmt
      .all(cacheKey, ratingKey)
      .map((entry) => String(entry?.genre_name || '').trim())
      .filter(Boolean);
  }

  function readSearchBrowseCollectionFromSqlite(cacheKey, collection) {
    if (collection === 'artists') {
      const rows = selectLibraryCacheArtistRowsStmt.all(cacheKey);
      if (!Array.isArray(rows) || rows.length === 0) {
        return null;
      }
      return rows.map((row) => artistFromCacheRow(row));
    }
    if (collection === 'albums') {
      const rows = selectLibraryCacheAlbumRowsStmt.all(cacheKey);
      if (!Array.isArray(rows) || rows.length === 0) {
        return null;
      }
      const genresByAlbum = new Map();
      for (const row of selectAlbumGenreRowsStmt.all(cacheKey)) {
        const albumKey = String(row?.album_rating_key || '').trim();
        const genre = String(row?.genre_name || '').trim();
        if (!albumKey || !genre) {
          continue;
        }
        const bucket = genresByAlbum.get(albumKey) || [];
        bucket.push(genre);
        genresByAlbum.set(albumKey, bucket);
      }
      return rows.map((row) => {
        const ratingKey = String(row?.rating_key || '');
        return albumFromCacheRow(row, genresByAlbum.get(ratingKey) || []);
      });
    }
    if (collection === 'tracks') {
      const rows = selectLibraryCacheTrackRowsStmt.all(cacheKey);
      if (!Array.isArray(rows) || rows.length === 0) {
        return null;
      }
      const genresByTrack = new Map();
      for (const row of selectTrackGenreRowsStmt.all(cacheKey)) {
        const trackKey = String(row?.track_rating_key || '').trim();
        const genre = String(row?.genre_name || '').trim();
        if (!trackKey || !genre) {
          continue;
        }
        const bucket = genresByTrack.get(trackKey) || [];
        bucket.push(genre);
        genresByTrack.set(trackKey, bucket);
      }
      const artistsByTrack = new Map();
      for (const row of selectTrackArtistRowsStmt.all(cacheKey)) {
        const trackKey = String(row?.track_rating_key || '').trim();
        if (!trackKey) {
          continue;
        }
        const bucket = artistsByTrack.get(trackKey) || [];
        bucket.push({
          id: firstNonEmptyText([row?.artist_id], undefined),
          name: firstNonEmptyText([row?.artist_name], ''),
        });
        artistsByTrack.set(trackKey, bucket);
      }
      const albumArtistsByTrack = new Map();
      for (const row of selectTrackAlbumArtistRowsStmt.all(cacheKey)) {
        const trackKey = String(row?.track_rating_key || '').trim();
        if (!trackKey) {
          continue;
        }
        const bucket = albumArtistsByTrack.get(trackKey) || [];
        bucket.push({
          id: firstNonEmptyText([row?.artist_id], undefined),
          name: firstNonEmptyText([row?.artist_name], ''),
        });
        albumArtistsByTrack.set(trackKey, bucket);
      }
      return rows.map((row) => {
        const ratingKey = String(row?.rating_key || '');
        return trackFromCacheRow(row, {
          genreNames: genresByTrack.get(ratingKey) || [],
          artists: artistsByTrack.get(ratingKey) || [],
          albumArtists: albumArtistsByTrack.get(ratingKey) || [],
        });
      });
    }
    return null;
  }

  async function loadSearchBrowseCollection({ cacheKey, collection, loader, request = null, background = false }) {
    if (!SEARCH_BROWSE_COLLECTIONS.includes(collection)) {
      throw new Error(`Invalid cache collection: ${collection}`);
    }

    const inFlightKey = `${cacheKey}:${collection}`;
    const existing = cacheCollectionLoadInFlight.get(inFlightKey);
    if (existing) {
      return existing;
    }

    const pending = (async () => {
      const loaded = await loader();
      return Array.isArray(loaded) ? loaded : [];
    })();
    cacheCollectionLoadInFlight.set(inFlightKey, pending);

    try {
      const loaded = await pending;
      const nowSeconds = Math.floor(Date.now() / 1000);
      if (collection === 'artists') {
        const rows = buildArtistCacheRows(cacheKey, loaded, nowSeconds);
        replaceArtistCacheTx(cacheKey, rows, nowSeconds);
      } else if (collection === 'albums') {
        const payload = buildAlbumCachePayload(cacheKey, loaded, nowSeconds);
        replaceAlbumCacheTx(cacheKey, payload.albumRows, payload.genreRows, nowSeconds);
      } else if (collection === 'tracks') {
        const payload = buildTrackCachePayload(cacheKey, loaded, nowSeconds);
        replaceTrackCacheTx(
          cacheKey,
          payload.trackRows,
          payload.genreRows,
          payload.artistRows,
          payload.albumArtistRows,
          nowSeconds,
        );
      } else {
        throw new Error(`Invalid cache collection: ${collection}`);
      }
      return loaded;
    } catch (error) {
      if (background) {
        request?.log?.debug(error, `Background refresh failed for ${collection} cache`);
        const fallback = readSearchBrowseCollectionFromSqlite(cacheKey, collection);
        if (Array.isArray(fallback)) {
          return fallback;
        }
        return [];
      }
      throw error;
    } finally {
      if (cacheCollectionLoadInFlight.get(inFlightKey) === pending) {
        cacheCollectionLoadInFlight.delete(inFlightKey);
      }
    }
  }

  async function loadLibraryArtistsRaw({ plexState }) {
    const loaded = await listArtists({
      baseUrl: plexState.baseUrl,
      plexToken: plexState.plexToken,
      sectionId: plexState.musicSectionId,
    });
    return [...loaded].sort((a, b) => String(a?.title || '').localeCompare(String(b?.title || '')));
  }

  async function loadLibraryAlbumsRaw({ plexState }) {
    const loaded = await listAlbums({
      baseUrl: plexState.baseUrl,
      plexToken: plexState.plexToken,
      sectionId: plexState.musicSectionId,
    });
    return sortAlbumsByName(loaded);
  }

  async function loadLibraryTracksRaw({ plexState }) {
    const [tracks, albums] = await Promise.all([
      listTracks({
        baseUrl: plexState.baseUrl,
        plexToken: plexState.plexToken,
        sectionId: plexState.musicSectionId,
      }),
      listAlbums({
        baseUrl: plexState.baseUrl,
        plexToken: plexState.plexToken,
        sectionId: plexState.musicSectionId,
      }),
    ]);
    const albumGenreTagMap = buildAlbumGenreTagMap(albums);
    const enrichedTracks = tracks.map((track) => withResolvedTrackGenres(track, albumGenreTagMap));
    return sortTracksForLibraryBrowse(enrichedTracks);
  }

  function getLibraryCollectionLoader(collection, plexState) {
    if (collection === 'artists') {
      return () => loadLibraryArtistsRaw({ plexState });
    }
    if (collection === 'albums') {
      return () => loadLibraryAlbumsRaw({ plexState });
    }
    if (collection === 'tracks') {
      return () => loadLibraryTracksRaw({ plexState });
    }
    throw new Error(`Unsupported library collection: ${collection}`);
  }

  function markSearchBrowseCacheDirty(cacheKey = null) {
    const nowSeconds = Math.floor(Date.now() / 1000);
    if (cacheKey) {
      markLibraryCacheDirtyByKeyStmt.run({
        cache_key: cacheKey,
        updated_at: nowSeconds,
      });
      return;
    }

    ensureStateRowsForCacheItemsStmt.run({ updated_at: nowSeconds });
    markAllLibraryCachesDirtyStmt.run({ updated_at: nowSeconds });
  }

  function applyUserRatingPatchToCacheKey(cacheKey, itemIds, { userRating = null, clearUserRating = false }, updatedAtSeconds) {
    const nextRating = clearUserRating ? 0 : userRating;
    const updatedCacheAt = Math.floor(Date.now() / 1000);
    let patchedCount = 0;
    for (const id of itemIds) {
      const params = {
        cache_key: cacheKey,
        rating_key: String(id || ''),
        user_rating: nextRating,
        updated_at: updatedAtSeconds,
        updated_cache_at: updatedCacheAt,
      };
      patchedCount += updateTrackRatingStmt.run(params).changes;
      patchedCount += updateAlbumRatingStmt.run(params).changes;
      patchedCount += updateArtistRatingStmt.run(params).changes;
    }
    return patchedCount;
  }

  function applyUserRatingPatchToSearchBrowseCache({ cacheKey = null, itemIds, userRating = null, clearUserRating = false }) {
    if (!clearUserRating && normalizePlexRating(userRating) == null) {
      return 0;
    }
    const normalizedRating = clearUserRating ? null : normalizePlexRating(userRating);

    const ids = uniqueNonEmptyValues(itemIds);
    if (ids.length === 0) {
      return 0;
    }

    const updatedAtSeconds = Math.floor(Date.now() / 1000);
    const targets = new Set();
    if (cacheKey) {
      targets.add(cacheKey);
    } else {
      for (const id of ids) {
        const rows = selectDistinctCacheKeysByRatingKeyStmt.all(id, id, id);
        for (const row of rows) {
          const key = String(row?.cache_key || '').trim();
          if (key) {
            targets.add(key);
          }
        }
      }
    }

    if (targets.size === 0) {
      return 0;
    }

    let patchedCount = 0;
    for (const targetCacheKey of targets) {
      patchedCount += applyUserRatingPatchToCacheKey(
        targetCacheKey,
        ids,
        {
          userRating: normalizedRating,
          clearUserRating,
        },
        updatedAtSeconds,
      );
    }
    return patchedCount;
  }

  function getCachedUserRatingForItem(cacheKey, itemId) {
    const key = String(itemId || '').trim();
    if (!key || !cacheKey) {
      return null;
    }

    const found = selectCachedItemRatingStmt.get({
      cache_key: cacheKey,
      rating_key: key,
    });
    if (!found || found.user_rating == null) {
      return null;
    }
    return normalizePlexRatingInt(found.user_rating);
  }

  async function getLibraryFingerprint({ plexState }) {
    const sectionId = String(plexState.musicSectionId || '');
    const [sections, probe] = await Promise.all([
      listMusicSections({
        baseUrl: plexState.baseUrl,
        plexToken: plexState.plexToken,
      }),
      probeSectionFingerprint({
        baseUrl: plexState.baseUrl,
        plexToken: plexState.plexToken,
        sectionId,
      }).catch(() => ''),
    ]);

    const section = sections.find((item) => String(item?.id || '') === sectionId);
    const sectionPart = section
      ? `${section.id}|${section.updatedAt}|${section.scannedAt}|${section.refreshedAt}|${section.contentChangedAt}|${section.leafCount}`
      : `${sectionId}|missing`;
    return `${sectionPart}|${probe || ''}`;
  }

  async function refreshSearchBrowseCollectionsForCacheKey({ cacheKey, plexState, request }) {
    for (const collection of SEARCH_BROWSE_COLLECTIONS) {
      await loadSearchBrowseCollection({
        cacheKey,
        collection,
        loader: getLibraryCollectionLoader(collection, plexState),
        request,
        background: false,
      });
    }
    const nowSeconds = Math.floor(Date.now() / 1000);
    const state = getPersistedLibraryCacheState(cacheKey);
    state.lastSyncedAt = nowSeconds;
    state.dirty = false;
    persistLibraryCacheState(cacheKey, state, nowSeconds);
  }

  async function ensureDirtySearchBrowseRefresh({
    cacheKey,
    plexState,
    request,
    wait = false,
  }) {
    const state = getPersistedLibraryCacheState(cacheKey);
    if (!state.dirty) {
      return;
    }

    let pending = cacheRefreshInFlight.get(cacheKey);
    if (!pending) {
      pending = (async () => {
        try {
          await refreshSearchBrowseCollectionsForCacheKey({ cacheKey, plexState, request });
        } catch (error) {
          request?.log?.warn(error, `Failed to refresh stale cache for ${cacheKey}`);
          throw error;
        } finally {
          if (cacheRefreshInFlight.get(cacheKey) === pending) {
            cacheRefreshInFlight.delete(cacheKey);
          }
        }
      })();
      cacheRefreshInFlight.set(cacheKey, pending);
      if (!wait) {
        return;
      }
    }

    if (wait && pending) {
      try {
        await pending;
      } catch {
        // Keep serving stale cache on refresh failures.
      }
    }
  }

  function maybeCheckLibraryChanges({ cacheKey, plexState, request }) {
    if (!request) {
      return;
    }

    const state = getPersistedLibraryCacheState(cacheKey);
    const now = Date.now();
    if (cacheChangeCheckInFlight.has(cacheKey)) {
      return;
    }
    if ((now - Number(state.lastCheckedAt || 0)) < SEARCH_BROWSE_CHANGE_CHECK_DEBOUNCE_MS) {
      return;
    }

    state.lastCheckedAt = now;
    persistLibraryCacheState(cacheKey, state, Math.floor(now / 1000));
    const pending = (async () => {
      try {
        const fingerprint = await getLibraryFingerprint({ plexState });
        if (!fingerprint) {
          return;
        }

        const latestState = getPersistedLibraryCacheState(cacheKey);
        if (!latestState.lastFingerprint) {
          latestState.lastFingerprint = fingerprint;
          persistLibraryCacheState(cacheKey, latestState);
          return;
        }

        if (latestState.lastFingerprint !== fingerprint) {
          latestState.lastFingerprint = fingerprint;
          latestState.dirty = true;
          latestState.lastSyncedAt = 0;
          persistLibraryCacheState(cacheKey, latestState);
          request.log.info({ cacheKey }, 'Plex library change detected, refreshing cache');
          await ensureDirtySearchBrowseRefresh({
            cacheKey,
            plexState,
            request,
            wait: false,
          });
        }
      } catch (error) {
        request.log.debug(error, `Failed to check library changes for ${cacheKey}`);
      } finally {
        if (cacheChangeCheckInFlight.get(cacheKey) === pending) {
          cacheChangeCheckInFlight.delete(cacheKey);
        }
      }
    })();
    cacheChangeCheckInFlight.set(cacheKey, pending);
  }

  function shouldRunLibraryCheckForRequest(request, cacheKey) {
    if (!request) {
      return true;
    }

    const markerKey = '__plexsonicLibraryChecks';
    let checkedCacheKeys = request[markerKey];
    if (!(checkedCacheKeys instanceof Set)) {
      checkedCacheKeys = new Set();
      request[markerKey] = checkedCacheKeys;
    }

    if (checkedCacheKeys.has(cacheKey)) {
      return false;
    }

    checkedCacheKeys.add(cacheKey);
    return true;
  }

  async function getSearchBrowseCollection({ cacheKey, collection, loader, plexState, request = null }) {
    const now = Date.now();

    if (hasSearchBrowseCollectionPersistedData(cacheKey) && shouldRunLibraryCheckForRequest(request, cacheKey)) {
      maybeCheckLibraryChanges({ cacheKey, plexState, request });
    }
    await ensureDirtySearchBrowseRefresh({
      cacheKey,
      plexState,
      request,
      wait: true,
    });

    const cached = readSearchBrowseCollectionFromSqlite(cacheKey, collection);
    if (Array.isArray(cached)) {
      const state = getPersistedLibraryCacheState(cacheKey);
      const lastSyncedMs = Number(state.lastSyncedAt || 0) * 1000;
      const isStale = lastSyncedMs <= 0 || (now - lastSyncedMs) >= SEARCH_BROWSE_REVALIDATE_DEBOUNCE_MS;
      if (isStale) {
        loadSearchBrowseCollection({
          cacheKey,
          collection,
          loader,
          request,
          background: true,
        }).catch((error) => {
          request?.log?.debug?.(error, `Background refresh scheduling failed for ${collection} cache`);
        });
      }
      return cached;
    }

    if (hasPersistedCollectionData(cacheKey, collection)) {
      return [];
    }

    return loadSearchBrowseCollection({
      cacheKey,
      collection,
      loader,
      request,
      background: false,
    });
  }

  function searchSqlParams(cacheKey, query, limit, offset) {
    const normalizedQuery = safeLower(String(query || '').trim());
    return {
      cache_key: cacheKey,
      query: normalizedQuery,
      pattern: `%${normalizedQuery}%`,
      limit: Math.max(0, Number.parseInt(String(limit ?? 0), 10) || 0),
      offset: Math.max(0, Number.parseInt(String(offset ?? 0), 10) || 0),
    };
  }

  function numericTotal(value) {
    return parseNonNegativeInt(value, 0);
  }

  async function ensureSearchBrowseCollectionReady({
    accountId,
    plexState,
    request = null,
    collection,
  }) {
    if (!SEARCH_BROWSE_COLLECTIONS.includes(collection)) {
      throw new Error(`Unsupported cache collection: ${collection}`);
    }

    const cacheKey = searchBrowseCacheKey(accountId, plexState);
    const now = Date.now();

    if (hasSearchBrowseCollectionPersistedData(cacheKey) && shouldRunLibraryCheckForRequest(request, cacheKey)) {
      maybeCheckLibraryChanges({ cacheKey, plexState, request });
    }
    await ensureDirtySearchBrowseRefresh({
      cacheKey,
      plexState,
      request,
      wait: true,
    });

    if (!hasPersistedCollectionData(cacheKey, collection)) {
      await loadSearchBrowseCollection({
        cacheKey,
        collection,
        loader: getLibraryCollectionLoader(collection, plexState),
        request,
        background: false,
      });
      return cacheKey;
    }

    const state = getPersistedLibraryCacheState(cacheKey);
    const lastSyncedMs = Number(state.lastSyncedAt || 0) * 1000;
    const isStale = lastSyncedMs <= 0 || (now - lastSyncedMs) >= SEARCH_BROWSE_REVALIDATE_DEBOUNCE_MS;
    if (isStale) {
      loadSearchBrowseCollection({
        cacheKey,
        collection,
        loader: getLibraryCollectionLoader(collection, plexState),
        request,
        background: true,
      }).catch((error) => {
        request?.log?.debug?.(error, `Background refresh scheduling failed for ${collection} cache`);
      });
    }

    return cacheKey;
  }

  function trackFromCacheRowWithRelations(cacheKey, row) {
    const ratingKey = String(row?.rating_key || '').trim();
    if (!ratingKey) {
      return trackFromCacheRow(row);
    }
    const relations = trackRelationsByRatingKey(cacheKey, ratingKey);
    return trackFromCacheRow(row, {
      genreNames: relations.genres,
      artists: relations.artists,
      albumArtists: relations.albumArtists,
    });
  }

  function albumFromCacheRowWithRelations(cacheKey, row) {
    const ratingKey = String(row?.rating_key || '').trim();
    return albumFromCacheRow(row, ratingKey ? albumGenresByRatingKey(cacheKey, ratingKey) : []);
  }

  async function queryArtistsBySearch({
    accountId,
    plexState,
    request,
    query,
    count,
    offset,
  }) {
    const cacheKey = await ensureSearchBrowseCollectionReady({
      accountId,
      plexState,
      request,
      collection: 'artists',
    });
    const params = searchSqlParams(cacheKey, query, count, offset);
    const total = numericTotal(countArtistsByQueryStmt.get(params)?.total);
    if (params.limit <= 0) {
      return { total, items: [] };
    }
    const items = selectArtistsPageByQueryStmt.all(params).map((row) => artistFromCacheRow(row));
    return { total, items };
  }

  async function queryAlbumsBySearch({
    accountId,
    plexState,
    request,
    query,
    count,
    offset,
  }) {
    const cacheKey = await ensureSearchBrowseCollectionReady({
      accountId,
      plexState,
      request,
      collection: 'albums',
    });
    const params = searchSqlParams(cacheKey, query, count, offset);
    const total = numericTotal(countAlbumsByQueryStmt.get(params)?.total);
    if (params.limit <= 0) {
      return { total, items: [] };
    }
    const rows = selectAlbumsPageByQueryStmt.all(params);
    const items = rows.map((row) => albumFromCacheRowWithRelations(cacheKey, row));
    return { total, items };
  }

  async function queryTracksBySearch({
    accountId,
    plexState,
    request,
    query,
    count,
    offset,
  }) {
    const cacheKey = await ensureSearchBrowseCollectionReady({
      accountId,
      plexState,
      request,
      collection: 'tracks',
    });
    const params = searchSqlParams(cacheKey, query, count, offset);
    const total = numericTotal(countTracksByQueryStmt.get(params)?.total);
    if (params.limit <= 0) {
      return { total, items: [] };
    }
    const rows = selectTracksPageByQueryStmt.all(params);
    const items = rows.map((row) => trackFromCacheRowWithRelations(cacheKey, row));
    return { total, items };
  }

  async function queryTracksByGenre({
    accountId,
    plexState,
    request,
    genre,
    count,
    offset,
  }) {
    const cacheKey = await ensureSearchBrowseCollectionReady({
      accountId,
      plexState,
      request,
      collection: 'tracks',
    });
    const params = {
      cache_key: cacheKey,
      genre: String(genre || ''),
      limit: Math.max(0, Number.parseInt(String(count ?? 0), 10) || 0),
      offset: Math.max(0, Number.parseInt(String(offset ?? 0), 10) || 0),
    };
    const total = numericTotal(countTracksByGenreStmt.get(params)?.total);
    if (params.limit <= 0) {
      return { total, items: [] };
    }
    const rows = selectTracksByGenreStmt.all(params);
    const items = rows.map((row) => trackFromCacheRowWithRelations(cacheKey, row));
    return { total, items };
  }

  async function queryGenreSummaries({
    accountId,
    plexState,
    request,
  }) {
    const cacheKey = await ensureSearchBrowseCollectionReady({
      accountId,
      plexState,
      request,
      collection: 'tracks',
    });
    const rows = selectGenreSummaryRowsStmt.all(cacheKey);
    return rows.map((row) => ({
      value: firstNonEmptyText([row?.genre_name], ''),
      songCount: numericTotal(row?.song_count),
      albumCount: numericTotal(row?.album_count),
    }))
      .filter((item) => Boolean(item.value));
  }

  function albumListStatementsByType(type, fromYear, toYear) {
    switch (type) {
      case 'alphabeticalbyartist':
        return {
          selectStmt: selectAlbumsAlphabeticalByArtistStmt,
          countStmt: countAlbumsAlphabeticalByArtistStmt,
          params: {},
        };
      case 'newest':
        return {
          selectStmt: selectAlbumsNewestStmt,
          countStmt: countAlbumsNewestStmt,
          params: {},
        };
      case 'highest':
        return {
          selectStmt: selectAlbumsHighestStmt,
          countStmt: countAlbumsHighestStmt,
          params: {},
        };
      case 'frequent':
        return {
          selectStmt: selectAlbumsFrequentStmt,
          countStmt: countAlbumsFrequentStmt,
          params: {},
        };
      case 'recent':
        return {
          selectStmt: selectAlbumsRecentStmt,
          countStmt: countAlbumsRecentStmt,
          params: {},
        };
      case 'starred':
        return {
          selectStmt: selectAlbumsStarredStmt,
          countStmt: countAlbumsStarredStmt,
          params: {},
        };
      case 'random':
        return {
          selectStmt: selectAlbumsRandomStmt,
          countStmt: countAlbumsRandomStmt,
          params: {},
        };
      case 'byyear': {
        const yearLow = Math.min(fromYear, toYear);
        const yearHigh = Math.max(fromYear, toYear);
        const descending = fromYear > toYear;
        return {
          selectStmt: descending ? selectAlbumsByYearDescStmt : selectAlbumsByYearAscStmt,
          countStmt: countAlbumsByYearStmt,
          params: {
            year_low: yearLow,
            year_high: yearHigh,
          },
        };
      }
      case 'bygenre':
        return {
          selectStmt: selectAlbumsByGenreStmt,
          countStmt: countAlbumsByGenreStmt,
          params: {},
        };
      case 'alphabeticalbyname':
      default:
        return {
          selectStmt: selectAlbumsAlphabeticalByNameStmt,
          countStmt: countAlbumsAlphabeticalByNameStmt,
          params: {},
        };
    }
  }

  async function queryAlbumListFromCache({
    accountId,
    plexState,
    request,
    type,
    fromYear,
    toYear,
    genre,
    size,
    offset,
  }) {
    const cacheKey = await ensureSearchBrowseCollectionReady({
      accountId,
      plexState,
      request,
      collection: 'albums',
    });
    const selected = albumListStatementsByType(type, fromYear, toYear);
    const params = {
      cache_key: cacheKey,
      limit: Math.max(0, Number.parseInt(String(size ?? 0), 10) || 0),
      offset: Math.max(0, Number.parseInt(String(offset ?? 0), 10) || 0),
      genre: String(genre || ''),
      ...selected.params,
    };
    const total = numericTotal(selected.countStmt.get(params)?.total);
    if (params.limit <= 0) {
      return { total, items: [] };
    }
    const rows = selected.selectStmt.all(params);
    const items = rows.map((row) => albumFromCacheRowWithRelations(cacheKey, row));
    return { total, items };
  }

  async function getCachedLibraryArtists({ accountId, plexState, request }) {
    const cacheKey = searchBrowseCacheKey(accountId, plexState);
    return getSearchBrowseCollection({
      cacheKey,
      collection: 'artists',
      plexState,
      request,
      loader: () => loadLibraryArtistsRaw({ plexState }),
    });
  }

  async function getCachedLibraryAlbums({ accountId, plexState, request }) {
    const cacheKey = searchBrowseCacheKey(accountId, plexState);
    return getSearchBrowseCollection({
      cacheKey,
      collection: 'albums',
      plexState,
      request,
      loader: () => loadLibraryAlbumsRaw({ plexState }),
    });
  }

  async function getCachedLibraryTracks({ accountId, plexState, request }) {
    const cacheKey = searchBrowseCacheKey(accountId, plexState);
    return getSearchBrowseCollection({
      cacheKey,
      collection: 'tracks',
      plexState,
      request,
      loader: () => loadLibraryTracksRaw({ plexState }),
    });
  }

  async function recoverWarmupPlexState({ accountId, fallbackState, request = null }) {
    const logger = request?.log || app.log;
    const currentContext = repo.getAccountPlexContext(accountId);
    if (!hasPlexSelectionContext(currentContext)) {
      return null;
    }

    const existingState = buildPlexStateFromContext(currentContext, tokenCipher) || fallbackState;
    if (!existingState?.baseUrl || !existingState?.machineId) {
      return null;
    }

    const pickSectionAndPersist = async ({ baseUrl, plexToken }) => {
      const sections = await listMusicSections({
        baseUrl,
        plexToken,
      });
      const chosen = chooseRecoverableMusicSection(
        sections,
        currentContext.music_section_id,
        currentContext.music_section_name,
      );
      if (!chosen) {
        return null;
      }
      const chosenId = String(chosen.id || '').trim();
      if (!chosenId) {
        return null;
      }
      if (chosenId !== String(currentContext.music_section_id || '').trim()) {
        repo.upsertSelectedLibrary({
          accountId,
          musicSectionId: chosenId,
          musicSectionName: chosen.title ? String(chosen.title) : null,
        });
      }
      return chosen;
    };

    try {
      const chosen = await pickSectionAndPersist({
        baseUrl: existingState.baseUrl,
        plexToken: existingState.plexToken,
      });
      if (chosen) {
        const refreshed = repo.getAccountPlexContext(accountId);
        const recoveredState = buildPlexStateFromContext(refreshed, tokenCipher);
        if (recoveredState) {
          return recoveredState;
        }
      }
    } catch {
      // Continue to server URL recovery path below.
    }

    let accountToken = null;
    if (currentContext.plex_token_enc) {
      try {
        accountToken = decodePlexTokenOrThrow(tokenCipher, currentContext.plex_token_enc);
      } catch { }
    }
    if (!accountToken) {
      return null;
    }

    let resources;
    try {
      resources = await listPlexServers(config, accountToken);
    } catch (error) {
      logger.debug({ err: error, accountId }, 'Unable to list Plex resources for warm-up recovery');
      return null;
    }
    const matched = (Array.isArray(resources) ? resources : [])
      .find((resource) => String(resource?.machineId || '') === String(currentContext.machine_id || ''));
    if (!matched) {
      return null;
    }

    const candidateUrls = uniqueNonEmptyValues([
      currentContext.server_base_url,
      matched.baseUrl,
      ...((Array.isArray(matched.connectionUris) ? matched.connectionUris : [])),
    ]);
    const candidateTokens = uniqueNonEmptyValues([
      matched.accessToken,
      ...(Array.isArray(existingState.plexToken) ? existingState.plexToken : []),
      accountToken,
    ]);

    for (const candidateToken of candidateTokens) {
      for (const candidateUrl of candidateUrls) {
        try {
          const chosen = await pickSectionAndPersist({
            baseUrl: candidateUrl,
            plexToken: candidateToken,
          });
          if (!chosen) {
            continue;
          }

          const encryptedServerToken = candidateToken
            ? tokenCipher.encrypt(String(candidateToken))
            : currentContext.server_token_enc || null;
          repo.upsertSelectedServer({
            accountId,
            machineId: String(currentContext.machine_id),
            name: String(matched.name || currentContext.server_name || 'Plex Server'),
            baseUrl: String(candidateUrl),
            encryptedServerToken,
          });

          const refreshed = repo.getAccountPlexContext(accountId);
          const recoveredState = buildPlexStateFromContext(refreshed, tokenCipher);
          if (recoveredState) {
            logger.info(
              { accountId, machineId: currentContext.machine_id, baseUrl: candidateUrl, sectionId: chosen.id },
              'Recovered Plex context for cache warm-up',
            );
            return recoveredState;
          }
        } catch {
          // Try next candidate URL/token.
        }
      }
    }

    return null;
  }

  async function warmLibraryCacheForAccount({
    accountId,
    plexState,
    reason = 'manual',
    request = null,
    attemptRecovery = true,
    forceRefresh = false,
  }) {
    if (!accountId || !plexState) {
      return;
    }
    const cacheKey = searchBrowseCacheKey(accountId, plexState);
    if (cacheWarmupInFlight.has(cacheKey)) {
      return cacheWarmupInFlight.get(cacheKey);
    }

    const pending = (async () => {
      try {
        const collectionsToWarm = SEARCH_BROWSE_COLLECTIONS.filter((collection) =>
          forceRefresh || !hasPersistedCollectionData(cacheKey, collection),
        );
        if (collectionsToWarm.length === 0) {
          app.log.debug({ cacheKey, accountId, reason }, 'Library cache warm-up skipped (already populated)');
          return;
        }

        const loaderCounts = {
          artists: 0,
          albums: 0,
          tracks: 0,
        };
        for (const collection of collectionsToWarm) {
          const loaded = await loadSearchBrowseCollection({
            cacheKey,
            collection,
            loader: getLibraryCollectionLoader(collection, plexState),
            request,
            background: false,
          });
          loaderCounts[collection] = Array.isArray(loaded) ? loaded.length : 0;
        }
        const nowSeconds = Math.floor(Date.now() / 1000);
        const state = getPersistedLibraryCacheState(cacheKey);
        state.lastSyncedAt = Math.max(Number(state.lastSyncedAt || 0), nowSeconds);
        state.dirty = false;
        persistLibraryCacheState(cacheKey, state, nowSeconds);
        app.log.info(
          {
            cacheKey,
            accountId,
            reason,
            warmedCollections: collectionsToWarm,
            artists: loaderCounts.artists,
            albums: loaderCounts.albums,
            tracks: loaderCounts.tracks,
          },
          'Library cache warm-up completed',
        );
      } catch (error) {
        if (attemptRecovery) {
          const recoveredState = await recoverWarmupPlexState({
            accountId,
            fallbackState: plexState,
            request,
          });
          if (recoveredState) {
            return warmLibraryCacheForAccount({
              accountId,
              plexState: recoveredState,
              reason: `${reason}-recovered`,
              request,
              attemptRecovery: false,
              forceRefresh,
            });
          }
        }
        const logger = request?.log || app.log;
        logger.warn({ err: error, cacheKey, accountId, reason }, 'Library cache warm-up failed');
      }
    })();

    cacheWarmupInFlight.set(cacheKey, pending);
    pending.finally(() => {
      if (cacheWarmupInFlight.get(cacheKey) === pending) {
        cacheWarmupInFlight.delete(cacheKey);
      }
    });
    return pending;
  }

  async function warmAllLinkedLibraryCaches(reason = 'startup') {
    const contexts = repo.listAccountPlexContexts()
      .filter((context) =>
        Number(context?.enabled) === 1 &&
        hasPlexSelectionContext(context),
      );
    for (const context of contexts) {
      const plexState = buildPlexStateFromContext(context, tokenCipher);
      if (!plexState) {
        continue;
      }
      // Warm sequentially to cap memory spikes when multiple accounts share large libraries.
      await warmLibraryCacheForAccount({
        accountId: context.account_id,
        plexState,
        reason,
        forceRefresh: false,
      });
    }
  }

  function cachedRowToCollectionItem(cacheKey, collection, row) {
    if (!row) {
      return null;
    }
    if (collection === 'artists') {
      return artistFromCacheRow(row);
    }
    if (collection === 'albums') {
      return albumFromCacheRowWithRelations(cacheKey, row);
    }
    if (collection === 'tracks') {
      return trackFromCacheRowWithRelations(cacheKey, row);
    }
    return null;
  }

  function selectCollectionRowByIdentity(cacheKey, collection, id) {
    const exact = String(id || '').trim();
    if (!exact) {
      return null;
    }
    const lowered = safeLower(exact);
    const params = {
      cache_key: cacheKey,
      exact,
      lowered,
    };
    if (collection === 'artists') {
      return selectArtistRowByIdentityStmt.get(params) || null;
    }
    if (collection === 'albums') {
      return selectAlbumRowByIdentityStmt.get(params) || null;
    }
    if (collection === 'tracks') {
      return selectTrackRowByIdentityStmt.get(params) || null;
    }
    return null;
  }

  function selectCollectionRowByRatingKey(cacheKey, collection, ratingKey) {
    const normalized = String(ratingKey || '').trim();
    if (!normalized) {
      return null;
    }
    if (collection === 'artists') {
      return selectArtistRowByRatingKeyStmt.get(cacheKey, normalized) || null;
    }
    if (collection === 'albums') {
      return selectAlbumRowByRatingKeyStmt.get(cacheKey, normalized) || null;
    }
    if (collection === 'tracks') {
      return selectTrackRowByRatingKeyStmt.get(cacheKey, normalized) || null;
    }
    return null;
  }

  async function resolveCachedLibraryItemById({ accountId, plexState, request, collection, id }) {
    const normalizedId = String(id || '').trim();
    if (!normalizedId) {
      return null;
    }
    if (!SEARCH_BROWSE_COLLECTIONS.includes(collection)) {
      return null;
    }

    const cacheKey = await ensureSearchBrowseCollectionReady({
      accountId,
      plexState,
      request,
      collection,
    });
    const metadataId = metadataPathRatingKey(normalizedId);
    const numericCandidate = isNumericRatingKey(normalizedId) ? normalizedId : metadataId;
    if (numericCandidate) {
      const row = selectCollectionRowByRatingKey(cacheKey, collection, numericCandidate);
      const item = cachedRowToCollectionItem(cacheKey, collection, row);
      if (item) {
        return item;
      }
    }

    const directRow = selectCollectionRowByIdentity(cacheKey, collection, normalizedId);
    if (directRow) {
      const item = cachedRowToCollectionItem(cacheKey, collection, directRow);
      if (item) {
        return item;
      }
    }

    const variants = [...comparableIdVariants(normalizedId)];
    for (const variant of variants) {
      const row = selectCollectionRowByIdentity(cacheKey, collection, variant);
      if (row) {
        const item = cachedRowToCollectionItem(cacheKey, collection, row);
        if (item) {
          return item;
        }
      }
    }

    const fallbackItems = readSearchBrowseCollectionFromSqlite(cacheKey, collection) || [];
    return findItemByRequestedId(fallbackItems, normalizedId);
  }

  async function resolveCachedLibraryRatingKey({ accountId, plexState, request, collection, id }) {
    const normalizedId = String(id || '').trim();
    if (!normalizedId) {
      return '';
    }
    if (isNumericRatingKey(normalizedId)) {
      return normalizedId;
    }

    const metadataId = metadataPathRatingKey(normalizedId);
    if (metadataId) {
      return metadataId;
    }

    const item = await resolveCachedLibraryItemById({
      accountId,
      plexState,
      request,
      collection,
      id: normalizedId,
    });
    return String(item?.ratingKey || '').trim();
  }

  async function resolveCachedLibraryRatingKeyAnyCollection({
    accountId,
    plexState,
    request,
    id,
    collections = ['tracks', 'albums', 'artists'],
  }) {
    for (const collection of collections) {
      const resolved = await resolveCachedLibraryRatingKey({
        accountId,
        plexState,
        request,
        collection,
        id,
      });
      if (resolved) {
        return resolved;
      }
    }
    return '';
  }

  function pruneSavedPlayQueues(now = Date.now()) {
    for (const [key, value] of savedPlayQueues.entries()) {
      if (!value || (now - Number(value.updatedAt || 0)) > PLAY_QUEUE_IDLE_TTL_MS) {
        savedPlayQueues.delete(key);
      }
    }
  }

  function playQueueClientKey(request) {
    const rawClient =
      getRequestParam(request, 'c') ||
      String(request.headers?.['user-agent'] || '').trim() ||
      'subsonic-client';
    return safeLower(rawClient).slice(0, 128) || 'subsonic-client';
  }

  function playQueueStorageKey(accountId, request) {
    return `${accountId}:${playQueueClientKey(request)}`;
  }

  function requestedPlayQueueItemIds(request) {
    const ids = getRequestParamValues(request, 'id');
    if (ids.length > 0) {
      return ids;
    }
    return getRequestParamValues(request, 'songId');
  }

  async function resolveTracksByIdOrder({ accountId, plexState, request, ids }) {
    const orderedIds = (Array.isArray(ids) ? ids : [])
      .map((id) => String(id || '').trim())
      .filter(Boolean);
    if (orderedIds.length === 0) {
      return [];
    }

    const cacheKey = await ensureSearchBrowseCollectionReady({
      accountId,
      plexState,
      request,
      collection: 'tracks',
    });
    const cachedById = new Map();
    for (const id of orderedIds) {
      const metadataId = metadataPathRatingKey(id);
      let row = selectTrackRowByRatingKeyStmt.get(cacheKey, id) ||
        (metadataId ? selectTrackRowByRatingKeyStmt.get(cacheKey, metadataId) : null) ||
        selectTrackRowByIdentityStmt.get({
          cache_key: cacheKey,
          exact: id,
          lowered: safeLower(id),
        });
      if (!row) {
        for (const variant of comparableIdVariants(id)) {
          row = selectTrackRowByIdentityStmt.get({
            cache_key: cacheKey,
            exact: variant,
            lowered: safeLower(variant),
          });
          if (row) {
            break;
          }
        }
      }
      if (!row) {
        continue;
      }
      const mapped = trackFromCacheRowWithRelations(cacheKey, row);
      const ratingKey = String(mapped?.ratingKey || '').trim();
      if (ratingKey && !cachedById.has(ratingKey)) {
        cachedById.set(ratingKey, mapped);
      }
    }

    const missingIds = [];
    for (const id of orderedIds) {
      if (!cachedById.has(id)) {
        missingIds.push(id);
      }
    }

    if (missingIds.length > 0) {
      const fetched = await Promise.all(
        missingIds.map(async (trackId) => {
          try {
            const track = await getTrack({
              baseUrl: plexState.baseUrl,
              plexToken: plexState.plexToken,
              trackId,
            });
            return track || null;
          } catch {
            return null;
          }
        }),
      );

      const nonNullFetched = fetched.filter(Boolean);
      applyCachedRatingOverridesForAccount({ accountId, plexState, items: nonNullFetched });

      for (const track of nonNullFetched) {
        const ratingKey = String(track?.ratingKey || '').trim();
        if (ratingKey && !cachedById.has(ratingKey)) {
          cachedById.set(ratingKey, track);
        }
      }
    }

    return orderedIds
      .map((id) => cachedById.get(id))
      .filter(Boolean);
  }

  function applyCachedRatingOverridesForAccount({ accountId, plexState, items }) {
    if (!Array.isArray(items) || items.length === 0) {
      return 0;
    }
    const cacheKey = searchBrowseCacheKey(accountId, plexState);
    let patched = 0;
    for (const item of items) {
      const ratingKey = String(item?.ratingKey || '').trim();
      if (!ratingKey) {
        continue;
      }
      const found = selectCachedItemRatingStmt.get({
        cache_key: cacheKey,
        rating_key: ratingKey,
      });
      if (!found || found.user_rating == null) {
        continue;
      }
      const normalized = normalizePlexRating(found.user_rating);
      if (normalized == null) {
        continue;
      }
      item.userRating = normalized;
      const updatedAt = Number.parseInt(String(found.updated_at ?? ''), 10);
      if (Number.isFinite(updatedAt) && updatedAt > 0) {
        item.updatedAt = updatedAt;
      }
      if (!isPlexLiked(item.userRating)) {
        delete item.starred;
        delete item.starredAt;
      }
      patched += 1;
    }
    return patched;
  }

  async function resolveArtistFromCachedLibrary({ accountId, plexState, request, artistId }) {
    const normalizedArtistId = String(artistId || '').trim();
    if (!normalizedArtistId) {
      return null;
    }
    const [artistCacheKey, albumCacheKey, trackCacheKey] = await Promise.all([
      ensureSearchBrowseCollectionReady({ accountId, plexState, request, collection: 'artists' }),
      ensureSearchBrowseCollectionReady({ accountId, plexState, request, collection: 'albums' }),
      ensureSearchBrowseCollectionReady({ accountId, plexState, request, collection: 'tracks' }),
    ]);

    let cachedArtist = await resolveCachedLibraryItemById({
      accountId,
      plexState,
      request,
      collection: 'artists',
      id: normalizedArtistId,
    });
    const numericArtistId = isNumericRatingKey(normalizedArtistId)
      ? normalizedArtistId
      : metadataPathRatingKey(normalizedArtistId);

    let trackRows = [];
    const resolvedArtistIdHint = String(cachedArtist?.ratingKey || numericArtistId || '').trim();
    if (resolvedArtistIdHint) {
      trackRows = selectTracksByGrandparentRatingKeyStmt.all(trackCacheKey, resolvedArtistIdHint);
    }
    if (trackRows.length === 0) {
      trackRows = selectTracksByGrandparentTitleStmt.all(trackCacheKey, normalizedArtistId);
    }
    const artistTracks = trackRows.map((row) => trackFromCacheRowWithRelations(trackCacheKey, row));
    const artistNameFromTracks = firstNonEmptyText(
      artistTracks.map((item) => trackPrimaryArtistName(item)),
      '',
    );
    if (!cachedArtist && artistNameFromTracks) {
      const row = selectArtistRowByTitleStmt.get(artistCacheKey, artistNameFromTracks);
      if (row) {
        cachedArtist = artistFromCacheRow(row);
      }
    }

    const resolvedArtistId = String(
      cachedArtist?.ratingKey ||
      trackPrimaryArtistId(artistTracks[0]) ||
      artistTracks[0]?.grandparentRatingKey ||
      numericArtistId ||
      normalizedArtistId,
    ).trim();
    const effectiveArtistName = cachedArtist?.title || artistNameFromTracks || normalizedArtistId;

    let albumRows = [];
    if (resolvedArtistId) {
      albumRows = selectAlbumsByParentRatingKeyStmt.all(albumCacheKey, resolvedArtistId);
    }
    if (albumRows.length === 0 && effectiveArtistName) {
      albumRows = selectAlbumsByParentTitleStmt.all(albumCacheKey, effectiveArtistName);
    }
    const resolvedAlbums = albumRows.length > 0
      ? albumRows.map((row) => albumFromCacheRowWithRelations(albumCacheKey, row))
      : deriveAlbumsFromTracks(artistTracks, resolvedArtistId, effectiveArtistName);

    if (!cachedArtist && resolvedAlbums.length === 0 && artistTracks.length === 0) {
      return null;
    }

    const artistName = cachedArtist?.title ||
      artistNameFromTracks ||
      firstNonEmptyText(artistTracks.map((item) => item?.grandparentTitle), `Artist ${normalizedArtistId}`);
    const artist = cachedArtist || {
      ratingKey: resolvedArtistId,
      title: artistName,
      addedAt: artistTracks[0]?.addedAt,
      updatedAt: artistTracks[0]?.updatedAt,
    };

    return {
      artist,
      albums: resolvedAlbums,
    };
  }

  async function resolveAlbumFromCachedLibrary({ accountId, plexState, request, albumId }) {
    const normalizedAlbumId = String(albumId || '').trim();
    if (!normalizedAlbumId) {
      return null;
    }

    const album = await resolveCachedLibraryItemById({
      accountId,
      plexState,
      request,
      collection: 'albums',
      id: normalizedAlbumId,
    });
    if (!album) {
      return null;
    }

    const trackCacheKey = await ensureSearchBrowseCollectionReady({
      accountId,
      plexState,
      request,
      collection: 'tracks',
    });
    const resolvedAlbumId = String(album.ratingKey || '').trim();
    const albumTracks = selectTracksByParentRatingKeyStmt
      .all(trackCacheKey, resolvedAlbumId)
      .map((row) => trackFromCacheRowWithRelations(trackCacheKey, row));
    return {
      album,
      tracks: albumTracks,
    };
  }

  async function resolveTrackFromCachedLibrary({ accountId, plexState, request, trackId }) {
    const normalizedTrackId = String(trackId || '').trim();
    if (!normalizedTrackId) {
      return null;
    }
    return resolveCachedLibraryItemById({
      accountId,
      plexState,
      request,
      collection: 'tracks',
      id: normalizedTrackId,
    });
  }

  function scanStatusAttrsFromSection(section, { fallbackScanning = false } = {}) {
    return {
      scanning: Boolean(section?.scanning ?? fallbackScanning),
      count: parseNonNegativeInt(section?.leafCount, 0),
    };
  }

  async function getMusicSectionScanStatus(plexState) {
    const sections = await listMusicSections({
      baseUrl: plexState.baseUrl,
      plexToken: plexState.plexToken,
    });
    const section = sections.find((item) => String(item?.id || '') === String(plexState.musicSectionId || ''));
    return section || null;
  }

  function beginSearchRequest(request, accountId) {
    const clientName =
      getRequestParam(request, 'c') ||
      String(request.headers?.['user-agent'] || '').trim() ||
      request.ip ||
      'Subsonic Client';
    const endpointPath = String(request.url || '').split('?')[0] || '/rest/search';
    const registryKey = `${accountId}:${clientName}:${endpointPath}`;
    const previousScope = activeSearchRequests.get(registryKey);
    if (previousScope) {
      previousScope.controller.abort('superseded');
    }

    const controller = new AbortController();
    const scope = { controller };
    activeSearchRequests.set(registryKey, scope);

    const abortOnDisconnect = () => {
      controller.abort('client-disconnected');
    };
    request.raw.once('aborted', abortOnDisconnect);
    request.raw.once('close', abortOnDisconnect);

    return {
      signal: controller.signal,
      reason: () => controller.signal.reason,
      cleanup: () => {
        request.raw.removeListener('aborted', abortOnDisconnect);
        request.raw.removeListener('close', abortOnDisconnect);
        if (activeSearchRequests.get(registryKey) === scope) {
          activeSearchRequests.delete(registryKey);
        }
      },
    };
  }

  function normalizePlaybackState(value, fallback = 'playing') {
    const state = safeLower(value);
    if (state === 'playing' || state === 'paused' || state === 'stopped') {
      return state;
    }
    return fallback;
  }

  function playbackClientContext(accountId, clientNameRaw) {
    const clientName = String(clientNameRaw || 'Subsonic Client');
    const clientIdentifier = md5HexUtf8(`${accountId}:${clientName}`).slice(0, 32);
    const sessionKey = `${accountId}:${clientIdentifier}`;
    const sessionId = `${clientIdentifier}:plexsonic`;
    return {
      clientName,
      clientIdentifier,
      sessionKey,
      sessionId,
    };
  }

  function pruneRecentScrobbles() {
    for (const [key, value] of recentScrobblesByClient.entries()) {
      if (!value) {
        recentScrobblesByClient.delete(key);
      }
    }
  }

  function getPlaybackContinuityState(accountId, clientName) {
    const playbackClient = playbackClientContext(accountId, clientName);
    let state = recentScrobblesByClient.get(playbackClient.sessionKey);
    if (!state) {
      state = {
        at: 0,
        trackId: '',
        queueCurrentId: '',
        queueIds: [],
      };
      recentScrobblesByClient.set(playbackClient.sessionKey, state);
    }
    return { playbackClient, state };
  }

  function resolveQueuedNextTrackId(state, currentTrackId) {
    const normalizedCurrent = String(currentTrackId || '').trim();
    if (!normalizedCurrent) {
      return '';
    }

    const queueIds = Array.isArray(state?.queueIds) ? state.queueIds : [];
    if (queueIds.length === 0) {
      return '';
    }

    const index = queueIds.findIndex((id) => String(id || '').trim() === normalizedCurrent);
    if (index === -1) {
      return '';
    }
    const next = String(queueIds[index + 1] || '').trim();
    return next;
  }

  function notePlaybackQueueContext({ accountId, clientName, currentTrackId = '', queueIds = [] }) {
    const { state } = getPlaybackContinuityState(accountId, clientName);
    state.queueCurrentId = String(currentTrackId || '').trim();
    state.queueIds = uniqueNonEmptyValues(Array.isArray(queueIds) ? queueIds : []);
  }

  function noteRecentScrobble({ accountId, clientName, trackId = '' }) {
    const now = Date.now();
    const { state } = getPlaybackContinuityState(accountId, clientName);
    state.at = now;
    state.trackId = String(trackId || '').trim();
    pruneRecentScrobbles();
  }

  function shouldSuppressPlaybackSyncForStreamLoad({ accountId, clientName, trackId }) {
    const now = Date.now();
    pruneRecentScrobbles();

    const { playbackClient, state: recent } = getPlaybackContinuityState(accountId, clientName);
    const current = playbackSessions.get(playbackClient.sessionKey);

    const normalizedTrackId = String(trackId || '').trim();
    if (!normalizedTrackId) {
      return false;
    }

    const currentTrackId = String(current?.itemId || '').trim();
    if (current?.state === 'playing' && currentTrackId && normalizedTrackId === currentTrackId) {
      return false;
    }

    const queuedCurrentId = String(recent.queueCurrentId || '').trim();
    if (queuedCurrentId && queuedCurrentId === normalizedTrackId) {
      return false;
    }

    const recentTrackId = String(recent.trackId || '').trim();
    if (
      recentTrackId &&
      recentTrackId === currentTrackId &&
      (now - Number(recent.at || 0)) <= PLAYBACK_CONTINUITY_AFTER_SCROBBLE_MS
    ) {
      const queuedNextTrackId = resolveQueuedNextTrackId(recent, recentTrackId);
      if (queuedNextTrackId && queuedNextTrackId === normalizedTrackId) {
        return false;
      }
    }

    // No confirmed playback and no trusted continuity signal: treat stream load as preload.
    if (!current || current.state !== 'playing') {
      return true;
    }

    // Current track exists but stale: still require explicit continuity signal to avoid preload flashes.
    if ((now - Number(current.updatedAt || 0)) > PLAYBACK_IDLE_TIMEOUT_MS) {
      return true;
    }

    // Suppress short-lived preloads right after a scrobble signal.
    if ((now - Number(recent.at || 0)) <= STREAM_PRELOAD_SUPPRESS_AFTER_SCROBBLE_MS) {
      return true;
    }

    // Continuity mode: keep current track authoritative unless trusted signal allows switch.
    return true;
  }

  async function syncClientPlaybackState({
    accountId,
    plexState,
    clientName,
    itemId,
    state,
    positionMs = 0,
    durationMs = null,
    request,
  }) {
    const normalizedItemId = String(itemId || '').trim();
    const normalizedState = normalizePlaybackState(state);
    const normalizedPosition = Number.isFinite(positionMs) ? Math.max(0, Math.trunc(positionMs)) : 0;
    const normalizedDuration = Number.isFinite(durationMs) ? Math.max(0, Math.trunc(durationMs)) : null;
    const now = Date.now();
    const playbackClient = playbackClientContext(accountId, clientName);
    const previous = playbackSessions.get(playbackClient.sessionKey);

    if (!normalizedItemId) {
      return;
    }

    if (
      (normalizedState === 'playing' || normalizedState === 'paused') &&
      previous?.itemId &&
      previous.itemId !== normalizedItemId &&
      previous.state !== 'stopped'
    ) {
      try {
        await updatePlexPlaybackStatus({
          baseUrl: plexState.baseUrl,
          plexToken: plexState.plexToken,
          itemId: previous.itemId,
          state: 'stopped',
          positionMs: previous.positionMs || 0,
          clientIdentifier: playbackClient.clientIdentifier,
          clientName: playbackClient.clientName,
          product: config.plexProduct,
          sessionId: playbackClient.sessionId,
        });
      } catch (error) {
        request?.log?.warn(error, 'Failed to clear previous playback state in Plex');
      }
    }

    await updatePlexPlaybackStatus({
      baseUrl: plexState.baseUrl,
      plexToken: plexState.plexToken,
      itemId: normalizedItemId,
      state: normalizedState,
      positionMs: normalizedPosition,
      durationMs: normalizedDuration,
      clientIdentifier: playbackClient.clientIdentifier,
      clientName: playbackClient.clientName,
      product: config.plexProduct,
      sessionId: playbackClient.sessionId,
    });

    if (normalizedState === 'stopped') {
      playbackSessions.delete(playbackClient.sessionKey);
      return;
    }

    playbackSessions.set(playbackClient.sessionKey, {
      accountId,
      clientName: playbackClient.clientName,
      clientIdentifier: playbackClient.clientIdentifier,
      sessionId: playbackClient.sessionId,
      baseUrl: plexState.baseUrl,
      plexToken: plexState.plexToken,
      itemId: normalizedItemId,
      state: normalizedState,
      positionMs: normalizedPosition,
      durationMs: normalizedDuration,
      estimatedStopAt:
        normalizedState === 'playing' && Number.isFinite(normalizedDuration)
          ? now + Math.max(0, normalizedDuration - normalizedPosition)
          : null,
      updatedAt: now,
    });
  }

  function updatePlaybackSessionEstimateFromStream({
    accountId,
    clientName,
    trackId,
    durationMs = null,
    positionMs = 0,
  }) {
    const playbackClient = playbackClientContext(accountId, clientName);
    const current = playbackSessions.get(playbackClient.sessionKey);
    if (!current || current.state !== 'playing') {
      return false;
    }

    const normalizedTrackId = String(trackId || '').trim();
    if (!normalizedTrackId || String(current.itemId || '').trim() !== normalizedTrackId) {
      return false;
    }

    const now = Date.now();
    const normalizedDuration = Number.isFinite(durationMs) && durationMs > 0
      ? Math.max(0, Math.trunc(durationMs))
      : Number.isFinite(current.durationMs) && current.durationMs > 0
        ? Math.max(0, Math.trunc(current.durationMs))
        : null;
    const normalizedPosition = Number.isFinite(positionMs) && positionMs >= 0
      ? Math.max(0, Math.trunc(positionMs))
      : 0;
    const basePosition = Math.max(Number(current.positionMs || 0), normalizedPosition);
    const estimatedStopAt = normalizedDuration != null
      ? now + Math.max(0, normalizedDuration - basePosition)
      : current.estimatedStopAt;

    playbackSessions.set(playbackClient.sessionKey, {
      ...current,
      durationMs: normalizedDuration,
      positionMs: basePosition,
      estimatedStopAt,
      updatedAt: now,
    });

    return true;
  }

  const playbackMaintenanceTimer = setInterval(async () => {
    const now = Date.now();
    const sessions = [...playbackSessions.entries()];

    for (const [sessionKey, session] of sessions) {
      if (!session || session.state === 'stopped') {
        playbackSessions.delete(sessionKey);
        continue;
      }

      const estimatedStopReached = (
        session.state === 'playing' &&
        Number.isFinite(session.estimatedStopAt) &&
        session.estimatedStopAt <= now
      );
      const idleExpired = now - Number(session.updatedAt || 0) > PLAYBACK_IDLE_TIMEOUT_MS;

      if (estimatedStopReached || idleExpired) {
        if (
          !estimatedStopReached &&
          session.state === 'playing' &&
          Number.isFinite(session.estimatedStopAt) &&
          session.estimatedStopAt > now
        ) {
          continue;
        }

        try {
          await updatePlexPlaybackStatus({
            baseUrl: session.baseUrl,
            plexToken: session.plexToken,
            itemId: session.itemId,
            state: 'stopped',
            positionMs: session.positionMs || 0,
            clientIdentifier: session.clientIdentifier,
            clientName: session.clientName,
            product: config.plexProduct,
            sessionId: session.sessionId,
          });
        } catch (error) {
          app.log.warn(error, 'Failed to stop stale playback session');
        } finally {
          playbackSessions.delete(sessionKey);
        }
        continue;
      }
    }
  }, PLAYBACK_RECONCILE_INTERVAL_MS);

  if (typeof playbackMaintenanceTimer.unref === 'function') {
    playbackMaintenanceTimer.unref();
  }

  app.addHook('onClose', async () => {
    clearInterval(playbackMaintenanceTimer);
  });

  app.get('/health', async () => ({ status: 'ok' }));

  app.post('/webhooks/plex', async (request, reply) => {
    const expectedToken = String(config.plexWebhookToken || '').trim();
    const providedToken = String(
      firstForwardedValue(request.headers?.['x-plexsonic-webhook-token']) ||
      getQueryFirst(request, 'token') ||
      getBodyFieldValue(request.body, 'token') ||
      '',
    ).trim();

    if (expectedToken && providedToken !== expectedToken) {
      request.log.warn({ ip: request.ip }, 'Rejected Plex webhook with invalid token');
      return reply.code(403).send({ ok: false });
    }

    const payload = parsePlexWebhookPayload(request.body);
    const event = String(payload?.event || '').trim() || 'unknown';
    if (isRatingPatchableWebhookEvent(event)) {
      const ratingPatch = extractRatingPatchFromWebhook(payload);
      if (ratingPatch) {
        const patchedCount = applyUserRatingPatchToSearchBrowseCache({
          itemIds: ratingPatch.itemIds,
          userRating: ratingPatch.userRating,
          clearUserRating: ratingPatch.clearUserRating,
        });
        if (patchedCount === 0) {
          markSearchBrowseCacheDirty();
        }
        request.log.info({ event, patchedCount }, 'Plex webhook rating event applied to cache');
        return reply.code(202).send({ ok: true, patched: patchedCount });
      }

      markSearchBrowseCacheDirty();
      request.log.info({ event }, 'Plex webhook rating event missing metadata, marked caches dirty');
      return reply.code(202).send({ ok: true });
    }

    if (!shouldInvalidateCacheForPlexWebhook(payload)) {
      request.log.debug({ event }, 'Plex webhook ignored (non-library-changing event)');
      return reply.code(202).send({ ok: true, ignored: true });
    }

    markSearchBrowseCacheDirty();
    request.log.info({ event }, 'Plex webhook received, marked caches dirty');

    return reply.code(202).send({ ok: true });
  });

  app.get('/', async (request, reply) => {
    if (request.session.accountId) {
      return reply.redirect('/link/plex');
    }
    if (repo.hasAnyAccount()) {
      return reply.redirect('/login');
    }
    return reply.redirect('/signup');
  });

  app.get('/signup', async (request, reply) => {
    if (request.session.accountId) {
      return reply.redirect('/link/plex');
    }

    return reply.type('text/html; charset=utf-8').send(signupPage(getRouteNotice(request)));
  });

  app.post('/signup', async (request, reply) => {
    const username = normalizeUsername(request.body?.username);
    const password = normalizePassword(request.body?.password);

    if (!USERNAME_PATTERN.test(username)) {
      return reply
        .code(400)
        .type('text/html; charset=utf-8')
        .send(signupPage('Username must be 3-32 chars: letters, numbers, dot, underscore, hyphen.'));
    }

    if (password.length < 8) {
      return reply
        .code(400)
        .type('text/html; charset=utf-8')
        .send(signupPage('Password must be at least 8 characters.'));
    }

    const passwordHash = await argon2.hash(password, { type: argon2.argon2id });

    try {
      repo.createAccount({
        id: randomUUID(),
        username,
        passwordHash,
        subsonicPasswordEnc: tokenCipher.encrypt(password),
      });
    } catch (error) {
      if (sqliteIsUniqueViolation(error)) {
        return reply.code(409).type('text/html; charset=utf-8').send(signupPage('Username is already taken.'));
      }
      throw error;
    }

    const account = repo.getAccountByUsername(username);
    request.session.accountId = account.id;
    request.session.username = account.username;

    return reply.redirect('/link/plex', 303);
  });

  app.get('/login', async (request, reply) => {
    return reply.type('text/html; charset=utf-8').send(loginPage(getRouteNotice(request)));
  });

  app.post('/login', async (request, reply) => {
    const username = normalizeUsername(request.body?.username);
    const password = normalizePassword(request.body?.password);

    const account = repo.getAccountByUsername(username);
    if (!account || account.enabled !== 1) {
      logFailedLoginAttempt(request, {
        username,
        route: '/login',
        mechanism: 'password',
        reason: 'account_not_found_or_disabled',
        hasPassword: password !== '',
      });
      return reply.code(401).type('text/html; charset=utf-8').send(loginPage('Invalid username or password.'));
    }

    const passwordValid = await argon2.verify(account.password_hash, password);
    if (!passwordValid) {
      logFailedLoginAttempt(request, {
        username,
        route: '/login',
        mechanism: 'password',
        reason: 'password_mismatch',
        hasPassword: password !== '',
      });
      return reply.code(401).type('text/html; charset=utf-8').send(loginPage('Invalid username or password.'));
    }

    syncStoredSubsonicPassword(repo, tokenCipher, account, password);

    request.session.accountId = account.id;
    request.session.username = account.username;

    return reply.redirect('/link/plex', 303);
  });

  app.post('/logout', async (request, reply) => {
    await request.session.destroy();
    return reply.redirect('/login?notice=Signed%20out');
  });

  app.post('/auth/login', async (request, reply) => {
    const username = normalizeUsername(getRequestParam(request, 'username'));
    const password = normalizePassword(getRequestParam(request, 'password'));

    if (!username || !password) {
      logFailedLoginAttempt(request, {
        username,
        route: '/auth/login',
        mechanism: 'password',
        reason: 'missing_username_or_password',
        hasPassword: password !== '',
      });
      return reply.code(422).type('application/json; charset=utf-8').send({
        error: 'Invalid username or password',
      });
    }

    const account = repo.getAccountByUsername(username);
    if (!account || account.enabled !== 1) {
      logFailedLoginAttempt(request, {
        username,
        route: '/auth/login',
        mechanism: 'password',
        reason: 'account_not_found_or_disabled',
        hasPassword: true,
      });
      return reply.code(401).type('application/json; charset=utf-8').send({
        error: 'Invalid username or password',
      });
    }

    const passwordValid = await argon2.verify(account.password_hash, password);
    if (!passwordValid) {
      logFailedLoginAttempt(request, {
        username,
        route: '/auth/login',
        mechanism: 'password',
        reason: 'password_mismatch',
        hasPassword: true,
      });
      return reply.code(401).type('application/json; charset=utf-8').send({
        error: 'Invalid username or password',
      });
    }

    syncStoredSubsonicPassword(repo, tokenCipher, account, password);

    request.session.accountId = account.id;
    request.session.username = account.username;

    const subsonicSalt = randomUUID().replaceAll('-', '').slice(0, 12);
    const subsonicToken = md5HexUtf8(`${password}${subsonicSalt}`);

    return reply.type('application/json; charset=utf-8').send({
      id: account.id,
      name: account.username,
      username: account.username,
      isAdmin: true,
      token: randomUUID(),
      subsonicSalt,
      subsonicToken,
      avatar: '',
    });
  });

  app.get('/link/plex', async (request, reply) => {
    const account = await requireWebSessionAccount(request, reply, repo);
    if (!account) {
      return;
    }

    const plexContext = repo.getAccountPlexContext(account.id);
    if (plexContext?.plex_token_enc) {
      return reply
        .type('text/html; charset=utf-8')
        .send(
          linkedPlexPage({
            username: account.username,
            serverName: plexContext.server_name || null,
            libraryName: plexContext.music_section_name || (plexContext.music_section_id ? 'Selected' : null),
            notice: getRouteNotice(request),
          }),
        );
    }

    return reply
      .type('text/html; charset=utf-8')
      .send(linkPlexPage(account.username, getRouteNotice(request)));
  });

  app.post('/link/plex/start', async (request, reply) => {
    const account = await requireWebSessionAccount(request, reply, repo);
    if (!account) {
      return;
    }

    try {
      const sid = randomUUID();
      const completeUrl = new URL('/link/plex/pin', requestPublicOrigin(request, config));
      completeUrl.searchParams.set('sid', sid);
      completeUrl.searchParams.set('phase', 'complete');

      const pin = await createPlexPin(config, {
        forwardUrl: completeUrl.toString(),
      });

      repo.createPinSession({
        id: sid,
        accountId: account.id,
        pinId: pin.id,
        code: pin.code,
        authUrl: pin.authUrl,
      });

      return reply.redirect(`/link/plex/pin?sid=${encodeURIComponent(sid)}&phase=launch`, 303);
    } catch (error) {
      request.log.error(error, 'Failed to start Plex PIN flow');
      return reply
        .code(502)
        .type('text/html; charset=utf-8')
        .send(linkPlexPage(account.username, 'Failed to create Plex PIN session. Try again.'));
    }
  });

  app.post('/account/plex/unlink', async (request, reply) => {
    const account = await requireWebSessionAccount(request, reply, repo);
    if (!account) {
      return;
    }

    repo.unlinkPlex(account.id);
    return reply.redirect('/link/plex?notice=Plex%20account%20unlinked');
  });

  app.post('/account/password', async (request, reply) => {
    const account = await requireWebSessionAccount(request, reply, repo);
    if (!account) {
      return;
    }

    const currentPassword = normalizePassword(request.body?.currentPassword);
    const newPassword = normalizePassword(request.body?.newPassword);
    const confirmPassword = normalizePassword(request.body?.confirmPassword);

    if (!currentPassword || !newPassword || !confirmPassword) {
      return reply.redirect('/link/plex?notice=All%20password%20fields%20are%20required');
    }

    if (newPassword.length < 8) {
      return reply.redirect('/link/plex?notice=New%20password%20must%20be%20at%20least%208%20characters');
    }

    if (newPassword !== confirmPassword) {
      return reply.redirect('/link/plex?notice=New%20password%20confirmation%20does%20not%20match');
    }

    const accountWithAuth = repo.getAccountByUsername(account.username);
    if (!accountWithAuth || accountWithAuth.enabled !== 1) {
      await request.session.destroy();
      return reply.redirect('/login?notice=Session%20expired');
    }

    const currentPasswordValid = await argon2.verify(accountWithAuth.password_hash, currentPassword);
    if (!currentPasswordValid) {
      return reply.redirect('/link/plex?notice=Current%20password%20is%20incorrect');
    }

    const passwordHash = await argon2.hash(newPassword, { type: argon2.argon2id });
    repo.updateAccountPassword({
      accountId: account.id,
      passwordHash,
      subsonicPasswordEnc: tokenCipher.encrypt(newPassword),
    });

    return reply.redirect('/link/plex?notice=Password%20updated');
  });

  app.get('/link/plex/pin', async (request, reply) => {
    const account = await requireWebSessionAccount(request, reply, repo);
    if (!account) {
      return;
    }

    const sid = getQueryString(request, 'sid');
    if (!sid) {
      return reply.redirect('/link/plex?notice=Missing%20PIN%20session');
    }

    const pinSession = repo.getPinSessionById(sid);
    if (!pinSession || pinSession.account_id !== account.id) {
      return reply.redirect('/link/plex?notice=PIN%20session%20not%20found');
    }

    const phaseRaw = getQueryString(request, 'phase');
    const phase = phaseRaw === 'complete' ? 'complete' : 'launch';

    return reply
      .type('text/html; charset=utf-8')
      .send(
        plexPinPage({
          sid,
          authUrl: pinSession.auth_url,
          phase,
        }),
      );
  });

  app.get('/link/plex/poll', async (request, reply) => {
    const account = await requireWebSessionAccount(request, reply, repo);
    if (!account) {
      return;
    }

    const sid = getQueryString(request, 'sid');
    if (!sid) {
      return reply.code(400).send({ status: 'error', message: 'Missing sid' });
    }

    const pinSession = repo.getPinSessionById(sid);
    if (!pinSession || pinSession.account_id !== account.id) {
      return reply.code(404).send({ status: 'error', message: 'PIN session not found' });
    }

    if (pinSession.status === 'linked') {
      return reply.send({ status: 'linked', next: '/link/plex/server' });
    }

    if (pinSession.status === 'expired') {
      return reply.send({ status: 'expired' });
    }

    repo.updatePinSessionPollTime(sid);

    try {
      const pollResult = await pollPlexPin(config, {
        pinId: pinSession.pin_id,
        code: pinSession.code,
      });

      if (pollResult.authToken) {
        const encryptedToken = tokenCipher.encrypt(pollResult.authToken);
        repo.markPinLinkedAndStoreToken({
          pinSessionId: sid,
          accountId: account.id,
          encryptedToken,
        });

        return reply.send({ status: 'linked', next: '/link/plex/server' });
      }

      if (pollResult.expired) {
        repo.updatePinSessionStatus(sid, 'expired');
        return reply.send({ status: 'expired' });
      }

      return reply.send({ status: 'pending' });
    } catch (error) {
      request.log.error(error, 'Failed to poll Plex PIN session');
      return reply.code(502).send({ status: 'error', message: 'Plex PIN poll failed' });
    }
  });

  app.get('/link/plex/server', async (request, reply) => {
    const account = await requireWebSessionAccount(request, reply, repo);
    if (!account) {
      return;
    }

    const link = repo.getPlexLinkByAccountId(account.id);
    if (!link) {
      return reply.redirect('/link/plex?notice=Link%20Plex%20first');
    }

    let plexToken;
    try {
      plexToken = decodePlexTokenOrThrow(tokenCipher, link.plex_token_enc);
    } catch {
      return reply.redirect('/link/plex?notice=Stored%20Plex%20token%20is%20invalid');
    }

    try {
      const servers = await listPlexServers(config, plexToken);
      const selectedServer = repo.getSelectedServerByAccountId(account.id);

      const choices = servers.map((server) => ({
        ...server,
        encodedChoice: encodeChoicePayload(server),
      }));

      return reply
        .type('text/html; charset=utf-8')
        .send(
          plexServerPage({
            servers: choices,
            selectedMachineId: selectedServer?.machine_id ?? null,
            notice: getRouteNotice(request),
          }),
        );
    } catch (error) {
      request.log.error(error, 'Failed to list Plex servers');
      return reply
        .code(502)
        .type('text/html; charset=utf-8')
        .send(plexServerPage({ servers: [], notice: 'Failed to query Plex resources.' }));
    }
  });

  app.post('/link/plex/server', async (request, reply) => {
    const account = await requireWebSessionAccount(request, reply, repo);
    if (!account) {
      return;
    }

    const choice = decodeChoicePayload(getBodyString(request, 'serverChoice'));
    if (!choice?.machineId || !choice?.name || !choice?.baseUrl) {
      return reply.redirect('/link/plex/server?notice=Choose%20a%20valid%20server');
    }

    const encryptedServerToken =
      choice?.accessToken && typeof choice.accessToken === 'string'
        ? tokenCipher.encrypt(choice.accessToken)
        : null;

    repo.upsertSelectedServer({
      accountId: account.id,
      machineId: String(choice.machineId),
      name: String(choice.name),
      baseUrl: String(choice.baseUrl),
      encryptedServerToken,
    });

    return reply.redirect('/link/plex/library');
  });

  app.get('/link/plex/library', async (request, reply) => {
    const account = await requireWebSessionAccount(request, reply, repo);
    if (!account) {
      return;
    }

    const plexLink = repo.getPlexLinkByAccountId(account.id);
    if (!plexLink) {
      return reply.redirect('/link/plex?notice=Link%20Plex%20first');
    }

    const selectedServer = repo.getSelectedServerByAccountId(account.id);
    if (!selectedServer) {
      return reply.redirect('/link/plex/server?notice=Select%20a%20server%20first');
    }

    let plexToken;
    try {
      plexToken = decodePlexTokenOrThrow(tokenCipher, plexLink.plex_token_enc);
    } catch {
      return reply.redirect('/link/plex?notice=Stored%20Plex%20token%20is%20invalid');
    }

    let selectedServerToken = null;
    if (selectedServer.server_token_enc) {
      try {
        selectedServerToken = decodePlexTokenOrThrow(tokenCipher, selectedServer.server_token_enc);
      } catch { }
    }

    try {
      let baseUrlForQuery = selectedServer.base_url;
      let sections;
      let recoveredBaseUrl = null;
      const tryListSections = async (candidateBaseUrl, candidateToken) => {
        if (!candidateBaseUrl || !candidateToken) {
          return null;
        }
        const listed = await listMusicSections({
          baseUrl: candidateBaseUrl,
          plexToken: candidateToken,
        });
        return Array.isArray(listed) ? listed : [];
      };

      let directError = null;
      try {
        sections = await tryListSections(baseUrlForQuery, selectedServerToken || plexToken);
      } catch (error) {
        directError = error;
      }

      if (!Array.isArray(sections) || sections.length === 0) {
        request.log.warn(
          {
            err: directError,
            baseUrl: baseUrlForQuery,
            machineId: selectedServer.machine_id,
          },
          'Music section query failed or returned no results on stored server URL. Attempting recovery from Plex resources.',
        );

        const resources = await listPlexServers(config, plexToken);
        const matched = resources.find((resource) => resource.machineId === selectedServer.machine_id);
        if (matched) {
          const candidateUrls = uniqueNonEmptyValues([
            baseUrlForQuery,
            matched.baseUrl,
            ...((Array.isArray(matched.connectionUris) ? matched.connectionUris : [])),
          ]);
          const candidateTokens = uniqueNonEmptyValues([matched.accessToken, selectedServerToken, plexToken]);

          let recoveredSections = null;
          let lastRecoveryError = directError;
          for (const candidateToken of candidateTokens) {
            for (const candidateUrl of candidateUrls) {
              try {
                const listed = await tryListSections(candidateUrl, candidateToken);
                if (!Array.isArray(listed) || listed.length === 0) {
                  continue;
                }
                recoveredSections = listed;
                if (candidateUrl !== baseUrlForQuery) {
                  baseUrlForQuery = candidateUrl;
                  recoveredBaseUrl = candidateUrl;
                }
                break;
              } catch (error) {
                lastRecoveryError = error;
              }
            }
            if (recoveredSections) {
              break;
            }
          }

          if (recoveredSections) {
            sections = recoveredSections;
            if (baseUrlForQuery !== selectedServer.base_url || matched.accessToken) {
              const encryptedServerToken = matched.accessToken
                ? tokenCipher.encrypt(String(matched.accessToken))
                : selectedServer.server_token_enc || null;
              repo.upsertSelectedServer({
                accountId: account.id,
                machineId: selectedServer.machine_id,
                name: matched.name || selectedServer.name,
                baseUrl: baseUrlForQuery,
                encryptedServerToken,
              });
            }
          } else if (lastRecoveryError) {
            throw lastRecoveryError;
          }
        } else if (directError) {
          throw directError;
        }
      }

      if (!Array.isArray(sections)) {
        sections = [];
      }

      const selectedLibrary = repo.getSelectedLibraryByAccountId(account.id);
      const choices = sections.map((section) => ({
        ...section,
        encodedChoice: encodeChoicePayload(section),
      }));
      const requestNotice = getRouteNotice(request);
      const noticeText = (() => {
        if (recoveredBaseUrl != null) {
          return `Recovered server URL automatically: ${recoveredBaseUrl}`;
        }
        if (sections.length === 0) {
          return requestNotice || 'No accessible music libraries found for this Plex account on the selected server.';
        }
        return requestNotice;
      })();

      return reply
        .type('text/html; charset=utf-8')
        .send(
          plexLibraryPage({
            sections: choices,
            selectedSectionId: selectedLibrary?.music_section_id ?? null,
            notice: noticeText,
          }),
        );
    } catch (error) {
      request.log.error(error, 'Failed to list Plex music sections');
      return reply
        .code(502)
        .type('text/html; charset=utf-8')
        .send(plexLibraryPage({ sections: [], notice: 'Failed to query library sections.' }));
    }
  });

  app.post('/link/plex/library', async (request, reply) => {
    const account = await requireWebSessionAccount(request, reply, repo);
    if (!account) {
      return;
    }

    const choice = decodeChoicePayload(getBodyString(request, 'libraryChoice'));
    if (!choice?.id) {
      return reply.redirect('/link/plex/library?notice=Choose%20a%20valid%20library');
    }

    repo.upsertSelectedLibrary({
      accountId: account.id,
      musicSectionId: String(choice.id),
      musicSectionName: choice.title ? String(choice.title) : null,
    });

    const context = repo.getAccountPlexContext(account.id);
    const plexState = buildPlexStateFromContext(context, tokenCipher);
    if (plexState) {
      warmLibraryCacheForAccount({
        accountId: account.id,
        plexState,
        reason: 'library-selected',
        request,
        forceRefresh: true,
      }).catch((error) => {
        request.log.warn(error, 'Library cache warm-up after library selection failed');
      });
    }

    return reply.redirect('/test');
  });

  app.get('/test', async (request, reply) => {
    const account = await requireWebSessionAccount(request, reply, repo);
    if (!account) {
      return;
    }

    const context = repo.getAccountPlexContext(account.id);
    if (!context?.plex_token_enc) {
      return reply.redirect('/link/plex?notice=Link%20Plex%20first');
    }

    if (!context.server_base_url) {
      return reply.redirect('/link/plex/server?notice=Select%20server%20first');
    }

    if (!context.music_section_id) {
      return reply.redirect('/link/plex/library?notice=Select%20library%20first');
    }

    return reply
      .type('text/html; charset=utf-8')
      .send(testPage({ username: account.username }));
  });

  app.get('/done', async (_request, reply) => {
    return reply.redirect('/test', 303);
  });

  app.get('/rest/getOpenSubsonicExtensions.view', async (_request, reply) => {
    return sendSubsonicOk(
      reply,
      {
        openSubsonicExtensions: [
          {
          name: 'songLyrics',
          versions: [1],
          },
        ],
      },
    );
  });

  app.get('/rest/getLicense.view', async (_request, reply) => {
    const attrs = {
      valid: true,
      licenseExpires: '2099-12-31T23:59:59',
    };

    if (config.licenseEmail) {
      attrs.email = config.licenseEmail;
    }

    return sendSubsonicOk(
      reply,
      { license: attrs },
    );
  });

  app.get('/rest/ping.view', async (request, reply) => {
    const account = await authenticateSubsonicRequest(request, reply, repo, tokenCipher);
    if (!account) {
      return;
    }

    return sendSubsonicOk(reply, { ping: {} });
  });

  app.get('/rest/getMusicFolders.view', async (request, reply) => {
    const account = await authenticateSubsonicRequest(request, reply, repo, tokenCipher);
    if (!account) {
      return;
    }

    const context = repo.getAccountPlexContext(account.id);
    const plexState = requiredPlexStateForSubsonic(reply, context, tokenCipher);
    if (!plexState) {
      return;
    }

    const rawSectionId = String(plexState.musicSectionId || '').trim();
    const musicFolderId = /^\d+$/.test(rawSectionId) ? Number(rawSectionId) : rawSectionId;
    const musicFolderName =
      String(plexState.musicSectionName || '').trim() ||
      String(plexState.serverName || '').trim() ||
      'Music';

    const inner = {
      musicFolders: [
        { id: musicFolderId, name: musicFolderName },
      ],
    };
    return sendSubsonicOk(reply, inner);
  });

  app.get('/rest/getUser.view', async (request, reply) => {
    const account = await authenticateSubsonicRequest(request, reply, repo, tokenCipher);
    if (!account) {
      return;
    }

    return sendSubsonicOk(
      reply,
      { user: {
        username: account.username,
        email: config.licenseEmail || undefined,
        scrobblingEnabled: true,
        adminRole: true,
        settingsRole: true,
        downloadRole: true,
        uploadRole: false,
        playlistRole: true,
        coverArtRole: true,
        commentRole: false,
        podcastRole: false,
        streamRole: true,
        jukeboxRole: false,
        shareRole: false,
        videoConversionRole: false,
      } },
    );
  });

  app.get('/rest/getNowPlaying.view', async (request, reply) => {
    const account = await authenticateSubsonicRequest(request, reply, repo, tokenCipher);
    if (!account) {
      return;
    }

    const context = repo.getAccountPlexContext(account.id);
    const plexState = requiredPlexStateForSubsonic(reply, context, tokenCipher);
    if (!plexState) {
      return;
    }

    try {
      const sessions = [...playbackSessions.values()]
        .filter((session) =>
          session &&
          session.accountId === account.id &&
          session.itemId &&
          session.state !== 'stopped',
        )
        .sort((a, b) => Number(b.updatedAt || 0) - Number(a.updatedAt || 0));

      if (sessions.length === 0) {
        return sendSubsonicOk(reply, { nowPlaying: [] });
      }

      const dedupedByItemId = new Map();
      for (const session of sessions) {
        const itemId = String(session.itemId || '').trim();
        if (itemId && !dedupedByItemId.has(itemId)) {
          dedupedByItemId.set(itemId, session);
        }
      }

      const itemIds = [...dedupedByItemId.keys()];
      const tracks = await resolveTracksByIdOrder({
        accountId: account.id,
        plexState,
        request,
        ids: itemIds,
      });

      const sessionByTrackId = new Map(
        [...dedupedByItemId.entries()].map(([id, session]) => [id, session]),
      );
      const entries = tracks
        .map((track) => {
          const trackId = String(track?.ratingKey || '').trim();
          const session = sessionByTrackId.get(trackId);
          const minutesAgo = Math.max(
            0,
            Math.floor((Date.now() - Number(session?.updatedAt || Date.now())) / 60000),
          );
          return {
            ...songAttrs(track),
            username: account.username,
            playerId: session?.clientIdentifier || undefined,
            minutesAgo,
          };
        });

      return sendSubsonicOk(reply, { nowPlaying: entries });
    } catch (error) {
      request.log.error(error, 'Failed to load now playing entries');
      return sendSubsonicError(reply, 10, 'Failed to load now playing');
    }
  });

  app.get('/rest/getScanStatus.view', async (request, reply) => {
    const account = await authenticateSubsonicRequest(request, reply, repo, tokenCipher);
    if (!account) {
      return;
    }

    const context = repo.getAccountPlexContext(account.id);
    const plexState = requiredPlexStateForSubsonic(reply, context, tokenCipher);
    if (!plexState) {
      return;
    }

    try {
      const section = await getMusicSectionScanStatus(plexState);
      return sendSubsonicOk(
        reply,
        { scanStatus: scanStatusAttrsFromSection(section) },
      );
    } catch (error) {
      request.log.error(error, 'Failed to load scan status from Plex');
      return sendSubsonicError(reply, 10, 'Failed to load scan status');
    }
  });

  app.get('/rest/startScan.view', async (request, reply) => {
    const account = await authenticateSubsonicRequest(request, reply, repo, tokenCipher);
    if (!account) {
      return;
    }

    const context = repo.getAccountPlexContext(account.id);
    const plexState = requiredPlexStateForSubsonic(reply, context, tokenCipher);
    if (!plexState) {
      return;
    }

    try {
      await startPlexSectionScan({
        baseUrl: plexState.baseUrl,
        plexToken: plexState.plexToken,
        sectionId: plexState.musicSectionId,
        force: true,
      });

      markSearchBrowseCacheDirty(searchBrowseCacheKey(account.id, plexState));

      const section = await getMusicSectionScanStatus(plexState);
      return sendSubsonicOk(
        reply,
        { scanStatus: scanStatusAttrsFromSection(section, { fallbackScanning: true }) },
      );
    } catch (error) {
      request.log.error(error, 'Failed to trigger Plex scan');
      return sendSubsonicError(reply, 10, 'Failed to trigger scan');
    }
  });

  app.get('/rest/getStarred.view', async (request, reply) => {
    const account = await authenticateSubsonicRequest(request, reply, repo, tokenCipher);
    if (!account) {
      return;
    }

    const context = repo.getAccountPlexContext(account.id);
    const plexState = requiredPlexStateForSubsonic(reply, context, tokenCipher);
    if (!plexState) {
      return;
    }

    try {
      const [artists, albums, tracks] = await Promise.all([
        getCachedLibraryArtists({ accountId: account.id, plexState, request }),
        getCachedLibraryAlbums({ accountId: account.id, plexState, request }),
        getCachedLibraryTracks({ accountId: account.id, plexState, request }),
      ]);

      const starredArtists = artists
        .filter((artist) => isPlexLiked(artist.userRating))
        .map((artist) => ({
          id: artist.ratingKey,
          name: artist.title,
          coverArt: artist.ratingKey,
          ...subsonicRatingAttrs(artist),
        }));

      const starredAlbums = albums
        .filter((album) => isPlexLiked(album.userRating))
        .map((album) => albumJson(album, albumAttrs(album)));

      const starredSongs = tracks
        .filter((track) => isPlexLiked(track.userRating))
        .map((track) => songJson(track));

      return sendSubsonicOk(reply, {
        starred: {
          artist: starredArtists,
          album: starredAlbums,
          song: starredSongs,
        },
      });
    } catch (error) {
      request.log.error(error, 'Failed to load starred items');
      return sendSubsonicError(reply, 10, 'Failed to load starred items');
    }
  });

  app.get('/rest/getStarred2.view', async (request, reply) => {
    const account = await authenticateSubsonicRequest(request, reply, repo, tokenCipher);
    if (!account) {
      return;
    }

    const context = repo.getAccountPlexContext(account.id);
    const plexState = requiredPlexStateForSubsonic(reply, context, tokenCipher);
    if (!plexState) {
      return;
    }

    try {
      const [artists, albums, tracks] = await Promise.all([
        getCachedLibraryArtists({ accountId: account.id, plexState, request }),
        getCachedLibraryAlbums({ accountId: account.id, plexState, request }),
        getCachedLibraryTracks({ accountId: account.id, plexState, request }),
      ]);

      const starredArtists = artists
        .filter((artist) => isPlexLiked(artist.userRating))
        .map((artist) => ({
          id: artist.ratingKey,
          name: artist.title,
          albumCount: artistAlbumCountValue(artist),
          coverArt: artist.ratingKey,
          ...subsonicRatingAttrs(artist),
        }));

      const starredAlbums = albums
        .filter((album) => isPlexLiked(album.userRating))
        .map((album) => albumJson(album, albumId3Attrs(album)));

      const starredSongs = tracks
        .filter((track) => isPlexLiked(track.userRating))
        .map((track) => songJson(track));

      return sendSubsonicOk(reply, {
        starred2: {
          artist: starredArtists,
          album: starredAlbums,
          song: starredSongs,
        },
      });
    } catch (error) {
      request.log.error(error, 'Failed to load starred items');
      return sendSubsonicError(reply, 10, 'Failed to load starred items');
    }
  });

  app.route({
    method: ['GET', 'POST'],
    url: '/rest/getGenres.view',
    async handler(request, reply) {
      const account = await authenticateSubsonicRequest(request, reply, repo, tokenCipher);
      if (!account) {
        return;
      }

      const context = repo.getAccountPlexContext(account.id);
      const plexState = requiredPlexStateForSubsonic(reply, context, tokenCipher);
      if (!plexState) {
        return;
      }

      try {
        const genreItems = await queryGenreSummaries({
          accountId: account.id,
          plexState,
          request,
        });
        return sendSubsonicOk(reply, { genres: genreItems });
      } catch (error) {
        request.log.error(error, 'Failed to load genres');
        return sendSubsonicError(reply, 10, 'Failed to load genres');
      }
    },
  });

  app.route({
    method: ['GET', 'POST'],
    url: '/rest/getSongsByGenre.view',
    async handler(request, reply) {
      const account = await authenticateSubsonicRequest(request, reply, repo, tokenCipher);
      if (!account) {
        return;
      }

      const genre = String(getRequestParam(request, 'genre') || '').trim();
      const count = Math.min(parsePositiveInt(getRequestParam(request, 'count'), 50), 500);
      const offset = parseNonNegativeInt(getRequestParam(request, 'offset'), 0);

      if (!genre) {
        return sendSubsonicError(reply, 70, 'Missing genre');
      }

      const context = repo.getAccountPlexContext(account.id);
      const plexState = requiredPlexStateForSubsonic(reply, context, tokenCipher);
      if (!plexState) {
        return;
      }

      try {
        const { total, items } = await queryTracksByGenre({
          accountId: account.id,
          plexState,
          request,
          genre,
          count,
          offset,
        });
        reply.header('x-total-count', String(total));
        const songs = items.map((track) => songJson(track));
        return sendSubsonicOk(reply, { songsByGenre: songs });
      } catch (error) {
        request.log.error(error, 'Failed to load songs by genre');
        return sendSubsonicError(reply, 10, 'Failed to load songs by genre');
      }
    },
  });

  app.get('/rest/getRandomSongs.view', async (request, reply) => {
    const account = await authenticateSubsonicRequest(request, reply, repo, tokenCipher);
    if (!account) {
      return;
    }

    const size = Math.min(parsePositiveInt(getQueryString(request, 'size'), 50), 500);

    const context = repo.getAccountPlexContext(account.id);
    const plexState = requiredPlexStateForSubsonic(reply, context, tokenCipher);
    if (!plexState) {
      return;
    }

    try {
      const allTracks = await getCachedLibraryTracks({ accountId: account.id, plexState, request });

      const randomTracks = shuffleInPlace(allTracks.slice()).slice(0, size);
      const songs = randomTracks.map((track) => songJson(track));
      return sendSubsonicOk(reply, { randomSongs: songs });
    } catch (error) {
      request.log.error(error, 'Failed to load random songs');
      return sendSubsonicError(reply, 10, 'Failed to load random songs');
    }
  });

  app.get('/rest/getTopSongs.view', async (request, reply) => {
    const account = await authenticateSubsonicRequest(request, reply, repo, tokenCipher);
    if (!account) {
      return;
    }

    const artistName = getQueryString(request, 'artist');
    const size = Math.min(parsePositiveInt(getQueryString(request, 'count'), 50), 500);
    if (!artistName) {
      return sendSubsonicError(reply, 70, 'Missing artist');
    }

    const context = repo.getAccountPlexContext(account.id);
    const plexState = requiredPlexStateForSubsonic(reply, context, tokenCipher);
    if (!plexState) {
      return;
    }

    try {
      const artists = await getCachedLibraryArtists({ accountId: account.id, plexState, request });

      const artist =
        artists.find((item) => safeLower(item.title) === safeLower(artistName)) ||
        artists.find((item) => includesText(item.title, artistName));
      if (!artist) {
        return sendSubsonicOk(reply, { topSongs: [] });
      }

      const tracks = await listArtistTracks({
        baseUrl: plexState.baseUrl,
        plexToken: plexState.plexToken,
        artistId: artist.ratingKey,
      });
      applyCachedRatingOverridesForAccount({ accountId: account.id, plexState, items: tracks });

      const topTracks = tracks.slice(0, size);
      const songs = topTracks.map((track) => songJson(track));
      return sendSubsonicOk(reply, { topSongs: songs });
    } catch (error) {
      request.log.error(error, 'Failed to load top songs');
      return sendSubsonicError(reply, 10, 'Failed to load top songs');
    }
  });

  async function resolveSimilarSongsSeed({ baseUrl, plexToken, id, preferArtistId = false }) {
    const rawId = String(id || '').trim();
    if (!rawId) {
      return { artistId: null, excludedTrackId: null };
    }

    const tryTrackFirst = !preferArtistId;
    if (tryTrackFirst) {
      const track = await getTrack({
        baseUrl,
        plexToken,
        trackId: rawId,
      });
      if (track?.grandparentRatingKey) {
        return {
          artistId: String(track.grandparentRatingKey),
          excludedTrackId: String(track.ratingKey || ''),
        };
      }
    }

    const artist = await getArtist({
      baseUrl,
      plexToken,
      artistId: rawId,
    });
    if (artist?.ratingKey) {
      return { artistId: String(artist.ratingKey), excludedTrackId: null };
    }

    const album = await getAlbum({
      baseUrl,
      plexToken,
      albumId: rawId,
    });
    if (album?.parentRatingKey) {
      return { artistId: String(album.parentRatingKey), excludedTrackId: null };
    }

    if (preferArtistId) {
      const track = await getTrack({
        baseUrl,
        plexToken,
        trackId: rawId,
      });
      if (track?.grandparentRatingKey) {
        return {
          artistId: String(track.grandparentRatingKey),
          excludedTrackId: String(track.ratingKey || ''),
        };
      }
    }

    return { artistId: null, excludedTrackId: null };
  }

  async function loadSimilarSongsFromPlex({ plexState, id, count, preferArtistId = false }) {
    const seed = await resolveSimilarSongsSeed({
      baseUrl: plexState.baseUrl,
      plexToken: plexState.plexToken,
      id,
      preferArtistId,
    });

    if (!seed.artistId) {
      return null;
    }

    const tracks = await listArtistTracks({
      baseUrl: plexState.baseUrl,
      plexToken: plexState.plexToken,
      artistId: seed.artistId,
    });

    const filtered = tracks.filter((track) => String(track?.ratingKey || '') !== seed.excludedTrackId);
    return shuffleInPlace(filtered.slice()).slice(0, count);
  }

  app.route({
    method: ['GET', 'POST'],
    url: '/rest/getSimilarSongs.view',
    async handler(request, reply) {
      const account = await authenticateSubsonicRequest(request, reply, repo, tokenCipher);
      if (!account) {
        return;
      }

      const id = getRequestParam(request, 'id');
      if (!id) {
        return sendSubsonicError(reply, 70, 'Missing id');
      }

      const count = Math.min(parsePositiveInt(getRequestParam(request, 'count'), 50), 500);

      const context = repo.getAccountPlexContext(account.id);
      const plexState = requiredPlexStateForSubsonic(reply, context, tokenCipher);
      if (!plexState) {
        return;
      }

      try {
        const tracks = await loadSimilarSongsFromPlex({
          plexState,
          id,
          count,
          preferArtistId: false,
        });

        if (tracks == null) {
          return sendSubsonicError(reply, 70, 'Item not found');
        }
        applyCachedRatingOverridesForAccount({ accountId: account.id, plexState, items: tracks });

        const songs = tracks.map((track) => songJson(track));
        return sendSubsonicOk(reply, { similarSongs: songs });
      } catch (error) {
        request.log.error(error, 'Failed to load similar songs');
        return sendSubsonicError(reply, 10, 'Failed to load similar songs');
      }
    },
  });

  app.route({
    method: ['GET', 'POST'],
    url: '/rest/getSimilarSongs2.view',
    async handler(request, reply) {
      const account = await authenticateSubsonicRequest(request, reply, repo, tokenCipher);
      if (!account) {
        return;
      }

      const id = getRequestParam(request, 'id');
      if (!id) {
        return sendSubsonicError(reply, 70, 'Missing id');
      }

      const count = Math.min(parsePositiveInt(getRequestParam(request, 'count'), 50), 500);

      const context = repo.getAccountPlexContext(account.id);
      const plexState = requiredPlexStateForSubsonic(reply, context, tokenCipher);
      if (!plexState) {
        return;
      }

      try {
        const tracks = await loadSimilarSongsFromPlex({
          plexState,
          id,
          count,
          preferArtistId: true,
        });

        if (tracks == null) {
          return sendSubsonicError(reply, 70, 'Item not found');
        }
        applyCachedRatingOverridesForAccount({ accountId: account.id, plexState, items: tracks });

        const songs = tracks.map((track) => songJson(track));
        return sendSubsonicOk(reply, { similarSongs2: songs });
      } catch (error) {
        request.log.error(error, 'Failed to load similar songs2');
        return sendSubsonicError(reply, 10, 'Failed to load similar songs');
      }
    },
  });

  app.get('/rest/getSong.view', async (request, reply) => {
    const account = await authenticateSubsonicRequest(request, reply, repo, tokenCipher);
    if (!account) {
      return;
    }

    const rawId = String(getRequestParam(request, 'id') || '').trim();
    if (!rawId) {
      return sendSubsonicError(reply, 70, 'Missing song id');
    }

    const context = repo.getAccountPlexContext(account.id);
    const plexState = requiredPlexStateForSubsonic(reply, context, tokenCipher);
    if (!plexState) {
      return;
    }

    try {
      const resolvedTrackId = await resolveCachedLibraryRatingKey({
        accountId: account.id,
        plexState,
        request,
        collection: 'tracks',
        id: rawId,
      }) || rawId;
      let track = await getTrack({
        baseUrl: plexState.baseUrl,
        plexToken: plexState.plexToken,
        trackId: resolvedTrackId,
      });
      if (!track) {
        track = await resolveTrackFromCachedLibrary({
          accountId: account.id,
          plexState,
          request,
          trackId: rawId,
        });
      }
      if (!track) {
        return sendSubsonicError(reply, 70, 'Song not found');
      }

      if (!firstGenreTag(track)) {
        const albumId = String(track?.parentRatingKey || '').trim();
        if (albumId) {
          try {
            const album = await getAlbum({
              baseUrl: plexState.baseUrl,
              plexToken: plexState.plexToken,
              albumId,
            });
            if (album) {
              const albumGenreTagMap = buildAlbumGenreTagMap([album]);
              track = withResolvedTrackGenres(track, albumGenreTagMap);
            }
          } catch (error) {
            request.log.debug(error, 'Failed to enrich song genre from album metadata');
          }
        }
      }
      applyCachedRatingOverridesForAccount({ accountId: account.id, plexState, items: [track] });

      return sendSubsonicOk(reply, { song: songAttrs(track) });
    } catch (error) {
      request.log.error(error, 'Failed to load song');
      return sendSubsonicError(reply, 10, 'Failed to load song');
    }
  });

  app.route({
    method: ['GET', 'POST'],
    url: '/rest/getLyrics.view',
    async handler(request, reply) {
      const account = await authenticateSubsonicRequest(request, reply, repo, tokenCipher);
      if (!account) {
        return;
      }

      const artistQuery = String(getRequestParam(request, 'artist') || '').trim();
      const titleQuery = String(getRequestParam(request, 'title') || '').trim();
      const query = `${artistQuery} ${titleQuery}`.trim();
      if (!query) {
        return sendSubsonicOk(reply, { lyrics: {} });
      }

      const context = repo.getAccountPlexContext(account.id);
      const plexState = requiredPlexStateForSubsonic(reply, context, tokenCipher);
      if (!plexState) {
        return;
      }
      const searchScope = beginSearchRequest(request, account.id);

      try {
        const { tracks } = await runPlexSearch({
          plexState,
          query,
          artistWindow: 1,
          albumWindow: 1,
          songWindow: 50,
          signal: searchScope.signal,
        });

        let matchedTrack = tracks.find((track) => {
          const titleMatches = titleQuery ? includesText(track?.title, titleQuery) : true;
          const artistMatches = artistQuery ? includesText(track?.grandparentTitle, artistQuery) : true;
          return titleMatches && artistMatches;
        });

        if (!matchedTrack) {
          matchedTrack = tracks[0] || null;
        }

        if (!matchedTrack) {
          return sendSubsonicOk(
            reply,
            { lyrics: {
              artist: artistQuery || undefined,
              title: titleQuery || undefined,
              value: '',
            } },
          );
        }

        const matchedTrackId = String(matchedTrack.ratingKey || '').trim();
        let lyricsTrack = matchedTrack;
        if (matchedTrackId) {
          const loadedTrack = await getTrack({
            baseUrl: plexState.baseUrl,
            plexToken: plexState.plexToken,
            trackId: matchedTrackId,
            signal: searchScope.signal,
          });
          if (loadedTrack) {
            lyricsTrack = loadedTrack;
          }
        }

        const lyricCandidates = matchedTrackId
          ? await fetchPlexTrackLyricsCandidates({
            baseUrl: plexState.baseUrl,
            plexToken: plexState.plexToken,
            trackId: matchedTrackId,
            signal: searchScope.signal,
          })
          : [];

        const plainLyrics = buildPlainLyricsFromStructuredLyrics(
          extractStructuredLyricsFromTrack(lyricsTrack, lyricCandidates),
        );
        const finalArtist = firstNonEmptyText(
          [plainLyrics.artist, lyricsTrack.grandparentTitle, artistQuery],
          undefined,
        );
        const finalTitle = firstNonEmptyText(
          [plainLyrics.title, lyricsTrack.title, titleQuery],
          undefined,
        );

        return sendSubsonicOk(
          reply,
          { lyrics: {
            artist: finalArtist,
            title: finalTitle,
            value: plainLyrics.value,
          } },
        );
      } catch (error) {
        if (isAbortError(error)) {
          const reason = String(searchScope.reason() || '');
          if (
            reason === 'superseded' &&
            !reply.sent &&
            !request.raw.destroyed &&
            !request.raw.aborted
          ) {
            return sendSubsonicError(reply, 10, 'Request canceled');
          }
          return;
        }
        request.log.error(error, 'Failed to load lyrics by artist/title');
        return sendSubsonicError(reply, 10, 'Failed to load lyrics');
      } finally {
        searchScope.cleanup();
      }
    },
  });

  app.route({
    method: ['GET', 'POST'],
    url: '/rest/getLyricsBySongId.view',
    async handler(request, reply) {
      const account = await authenticateSubsonicRequest(request, reply, repo, tokenCipher);
      if (!account) {
        return;
      }

      const rawId = String(getRequestParam(request, 'id') || '').trim();
      if (!rawId) {
        return sendSubsonicError(reply, 10, 'Required parameter is missing');
      }

      const context = repo.getAccountPlexContext(account.id);
      const plexState = requiredPlexStateForSubsonic(reply, context, tokenCipher);
      if (!plexState) {
        return;
      }
      const lyricsScope = beginSearchRequest(request, account.id);

      try {
        const resolvedTrackId = await resolveCachedLibraryRatingKey({
          accountId: account.id,
          plexState,
          request,
          collection: 'tracks',
          id: rawId,
        }) || rawId;
        const track = await getTrack({
          baseUrl: plexState.baseUrl,
          plexToken: plexState.plexToken,
          trackId: resolvedTrackId,
          signal: lyricsScope.signal,
        });

        if (!track) {
          return sendSubsonicError(reply, 70, 'Song not found');
        }

        const lyricCandidates = await fetchPlexTrackLyricsCandidates({
          baseUrl: plexState.baseUrl,
          plexToken: plexState.plexToken,
          trackId: resolvedTrackId,
          signal: lyricsScope.signal,
        });

        const structuredLyrics = extractStructuredLyricsFromTrack(track, lyricCandidates);
        const structuredLyricsItems = structuredLyrics
          .map((lyrics) => ({
            displayArtist: lyrics.displayArtist,
            displayTitle: lyrics.displayTitle,
            lang: lyrics.lang,
            synced: lyrics.synced,
            offset: lyrics.offset,
            line: lyrics.lines.map((line) => ({
              start: line.start,
              value: line.value,
            })),
          }));

        return sendSubsonicOk(reply, { lyricsList: structuredLyricsItems });
      } catch (error) {
        if (isAbortError(error)) {
          const reason = String(lyricsScope.reason() || '');
          if (
            reason === 'superseded' &&
            !reply.sent &&
            !request.raw.destroyed &&
            !request.raw.aborted
          ) {
            return sendSubsonicError(reply, 10, 'Request canceled');
          }
          return;
        }
        request.log.error(error, 'Failed to load lyrics by song id');
        return sendSubsonicError(reply, 10, 'Failed to load lyrics');
      } finally {
        lyricsScope.cleanup();
      }
    },
  });

  app.route({
    method: ['GET', 'POST'],
    url: '/rest/search3.view',
    async handler(request, reply) {
      const account = await authenticateSubsonicRequest(request, reply, repo, tokenCipher);
      if (!account) {
        return;
      }

      const query = normalizeSearchQuery(getRequestParam(request, 'query'));
      const artistCount = parseSearchCount(getRequestParam(request, 'artistCount'), 20, 500);
      const artistOffset = parseNonNegativeInt(getRequestParam(request, 'artistOffset'), 0);
      const albumCount = parseSearchCount(getRequestParam(request, 'albumCount'), 20, 500);
      const albumOffset = parseNonNegativeInt(getRequestParam(request, 'albumOffset'), 0);
      const songCount = parseSearchCount(getRequestParam(request, 'songCount'), 20, 500);
      const songOffset = parseNonNegativeInt(getRequestParam(request, 'songOffset'), 0);
      const musicFolderId = String(getRequestParam(request, 'musicFolderId') || '').trim();

      const context = repo.getAccountPlexContext(account.id);
      const plexState = requiredPlexStateForSubsonic(reply, context, tokenCipher);
      if (!plexState) {
        return;
      }

      const hasValidMusicFolder =
        !musicFolderId ||
        musicFolderId === String(plexState.musicSectionId || '');
      if (!hasValidMusicFolder) {
        request.log.debug(
          { musicFolderId, expected: String(plexState.musicSectionId || '') },
          'Returning empty search3 for non-matching musicFolderId',
        );
        reply.header('x-total-artists', '0');
        reply.header('x-total-albums', '0');
        reply.header('x-total-songs', '0');
        reply.header('x-total-count', '0');
        return sendSubsonicOk(reply, {
          searchResult3: {
            artist: [],
            album: [],
            song: [],
          },
        });
      }

      const searchScope = beginSearchRequest(request, account.id);

      try {
        const [artistSearch, albumSearch, trackSearch] = await Promise.all([
          artistCount > 0
            ? queryArtistsBySearch({
              accountId: account.id,
              plexState,
              request,
              query,
              count: artistCount,
              offset: artistOffset,
            })
            : { total: 0, items: [] },
          albumCount > 0
            ? queryAlbumsBySearch({
              accountId: account.id,
              plexState,
              request,
              query,
              count: albumCount,
              offset: albumOffset,
            })
            : { total: 0, items: [] },
          songCount > 0
            ? queryTracksBySearch({
              accountId: account.id,
              plexState,
              request,
              query,
              count: songCount,
              offset: songOffset,
            })
            : { total: 0, items: [] },
        ]);

        let matchedArtists = artistSearch.items;
        const matchedAlbums = albumSearch.items;
        const matchedTracks = trackSearch.items;

        if (query && artistCount > 0 && matchedArtists.length === 0) {
          const fallbackTracks = await queryTracksBySearch({
            accountId: account.id,
            plexState,
            request,
            query,
            count: Math.min(500, Math.max(artistCount * 10, 100)),
            offset: 0,
          });
          const virtualArtists = deriveVirtualArtistsFromTracks(fallbackTracks.items, query);
          matchedArtists = takePage(virtualArtists, artistOffset, artistCount);
        }

        reply.header('x-total-artists', String(artistSearch.total));
        reply.header('x-total-albums', String(albumSearch.total));
        reply.header('x-total-songs', String(trackSearch.total));
        reply.header('x-total-count', String(trackSearch.total));

        const artistItems = matchedArtists
          .map((artist) => ({
            id: artist.ratingKey,
            name: artist.title,
            albumCount: artistAlbumCountValue(artist),
            coverArt: firstNonEmptyText([artist?.thumb, artist?.ratingKey], undefined),
            ...subsonicRatingAttrs(artist),
          }));
        const albumItems = matchedAlbums
          .map((album) => albumJson(album, albumId3Attrs(album)));
        const songItems = matchedTracks
          .map((track) => songJson(track));

        const searchResult3 = {
          artist: artistItems,
          album: albumItems,
          song: songItems,
        };
        return sendSubsonicOk(reply, { searchResult3 });
      } catch (error) {
        if (isAbortError(error)) {
          const reason = String(searchScope.reason() || '');
          if (
            reason === 'superseded' &&
            !reply.sent &&
            !request.raw.destroyed &&
            !request.raw.aborted
          ) {
            return sendSubsonicError(reply, 10, 'Request canceled');
          }
          return;
        }
        request.log.error(error, 'Failed to perform search3');
        return sendSubsonicError(reply, 10, 'Failed to perform search');
      } finally {
        searchScope.cleanup();
      }
    },
  });

  app.route({
    method: ['GET', 'POST'],
    url: '/rest/search2.view',
    async handler(request, reply) {
      const account = await authenticateSubsonicRequest(request, reply, repo, tokenCipher);
      if (!account) {
        return;
      }

      const query = normalizeSearchQuery(getRequestParam(request, 'query'));
      const artistCount = parseSearchCount(getRequestParam(request, 'artistCount'), 20, 500);
      const artistOffset = parseNonNegativeInt(getRequestParam(request, 'artistOffset'), 0);
      const albumCount = parseSearchCount(getRequestParam(request, 'albumCount'), 20, 500);
      const albumOffset = parseNonNegativeInt(getRequestParam(request, 'albumOffset'), 0);
      const songCount = parseSearchCount(getRequestParam(request, 'songCount'), 20, 500);
      const songOffset = parseNonNegativeInt(getRequestParam(request, 'songOffset'), 0);

      if (!query) {
        return sendSubsonicOk(reply, { searchResult2: {} });
      }

      const context = repo.getAccountPlexContext(account.id);
      const plexState = requiredPlexStateForSubsonic(reply, context, tokenCipher);
      if (!plexState) {
        return;
      }
      const searchScope = beginSearchRequest(request, account.id);

      try {
        const [artistSearch, albumSearch, trackSearch] = await Promise.all([
          artistCount > 0
            ? queryArtistsBySearch({
              accountId: account.id,
              plexState,
              request,
              query,
              count: artistCount,
              offset: artistOffset,
            })
            : { total: 0, items: [] },
          albumCount > 0
            ? queryAlbumsBySearch({
              accountId: account.id,
              plexState,
              request,
              query,
              count: albumCount,
              offset: albumOffset,
            })
            : { total: 0, items: [] },
          songCount > 0
            ? queryTracksBySearch({
              accountId: account.id,
              plexState,
              request,
              query,
              count: songCount,
              offset: songOffset,
            })
            : { total: 0, items: [] },
        ]);

        let matchedArtists = artistSearch.items;
        const matchedAlbums = albumSearch.items;
        const matchedTracks = trackSearch.items;
        if (artistCount > 0 && matchedArtists.length === 0) {
          const fallbackTracks = await queryTracksBySearch({
            accountId: account.id,
            plexState,
            request,
            query,
            count: Math.min(500, Math.max(artistCount * 10, 100)),
            offset: 0,
          });
          const virtualArtists = deriveVirtualArtistsFromTracks(fallbackTracks.items, query);
          matchedArtists = takePage(virtualArtists, artistOffset, artistCount);
        }

        reply.header('x-total-artists', String(artistSearch.total));
        reply.header('x-total-albums', String(albumSearch.total));
        reply.header('x-total-songs', String(trackSearch.total));
        reply.header('x-total-count', String(trackSearch.total));

        const artistItems = matchedArtists
          .map((artist) => ({
            id: artist.ratingKey,
            name: artist.title,
            coverArt: firstNonEmptyText([artist?.thumb, artist?.ratingKey], undefined),
            ...subsonicRatingAttrs(artist),
          }));
        const albumItems = matchedAlbums
          .map((album) => albumJson(album, albumAttrs(album)));
        const songItems = matchedTracks
          .map((track) => songJson(track));

        const searchResult2 = {};
        assignNonEmptyBucket(searchResult2, 'artist', artistItems);
        assignNonEmptyBucket(searchResult2, 'album', albumItems);
        assignNonEmptyBucket(searchResult2, 'song', songItems);
        return sendSubsonicOk(reply, { searchResult2 });
      } catch (error) {
        if (isAbortError(error)) {
          const reason = String(searchScope.reason() || '');
          if (
            reason === 'superseded' &&
            !reply.sent &&
            !request.raw.destroyed &&
            !request.raw.aborted
          ) {
            return sendSubsonicError(reply, 10, 'Request canceled');
          }
          return;
        }
        request.log.error(error, 'Failed to perform search2');
        return sendSubsonicError(reply, 10, 'Failed to perform search');
      } finally {
        searchScope.cleanup();
      }
    },
  });

  app.route({
    method: ['GET', 'POST'],
    url: '/rest/search.view',
    async handler(request, reply) {
      const account = await authenticateSubsonicRequest(request, reply, repo, tokenCipher);
      if (!account) {
        return;
      }

      const query = normalizeSearchQuery(getRequestParam(request, 'query'));
      const artistCount = parseSearchCount(getRequestParam(request, 'artistCount'), 20, 500);
      const artistOffset = parseNonNegativeInt(getRequestParam(request, 'artistOffset'), 0);
      const albumCount = parseSearchCount(getRequestParam(request, 'albumCount'), 20, 500);
      const albumOffset = parseNonNegativeInt(getRequestParam(request, 'albumOffset'), 0);
      const songCount = parseSearchCount(getRequestParam(request, 'songCount'), 20, 500);
      const songOffset = parseNonNegativeInt(getRequestParam(request, 'songOffset'), 0);

      if (!query) {
        return sendSubsonicOk(reply, { searchResult: {} });
      }

      const context = repo.getAccountPlexContext(account.id);
      const plexState = requiredPlexStateForSubsonic(reply, context, tokenCipher);
      if (!plexState) {
        return;
      }
      const searchScope = beginSearchRequest(request, account.id);

      try {
        const [artistSearch, albumSearch, trackSearch] = await Promise.all([
          artistCount > 0
            ? queryArtistsBySearch({
              accountId: account.id,
              plexState,
              request,
              query,
              count: artistCount,
              offset: artistOffset,
            })
            : { total: 0, items: [] },
          albumCount > 0
            ? queryAlbumsBySearch({
              accountId: account.id,
              plexState,
              request,
              query,
              count: albumCount,
              offset: albumOffset,
            })
            : { total: 0, items: [] },
          songCount > 0
            ? queryTracksBySearch({
              accountId: account.id,
              plexState,
              request,
              query,
              count: songCount,
              offset: songOffset,
            })
            : { total: 0, items: [] },
        ]);

        let matchedArtists = artistSearch.items;
        const matchedAlbums = albumSearch.items;
        const matchedTracks = trackSearch.items;
        if (artistCount > 0 && matchedArtists.length === 0) {
          const fallbackTracks = await queryTracksBySearch({
            accountId: account.id,
            plexState,
            request,
            query,
            count: Math.min(500, Math.max(artistCount * 10, 100)),
            offset: 0,
          });
          const virtualArtists = deriveVirtualArtistsFromTracks(fallbackTracks.items, query);
          matchedArtists = takePage(virtualArtists, artistOffset, artistCount);
        }

        reply.header('x-total-artists', String(artistSearch.total));
        reply.header('x-total-albums', String(albumSearch.total));
        reply.header('x-total-songs', String(trackSearch.total));
        reply.header('x-total-count', String(trackSearch.total));

        const artistItems = matchedArtists
          .map((artist) => ({
            id: artist.ratingKey,
            name: artist.title,
            coverArt: firstNonEmptyText([artist?.thumb, artist?.ratingKey], undefined),
            ...subsonicRatingAttrs(artist),
          }));
        const albumItems = matchedAlbums
          .map((album) => albumJson(album, albumAttrs(album)));
        const matchItems = matchedTracks
          .map((track) => ({
            id: track.ratingKey,
            title: track.title,
            album: track.parentTitle,
            artist: trackPrimaryArtistName(track) || track.grandparentTitle,
          }));

        const searchResult = {};
        assignNonEmptyBucket(searchResult, 'artist', artistItems);
        assignNonEmptyBucket(searchResult, 'album', albumItems);
        assignNonEmptyBucket(searchResult, 'match', matchItems);
        return sendSubsonicOk(reply, { searchResult });
      } catch (error) {
        if (isAbortError(error)) {
          const reason = String(searchScope.reason() || '');
          if (
            reason === 'superseded' &&
            !reply.sent &&
            !request.raw.destroyed &&
            !request.raw.aborted
          ) {
            return sendSubsonicError(reply, 10, 'Request canceled');
          }
          return;
        }
        request.log.error(error, 'Failed to perform search');
        return sendSubsonicError(reply, 10, 'Failed to perform search');
      } finally {
        searchScope.cleanup();
      }
    },
  });

  app.get('/rest/getBookmarks.view', async (request, reply) => {
    const account = await authenticateSubsonicRequest(request, reply, repo, tokenCipher);
    if (!account) {
      return;
    }

    return sendSubsonicOk(reply, { bookmarks: {} });
  });

  app.get('/rest/getInternetRadioStations.view', async (request, reply) => {
    const account = await authenticateSubsonicRequest(request, reply, repo, tokenCipher);
    if (!account) {
      return;
    }

    return sendSubsonicOk(reply, { internetRadioStations: {} });
  });

  app.get('/rest/getPlayQueue.view', async (request, reply) => {
    const account = await authenticateSubsonicRequest(request, reply, repo, tokenCipher);
    if (!account) {
      return;
    }

    const context = repo.getAccountPlexContext(account.id);
    const plexState = requiredPlexStateForSubsonic(reply, context, tokenCipher);
    if (!plexState) {
      return;
    }

    pruneSavedPlayQueues();
    const queueKey = playQueueStorageKey(account.id, request);
    const queueState = savedPlayQueues.get(queueKey) || {
      ids: [],
      current: '',
      position: 0,
      updatedAt: Date.now(),
    };

    try {
      const effectiveIds = queueState.current && !queueState.ids.includes(queueState.current)
        ? [queueState.current, ...queueState.ids]
        : queueState.ids;
      const tracks = await resolveTracksByIdOrder({
        accountId: account.id,
        plexState,
        request,
        ids: effectiveIds,
      });

      const entries = tracks
        .map((track) => songAttrs(track));
      const changedIso = new Date(Number(queueState.updatedAt || Date.now())).toISOString();

      return sendSubsonicOk(
        reply,
        {
          playQueue: {
            current: queueState.current || '',
            position: parseNonNegativeInt(queueState.position, 0),
            username: account.username,
            changed: changedIso,
            entry: entries,
          },
        },
      );
    } catch (error) {
      request.log.error(error, 'Failed to load saved play queue');
      return sendSubsonicError(reply, 10, 'Failed to load play queue');
    }
  });

  app.get('/rest/savePlayQueue.view', async (request, reply) => {
    const account = await authenticateSubsonicRequest(request, reply, repo, tokenCipher);
    if (!account) {
      return;
    }

    const ids = requestedPlayQueueItemIds(request);
    const explicitCurrent = String(getRequestParam(request, 'current') || '').trim();
    const current = explicitCurrent || ids[0] || '';
    const position = parseNonNegativeInt(getRequestParam(request, 'position'), 0);
    const queueKey = playQueueStorageKey(account.id, request);
    const now = Date.now();

    savedPlayQueues.set(queueKey, {
      ids,
      current,
      position,
      updatedAt: now,
    });
    pruneSavedPlayQueues(now);
    const clientName = getRequestParam(request, 'c') || 'Subsonic Client';
    notePlaybackQueueContext({
      accountId: account.id,
      clientName,
      currentTrackId: current,
      queueIds: ids,
    });

    return sendSubsonicOk(reply);
  });

  app.route({
    method: ['GET', 'POST'],
    url: '/rest/scrobble.view',
    async handler(request, reply) {
      const account = await authenticateSubsonicRequest(request, reply, repo, tokenCipher);
      if (!account) {
        return;
      }

      const songIds = uniqueNonEmptyValues(getRequestParamValues(request, 'songId'));
      const genericIds = uniqueNonEmptyValues(getRequestParamValues(request, 'id'));
      const ids = uniqueNonEmptyValues([
        ...songIds,
        ...genericIds,
      ]);

      if (ids.length === 0) {
        return sendSubsonicError(reply, 10, 'Required parameter is missing');
      }

      const context = repo.getAccountPlexContext(account.id);
      const plexState = requiredPlexStateForSubsonic(reply, context, tokenCipher);
      if (!plexState) {
        return;
      }

      const submissionRaw = safeLower(getRequestParam(request, 'submission'));
      const shouldSubmit = !['false', '0', 'no'].includes(submissionRaw);
      const stateParam = safeLower(getRequestParam(request, 'state'));
      const hasExplicitState = stateParam === 'playing' || stateParam === 'paused' || stateParam === 'stopped';
      const playbackState = normalizePlaybackState(stateParam, shouldSubmit ? 'stopped' : 'playing');
      const positionRaw = getRequestParam(request, 'positionMs') || getRequestParam(request, 'position');
      const parsedPosition = Number.parseInt(positionRaw, 10);
      const timeOffsetRaw = getRequestParam(request, 'timeOffset');
      const parsedOffset = Number.parseFloat(timeOffsetRaw);
      const hasPlaybackProgress =
        (Number.isFinite(parsedPosition) && parsedPosition >= 0) ||
        (Number.isFinite(parsedOffset) && parsedOffset >= 0);
      const playbackPositionMs = Number.isFinite(parsedPosition) && parsedPosition >= 0
        ? parsedPosition
        : Number.isFinite(parsedOffset) && parsedOffset >= 0
          ? Math.round(parsedOffset * 1000)
          : 0;
      const clientName = getRequestParam(request, 'c') || 'Subsonic Client';
      const primaryTrackId = firstNonEmptyText(
        [
          getRequestParam(request, 'songId'),
          getRequestParam(request, 'id'),
          songIds[0],
          ids[0],
        ],
        '',
      );
      const submissionIds = shouldSubmit
        ? uniqueNonEmptyValues([primaryTrackId, ...ids])
        : [];
      const isNowPlayingScrobble = !shouldSubmit;
      const shouldSyncPlayback =
        Boolean(primaryTrackId) &&
        (
          hasPlaybackProgress ||
          hasExplicitState ||
          isNowPlayingScrobble
        );
      const playbackClient = playbackClientContext(account.id, clientName);

      let playbackSyncPromise = null;
      if (shouldSyncPlayback) {
        playbackSyncPromise = syncClientPlaybackState({
          accountId: account.id,
          plexState,
          clientName,
          itemId: primaryTrackId,
          state: playbackState,
          positionMs: playbackPositionMs,
          request,
        }).catch((error) => {
          request.log.warn(error, 'Failed to sync playback status to Plex');
        });
      }

      try {
        if (submissionIds.length > 0) {
          const [firstId, ...restIds] = submissionIds;
          await scrobblePlexItem({
            baseUrl: plexState.baseUrl,
            plexToken: plexState.plexToken,
            itemId: firstId,
          });
          if (restIds.length > 0) {
            await Promise.all(
              restIds.map((id) =>
                scrobblePlexItem({
                  baseUrl: plexState.baseUrl,
                  plexToken: plexState.plexToken,
                  itemId: id,
                }),
              ),
            );
          }
        }
      } catch (error) {
        request.log.error(error, 'Failed to sync scrobble to Plex');
        return sendSubsonicError(reply, 10, 'Failed to scrobble');
      }

      if (playbackSyncPromise) {
        await playbackSyncPromise;
      }

      noteRecentScrobble({
        accountId: account.id,
        clientName,
        trackId: primaryTrackId,
      });

      const allowQueuedPromotion =
        shouldSubmit &&
        Boolean(primaryTrackId) &&
        (
          (hasExplicitState && playbackState === 'stopped') ||
          (hasPlaybackProgress && playbackPositionMs > 0)
        );

      if (allowQueuedPromotion) {
        const continuity = recentScrobblesByClient.get(playbackClient.sessionKey);
        const queuedNextTrackId = resolveQueuedNextTrackId(continuity, primaryTrackId);
        if (queuedNextTrackId) {
          const current = playbackSessions.get(playbackClient.sessionKey);
          const currentTrackId = String(current?.itemId || '').trim();
          const shouldPromoteQueuedNext =
            !current ||
            current.state !== 'playing' ||
            currentTrackId === primaryTrackId;

          if (shouldPromoteQueuedNext) {
            try {
              await syncClientPlaybackState({
                accountId: account.id,
                plexState,
                clientName,
                itemId: queuedNextTrackId,
                state: 'playing',
                positionMs: 0,
                request,
              });
            } catch (error) {
              request.log.warn(error, 'Failed to promote queued next track after scrobble');
            }
          }
        }
      }

      return sendSubsonicOk(reply);
    },
  });

  app.route({
    method: ['GET', 'POST'],
    url: '/rest/star.view',
    async handler(request, reply) {
      const account = await authenticateSubsonicRequest(request, reply, repo, tokenCipher);
      if (!account) {
        return;
      }

      const genericIds = uniqueNonEmptyValues(getRequestParamValues(request, 'id'));
      const albumIds = uniqueNonEmptyValues(getRequestParamValues(request, 'albumId'));
      const artistIds = uniqueNonEmptyValues(getRequestParamValues(request, 'artistId'));
      if (genericIds.length === 0 && albumIds.length === 0 && artistIds.length === 0) {
        return sendSubsonicError(reply, 10, 'Required parameter is missing');
      }

      const context = repo.getAccountPlexContext(account.id);
      const plexState = requiredPlexStateForSubsonic(reply, context, tokenCipher);
      if (!plexState) {
        return;
      }

      const [resolvedGenericIds, resolvedAlbumIds, resolvedArtistIds] = await Promise.all([
        Promise.all(
          genericIds.map((id) =>
            resolveCachedLibraryRatingKeyAnyCollection({
              accountId: account.id,
              plexState,
              request,
              id,
            }),
          ),
        ),
        Promise.all(
          albumIds.map((id) =>
            resolveCachedLibraryRatingKey({
              accountId: account.id,
              plexState,
              request,
              collection: 'albums',
              id,
            }),
          ),
        ),
        Promise.all(
          artistIds.map((id) =>
            resolveCachedLibraryRatingKey({
              accountId: account.id,
              plexState,
              request,
              collection: 'artists',
              id,
            }),
          ),
        ),
      ]);
      const ids = uniqueNonEmptyValues([
        ...resolvedGenericIds,
        ...resolvedAlbumIds,
        ...resolvedArtistIds,
      ]);
      if (ids.length === 0) {
        return sendSubsonicOk(reply);
      }

      const cacheKey = searchBrowseCacheKey(account.id, plexState);
      const actions = ids.map((id) => {
        const currentRating = getCachedUserRatingForItem(cacheKey, id);
        return {
          id,
          targetRating: toLikedPlexRating(currentRating),
        };
      });

      try {
        const results = await Promise.allSettled(
          actions.map(({ id, targetRating }) =>
            ratePlexItem({
              baseUrl: plexState.baseUrl,
              plexToken: plexState.plexToken,
              itemId: id,
              rating: targetRating,
            })),
        );
        const failed = results.find(
          (result) => result.status === 'rejected' && !isPlexNotFoundError(result.reason),
        );
        if (failed && failed.status === 'rejected') {
          throw failed.reason;
        }
      } catch (error) {
        request.log.error(error, 'Failed to star item(s) in Plex');
        return sendSubsonicError(reply, 10, 'Failed to star');
      }

      let patchedCount = 0;
      for (const { id, targetRating } of actions) {
        patchedCount += applyUserRatingPatchToSearchBrowseCache({
          cacheKey,
          itemIds: [id],
          userRating: targetRating,
        });
      }
      if (patchedCount === 0) {
        markSearchBrowseCacheDirty(cacheKey);
      }

      return sendSubsonicOk(reply);
    },
  });

  app.route({
    method: ['GET', 'POST'],
    url: '/rest/unstar.view',
    async handler(request, reply) {
      const account = await authenticateSubsonicRequest(request, reply, repo, tokenCipher);
      if (!account) {
        return;
      }

      const genericIds = uniqueNonEmptyValues(getRequestParamValues(request, 'id'));
      const albumIds = uniqueNonEmptyValues(getRequestParamValues(request, 'albumId'));
      const artistIds = uniqueNonEmptyValues(getRequestParamValues(request, 'artistId'));
      if (genericIds.length === 0 && albumIds.length === 0 && artistIds.length === 0) {
        return sendSubsonicError(reply, 10, 'Required parameter is missing');
      }

      const context = repo.getAccountPlexContext(account.id);
      const plexState = requiredPlexStateForSubsonic(reply, context, tokenCipher);
      if (!plexState) {
        return;
      }

      const [resolvedGenericIds, resolvedAlbumIds, resolvedArtistIds] = await Promise.all([
        Promise.all(
          genericIds.map((id) =>
            resolveCachedLibraryRatingKeyAnyCollection({
              accountId: account.id,
              plexState,
              request,
              id,
            }),
          ),
        ),
        Promise.all(
          albumIds.map((id) =>
            resolveCachedLibraryRatingKey({
              accountId: account.id,
              plexState,
              request,
              collection: 'albums',
              id,
            }),
          ),
        ),
        Promise.all(
          artistIds.map((id) =>
            resolveCachedLibraryRatingKey({
              accountId: account.id,
              plexState,
              request,
              collection: 'artists',
              id,
            }),
          ),
        ),
      ]);
      const ids = uniqueNonEmptyValues([
        ...resolvedGenericIds,
        ...resolvedAlbumIds,
        ...resolvedArtistIds,
      ]);
      if (ids.length === 0) {
        return sendSubsonicOk(reply);
      }

      const cacheKey = searchBrowseCacheKey(account.id, plexState);
      const actions = ids.map((id) => {
        const currentRating = getCachedUserRatingForItem(cacheKey, id);
        return {
          id,
          targetRating: toUnlikedPlexRating(currentRating),
        };
      });

      try {
        const results = await Promise.allSettled(
          actions.map(({ id, targetRating }) =>
            ratePlexItem({
              baseUrl: plexState.baseUrl,
              plexToken: plexState.plexToken,
              itemId: id,
              rating: targetRating,
            })),
        );
        const failed = results.find(
          (result) => result.status === 'rejected' && !isPlexNotFoundError(result.reason),
        );
        if (failed && failed.status === 'rejected') {
          throw failed.reason;
        }
      } catch (error) {
        request.log.error(error, 'Failed to unstar item(s) in Plex');
        return sendSubsonicError(reply, 10, 'Failed to unstar');
      }

      let patchedCount = 0;
      for (const { id, targetRating } of actions) {
        patchedCount += applyUserRatingPatchToSearchBrowseCache({
          cacheKey,
          itemIds: [id],
          userRating: targetRating,
        });
      }
      if (patchedCount === 0) {
        markSearchBrowseCacheDirty(cacheKey);
      }

      return sendSubsonicOk(reply);
    },
  });

  app.route({
    method: ['GET', 'POST'],
    url: '/rest/setRating.view',
    async handler(request, reply) {
      const account = await authenticateSubsonicRequest(request, reply, repo, tokenCipher);
      if (!account) {
        return;
      }

      const id = getRequestParam(request, 'id');
      const ratingRaw = getRequestParam(request, 'rating');
      const rating = Number.parseInt(ratingRaw, 10);

      if (!id || !Number.isFinite(rating)) {
        return sendSubsonicError(reply, 10, 'Required parameter is missing');
      }

      if (rating < 0 || rating > 5) {
        return sendSubsonicError(reply, 10, 'Invalid rating');
      }

      const context = repo.getAccountPlexContext(account.id);
      const plexState = requiredPlexStateForSubsonic(reply, context, tokenCipher);
      if (!plexState) {
        return;
      }

      const resolvedId = await resolveCachedLibraryRatingKeyAnyCollection({
        accountId: account.id,
        plexState,
        request,
        id,
      });
      if (!resolvedId) {
        return sendSubsonicOk(reply);
      }

      const cacheKey = searchBrowseCacheKey(account.id, plexState);
      const currentRating = getCachedUserRatingForItem(cacheKey, resolvedId);
      const preserveLike = rating >= 2 && isPlexLiked(currentRating);
      const plexRating = subsonicRatingToPlexRating(rating, { liked: preserveLike });
      try {
        await ratePlexItem({
          baseUrl: plexState.baseUrl,
          plexToken: plexState.plexToken,
          itemId: resolvedId,
          rating: plexRating,
        });
      } catch (error) {
        if (isPlexNotFoundError(error)) {
          return sendSubsonicOk(reply);
        }
        request.log.error(error, 'Failed to set rating in Plex');
        return sendSubsonicError(reply, 10, 'Failed to set rating');
      }

      const patchedCount = applyUserRatingPatchToSearchBrowseCache({
        cacheKey,
        itemIds: [resolvedId],
        userRating: plexRating,
      });
      if (patchedCount === 0) {
        markSearchBrowseCacheDirty(cacheKey);
      }

      return sendSubsonicOk(reply);
    },
  });

  app.route({
    method: ['GET', 'POST'],
    url: '/rest/createPlaylist.view',
    async handler(request, reply) {
      const account = await authenticateSubsonicRequest(request, reply, repo, tokenCipher);
      if (!account) {
        return;
      }

      const playlistId = getRequestParam(request, 'playlistId');
      const name = getRequestParam(request, 'name') || getRequestParam(request, 'title');
      const songIds = uniqueNonEmptyValues([
        ...getRequestParamValues(request, 'songId'),
        ...getRequestParamValues(request, 'songIdToAdd'),
      ]);
      const nowIso = new Date().toISOString();

      if (!playlistId && !name) {
        return sendSubsonicError(reply, 10, 'Required parameter is missing');
      }

      const context = repo.getAccountPlexContext(account.id);
      const plexState = requiredPlexStateForSubsonic(reply, context, tokenCipher);
      if (!plexState) {
        return;
      }

      let effectiveId = playlistId;
      let effectiveName = name || (playlistId ? `Playlist ${playlistId}` : 'New Playlist');
      let effectiveSongCount = songIds.length;

      try {
        if (!playlistId) {
          const created = await createPlexPlaylist({
            baseUrl: plexState.baseUrl,
            plexToken: plexState.plexToken,
            machineId: plexState.machineId,
            title: effectiveName,
            itemIds: songIds,
          });

          effectiveId = String(created?.ratingKey || '');
          effectiveName = String(created?.title || effectiveName);
          const createdLeafCount = Number.parseInt(String(created?.leafCount ?? ''), 10);
          if (Number.isFinite(createdLeafCount)) {
            effectiveSongCount = createdLeafCount;
          }
        } else {
          if (name) {
            await renamePlexPlaylist({
              baseUrl: plexState.baseUrl,
              plexToken: plexState.plexToken,
              playlistId,
              title: name,
            });
          }

          if (songIds.length > 0) {
            await addItemsToPlexPlaylist({
              baseUrl: plexState.baseUrl,
              plexToken: plexState.plexToken,
              machineId: plexState.machineId,
              playlistId,
              itemIds: songIds,
            });
          }
        }

        if (!effectiveId) {
          return sendSubsonicError(reply, 10, 'Failed to create playlist');
        }

        const playlists = await listPlexPlaylists({
          baseUrl: plexState.baseUrl,
          plexToken: plexState.plexToken,
        });
        const playlist = playlists.find((item) => String(item.ratingKey) === String(effectiveId));
        if (playlist) {
          effectiveName = String(playlist.title || effectiveName);
          const playlistLeafCount = Number.parseInt(String(playlist.leafCount ?? ''), 10);
          if (Number.isFinite(playlistLeafCount)) {
            effectiveSongCount = playlistLeafCount;
          }
        }
      } catch (error) {
        request.log.error(error, 'Failed to create/update playlist in Plex');
        return sendSubsonicError(reply, 10, 'Failed to create playlist');
      }

      return sendSubsonicOk(
        reply,
        {
          playlist: {
            id: effectiveId,
            name: effectiveName,
            owner: account.username,
            public: false,
            readonly: false,
            songCount: effectiveSongCount,
            duration: 0,
            created: nowIso,
            changed: nowIso,
          },
        },
      );
    },
  });

  app.get('/rest/getAvatar.view', async (request, reply) => {
    const account = await authenticateSubsonicRequest(request, reply, repo, tokenCipher);
    if (!account) {
      return;
    }

    return sendSubsonicError(reply, 70, 'Avatar not found');
  });

  app.get('/rest/getPlaylists.view', async (request, reply) => {
    const account = await authenticateSubsonicRequest(request, reply, repo, tokenCipher);
    if (!account) {
      return;
    }

    const context = repo.getAccountPlexContext(account.id);
    const plexState = requiredPlexStateForSubsonic(reply, context, tokenCipher);
    if (!plexState) {
      return;
    }

    try {
      const playlists = await listPlexPlaylists({
        baseUrl: plexState.baseUrl,
        plexToken: plexState.plexToken,
      });

      const nowIso = new Date().toISOString();
      const playlistItems = playlists
        .map((playlist) => playlistAttrs(playlist, account.username, nowIso));

      return sendSubsonicOk(reply, { playlists: playlistItems });
    } catch (error) {
      request.log.error(error, 'Failed to load playlists');
      return sendSubsonicError(reply, 10, 'Failed to load playlists');
    }
  });

  app.get('/rest/getPlaylist.view', async (request, reply) => {
    const account = await authenticateSubsonicRequest(request, reply, repo, tokenCipher);
    if (!account) {
      return;
    }

    const id = getRequestParam(request, 'id');
    if (!id) {
      return sendSubsonicError(reply, 70, 'Playlist not found');
    }

    const context = repo.getAccountPlexContext(account.id);
    const plexState = requiredPlexStateForSubsonic(reply, context, tokenCipher);
    if (!plexState) {
      return;
    }

    try {
      const [playlists, tracks] = await Promise.all([
        listPlexPlaylists({
          baseUrl: plexState.baseUrl,
          plexToken: plexState.plexToken,
        }),
        listPlexPlaylistItems({
          baseUrl: plexState.baseUrl,
          plexToken: plexState.plexToken,
          playlistId: id,
        }),
      ]);

      const playlist = playlists.find((entry) => String(entry.ratingKey) === String(id));
      if (!playlist) {
        return sendSubsonicError(reply, 70, 'Playlist not found');
      }

      const nowIso = new Date().toISOString();
      const entries = tracks
        .map((track) => songAttrs(track, track.parentTitle || undefined, track.parentRatingKey || undefined));

      return sendSubsonicOk(reply, {
        playlist: {
          ...playlistAttrs(playlist, account.username, nowIso),
          entry: entries,
        },
      });
    } catch (error) {
      request.log.error(error, 'Failed to load playlist');
      return sendSubsonicError(reply, 10, 'Failed to load playlist');
    }
  });

  app.route({
    method: ['GET', 'POST'],
    url: '/rest/deletePlaylist.view',
    async handler(request, reply) {
      const account = await authenticateSubsonicRequest(request, reply, repo, tokenCipher);
      if (!account) {
        return;
      }

      const playlistId = getRequestParam(request, 'id') || getRequestParam(request, 'playlistId');
      if (!playlistId) {
        return sendSubsonicError(reply, 70, 'Playlist not found');
      }

      const context = repo.getAccountPlexContext(account.id);
      const plexState = requiredPlexStateForSubsonic(reply, context, tokenCipher);
      if (!plexState) {
        return;
      }

      try {
        await deletePlexPlaylist({
          baseUrl: plexState.baseUrl,
          plexToken: plexState.plexToken,
          playlistId,
        });
      } catch (error) {
        request.log.error(error, 'Failed to delete playlist');
        if (String(error?.message || '').includes('(404)')) {
          return sendSubsonicError(reply, 70, 'Playlist not found');
        }
        return sendSubsonicError(reply, 10, 'Failed to delete playlist');
      }

      return sendSubsonicOk(reply);
    },
  });

  app.route({
    method: ['GET', 'POST'],
    url: '/rest/updatePlaylist.view',
    async handler(request, reply) {
      const account = await authenticateSubsonicRequest(request, reply, repo, tokenCipher);
      if (!account) {
        return;
      }

      const playlistId = getRequestParam(request, 'playlistId') || getRequestParam(request, 'id');
      if (!playlistId) {
        return sendSubsonicError(reply, 70, 'Playlist not found');
      }

      const name = getRequestParam(request, 'name') || getRequestParam(request, 'title');
      const songIdsToAdd = uniqueNonEmptyValues([
        ...getRequestParamValues(request, 'songIdToAdd'),
        ...getRequestParamValues(request, 'songId'),
      ]);
      const songIdsToRemove = getRequestParamValues(request, 'songIdToRemove')
        .map((value) => String(value || '').trim())
        .filter(Boolean);
      const songIndexesToRemove = getRequestParamValues(request, 'songIndexToRemove')
        .map((value) => parseNonNegativeInt(value, -1))
        .filter((value) => value >= 0);

      const context = repo.getAccountPlexContext(account.id);
      const plexState = requiredPlexStateForSubsonic(reply, context, tokenCipher);
      if (!plexState) {
        return;
      }

      try {
        if (name) {
          await renamePlexPlaylist({
            baseUrl: plexState.baseUrl,
            plexToken: plexState.plexToken,
            playlistId,
            title: name,
          });
        }

        if (songIdsToRemove.length > 0 || songIndexesToRemove.length > 0) {
          const playlistItems = await listPlexPlaylistItems({
            baseUrl: plexState.baseUrl,
            plexToken: plexState.plexToken,
            playlistId,
          });

          const songIdToRemoveSet = new Set(songIdsToRemove.map((value) => String(value)));
          const playlistItemIdsToRemove = new Set();

          const pushPlaylistItemId = (item) => {
            const playlistItemId = String(item?.playlistItemID ?? item?.playlistItemId ?? '').trim();
            if (playlistItemId) {
              playlistItemIdsToRemove.add(playlistItemId);
              return;
            }

            const fallbackTrackId = String(item?.ratingKey ?? '').trim();
            if (fallbackTrackId) {
              playlistItemIdsToRemove.add(fallbackTrackId);
            }
          };

          for (const index of songIndexesToRemove) {
            if (index >= 0 && index < playlistItems.length) {
              pushPlaylistItemId(playlistItems[index]);
            }
          }

          if (songIdToRemoveSet.size > 0) {
            for (const item of playlistItems) {
              const trackId = String(item?.ratingKey ?? '').trim();
              if (trackId && songIdToRemoveSet.has(trackId)) {
                pushPlaylistItemId(item);
              }
            }
          }

          if (playlistItemIdsToRemove.size > 0) {
            await removePlexPlaylistItems({
              baseUrl: plexState.baseUrl,
              plexToken: plexState.plexToken,
              playlistId,
              playlistItemIds: [...playlistItemIdsToRemove],
            });
          }
        }

        if (songIdsToAdd.length > 0) {
          await addItemsToPlexPlaylist({
            baseUrl: plexState.baseUrl,
            plexToken: plexState.plexToken,
            machineId: plexState.machineId,
            playlistId,
            itemIds: songIdsToAdd,
          });
        }
      } catch (error) {
        request.log.error(error, 'Failed to update playlist');
        if (String(error?.message || '').includes('(404)')) {
          return sendSubsonicError(reply, 70, 'Playlist not found');
        }
        return sendSubsonicError(reply, 10, 'Failed to update playlist');
      }

      return sendSubsonicOk(reply);
    },
  });

  app.get('/rest/getArtists.view', async (request, reply) => {
    const account = await authenticateSubsonicRequest(request, reply, repo, tokenCipher);
    if (!account) {
      return;
    }

    const context = repo.getAccountPlexContext(account.id);
    const plexState = requiredPlexStateForSubsonic(reply, context, tokenCipher);
    if (!plexState) {
      return;
    }

    try {
      const artists = await getCachedLibraryArtists({ accountId: account.id, plexState, request });

      const indexes = groupArtistsForSubsonic(artists);
      return sendSubsonicOk(reply, {
        artists: {
          ignoredArticles: 'The El La Los Las Le Les',
          index: indexes,
        },
      });
    } catch (error) {
      request.log.error(error, 'Failed to load artists from Plex');
      return sendSubsonicError(reply, 10, 'Failed to load artists');
    }
  });

  app.get('/rest/getIndexes.view', async (request, reply) => {
    const account = await authenticateSubsonicRequest(request, reply, repo, tokenCipher);
    if (!account) {
      return;
    }

    const context = repo.getAccountPlexContext(account.id);
    const plexState = requiredPlexStateForSubsonic(reply, context, tokenCipher);
    if (!plexState) {
      return;
    }

    try {
      const rootFolders = await listPlexSectionFolder({
        baseUrl: plexState.baseUrl,
        plexToken: plexState.plexToken,
        sectionId: plexState.musicSectionId,
      });

      const folderEntries = rootFolders.items
        .map((item) => {
          const folderKey = String(item?.key || '');
          if (!folderKey || !isPlexFolderPathId(folderKey, plexState.musicSectionId)) {
            return null;
          }
          const id = encodePlexFolderId(folderKey, plexState.musicSectionId);
          if (!id) {
            return null;
          }
          return {
            id,
            name: String(item?.title || item?.name || 'Folder'),
          };
        })
        .filter(Boolean);

      const indexes = groupNamedEntriesForSubsonic(folderEntries);
      return sendSubsonicOk(
        reply,
        {
          indexes: {
            ignoredArticles: 'The El La Los Las Le Les',
            lastModified: 0,
            index: indexes,
          },
        },
      );
    } catch (error) {
      request.log.error(error, 'Failed to load indexes from Plex');
      return sendSubsonicError(reply, 10, 'Failed to load indexes');
    }
  });

  app.get('/rest/getArtist.view', async (request, reply) => {
    const account = await authenticateSubsonicRequest(request, reply, repo, tokenCipher);
    if (!account) {
      return;
    }

    const rawArtistId = String(getQueryString(request, 'id') || '').trim();
    if (!rawArtistId) {
      return sendSubsonicError(reply, 70, 'Missing artist id');
    }

    const context = repo.getAccountPlexContext(account.id);
    const plexState = requiredPlexStateForSubsonic(reply, context, tokenCipher);
    if (!plexState) {
      return;
    }

    try {
      const artistId = await resolveCachedLibraryRatingKey({
        accountId: account.id,
        plexState,
        request,
        collection: 'artists',
        id: rawArtistId,
      }) || rawArtistId;
      let artist = null;
      let finalAlbums = [];

      try {
        artist = await getArtist({
          baseUrl: plexState.baseUrl,
          plexToken: plexState.plexToken,
          artistId,
        });
      } catch (error) {
        if (!isPlexNotFoundError(error)) {
          throw error;
        }
      }

      if (artist) {
        applyCachedRatingOverridesForAccount({ accountId: account.id, plexState, items: [artist] });
        const albums = await listArtistAlbums({
          baseUrl: plexState.baseUrl,
          plexToken: plexState.plexToken,
          artistId,
        });
        applyCachedRatingOverridesForAccount({ accountId: account.id, plexState, items: albums });
        finalAlbums = albums;
        if (finalAlbums.length === 0) {
          const tracks = await listArtistTracks({
            baseUrl: plexState.baseUrl,
            plexToken: plexState.plexToken,
            artistId,
          });
          applyCachedRatingOverridesForAccount({ accountId: account.id, plexState, items: tracks });
          finalAlbums = deriveAlbumsFromTracks(tracks, artist.ratingKey, artist.title);
        }
      } else {
        const fallback = await resolveArtistFromCachedLibrary({
          accountId: account.id,
          plexState,
          request,
          artistId,
        });
        if (!fallback?.artist) {
          return sendSubsonicError(reply, 70, 'Artist not found');
        }
        artist = fallback.artist;
        finalAlbums = fallback.albums || [];
      }

      const albumItems = finalAlbums
        .map((album) =>
          albumJson(
            album,
            albumId3Attrs(album, artist.ratingKey, artist.title),
            artist.ratingKey,
            artist.title,
          ),
        );

      return sendSubsonicOk(
        reply,
        {
          artist: {
            id: artist.ratingKey,
            name: artist.title,
            albumCount: finalAlbums.length,
            coverArt: artist.ratingKey,
            ...subsonicRatingAttrs(artist),
            album: albumItems,
          },
        },
      );
    } catch (error) {
      request.log.error(error, 'Failed to load artist details from Plex');
      return sendSubsonicError(reply, 10, 'Failed to load artist');
    }
  });

  app.get('/rest/getArtistInfo.view', async (request, reply) => {
    const account = await authenticateSubsonicRequest(request, reply, repo, tokenCipher);
    if (!account) {
      return;
    }

    const rawArtistId = String(getRequestParam(request, 'id') || '').trim();
    if (!rawArtistId) {
      return sendSubsonicError(reply, 70, 'Missing artist id');
    }

    const context = repo.getAccountPlexContext(account.id);
    const plexState = requiredPlexStateForSubsonic(reply, context, tokenCipher);
    if (!plexState) {
      return;
    }

    try {
      const artistId = await resolveCachedLibraryRatingKey({
        accountId: account.id,
        plexState,
        request,
        collection: 'artists',
        id: rawArtistId,
      }) || rawArtistId;
      let artist = null;
      try {
        artist = await getArtist({
          baseUrl: plexState.baseUrl,
          plexToken: plexState.plexToken,
          artistId,
        });
      } catch (error) {
        if (!isPlexNotFoundError(error)) {
          throw error;
        }
      }

      if (!artist) {
        const fallback = await resolveArtistFromCachedLibrary({
          accountId: account.id,
          plexState,
          request,
          artistId,
        });
        if (fallback?.artist) {
          artist = fallback.artist;
        }
      }

      if (!artist) {
        return sendSubsonicError(reply, 70, 'Artist not found');
      }

      const biography = artistBioFromPlex(artist);
      const musicBrainzId = extractMusicBrainzArtistId(artist);
      return sendSubsonicOk(reply, {
        artistInfo: {
          biography: biography || undefined,
          musicBrainzId: musicBrainzId || undefined,
        },
      });
    } catch (error) {
      request.log.error(error, 'Failed to load artist info');
      return sendSubsonicError(reply, 10, 'Failed to load artist info');
    }
  });

  app.get('/rest/getArtistInfo2.view', async (request, reply) => {
    const account = await authenticateSubsonicRequest(request, reply, repo, tokenCipher);
    if (!account) {
      return;
    }

    const rawArtistId = String(getRequestParam(request, 'id') || '').trim();
    if (!rawArtistId) {
      return sendSubsonicError(reply, 70, 'Missing artist id');
    }

    const context = repo.getAccountPlexContext(account.id);
    const plexState = requiredPlexStateForSubsonic(reply, context, tokenCipher);
    if (!plexState) {
      return;
    }

    try {
      const artistId = await resolveCachedLibraryRatingKey({
        accountId: account.id,
        plexState,
        request,
        collection: 'artists',
        id: rawArtistId,
      }) || rawArtistId;
      let artist = null;
      try {
        artist = await getArtist({
          baseUrl: plexState.baseUrl,
          plexToken: plexState.plexToken,
          artistId,
        });
      } catch (error) {
        if (!isPlexNotFoundError(error)) {
          throw error;
        }
      }

      if (!artist) {
        const fallback = await resolveArtistFromCachedLibrary({
          accountId: account.id,
          plexState,
          request,
          artistId,
        });
        if (fallback?.artist) {
          artist = fallback.artist;
        }
      }

      if (!artist) {
        return sendSubsonicError(reply, 70, 'Artist not found');
      }

      const biography = artistBioFromPlex(artist);
      const musicBrainzId = extractMusicBrainzArtistId(artist);
      return sendSubsonicOk(reply, {
        artistInfo2: {
          biography: biography || undefined,
          musicBrainzId: musicBrainzId || undefined,
        },
      });
    } catch (error) {
      request.log.error(error, 'Failed to load artist info2');
      return sendSubsonicError(reply, 10, 'Failed to load artist info');
    }
  });

  app.get('/rest/getAlbum.view', async (request, reply) => {
    const account = await authenticateSubsonicRequest(request, reply, repo, tokenCipher);
    if (!account) {
      return;
    }

    const rawAlbumId = String(getQueryString(request, 'id') || '').trim();
    if (!rawAlbumId) {
      return sendSubsonicError(reply, 70, 'Missing album id');
    }

    const context = repo.getAccountPlexContext(account.id);
    const plexState = requiredPlexStateForSubsonic(reply, context, tokenCipher);
    if (!plexState) {
      return;
    }

    try {
      const albumId = await resolveCachedLibraryRatingKey({
        accountId: account.id,
        plexState,
        request,
        collection: 'albums',
        id: rawAlbumId,
      }) || rawAlbumId;
      let album = await getAlbum({
        baseUrl: plexState.baseUrl,
        plexToken: plexState.plexToken,
        albumId,
      });
      let tracks = [];

      if (album) {
        tracks = await listAlbumTracks({
          baseUrl: plexState.baseUrl,
          plexToken: plexState.plexToken,
          albumId,
        });
      } else {
        const fallback = await resolveAlbumFromCachedLibrary({
          accountId: account.id,
          plexState,
          request,
          albumId: rawAlbumId,
        });
        if (!fallback?.album) {
          return sendSubsonicError(reply, 70, 'Album not found');
        }
        album = fallback.album;
        tracks = Array.isArray(fallback.tracks) ? fallback.tracks : [];
      }

      const tracksWithGenre = await hydrateTracksWithGenre({
        baseUrl: plexState.baseUrl,
        plexToken: plexState.plexToken,
        tracks,
        request,
      });
      applyCachedRatingOverridesForAccount({ accountId: account.id, plexState, items: [album, ...tracksWithGenre] });
      const sortedTracks = sortTracksByDiscAndIndex(tracksWithGenre);

      const totalDuration = sortedTracks.reduce((sum, track) => sum + durationSeconds(track.duration), 0);

      const songItems = sortedTracks
        .map((track) => songJson(track, album.title, album.ratingKey, album));

      return sendSubsonicOk(
        reply,
        {
          album: {
            ...albumJson(
              album,
              {
                ...albumId3Attrs(album, album.parentRatingKey || null, album.parentTitle || null),
                songCount: sortedTracks.length,
                duration: totalDuration,
              },
              album.parentRatingKey || null,
              album.parentTitle || null,
            ),
            song: songItems,
          },
        },
      );
    } catch (error) {
      request.log.error(error, 'Failed to load album from Plex');
      return sendSubsonicError(reply, 10, 'Failed to load album');
    }
  });

  app.get('/rest/getMusicDirectory.view', async (request, reply) => {
    const account = await authenticateSubsonicRequest(request, reply, repo, tokenCipher);
    if (!account) {
      return;
    }

    const id = getRequestParam(request, 'id');
    if (!id) {
      return sendSubsonicError(reply, 70, 'Directory not found');
    }

    const context = repo.getAccountPlexContext(account.id);
    const plexState = requiredPlexStateForSubsonic(reply, context, tokenCipher);
    if (!plexState) {
      return;
    }

    try {
      const rootDirectoryId = plexFolderRootId(plexState.musicSectionId);
      const isRootFolder = id === '1' || id === rootDirectoryId;
      const explicitFolderPath =
        (isPlexFolderPathId(id, plexState.musicSectionId) ? id : null) ||
        decodePlexFolderId(id, plexState.musicSectionId);

      if (isRootFolder || explicitFolderPath) {
        const folderResult = await listPlexSectionFolder({
          baseUrl: plexState.baseUrl,
          plexToken: plexState.plexToken,
          sectionId: plexState.musicSectionId,
          folderPath: explicitFolderPath,
        });
        applyCachedRatingOverridesForAccount({ accountId: account.id, plexState, items: folderResult.items });

        const currentFolderPath = isRootFolder ? null : explicitFolderPath;
        const currentDirectoryId = isRootFolder
          ? rootDirectoryId
          : encodePlexFolderId(explicitFolderPath, plexState.musicSectionId) || id;
        const children = folderResult.items
          .map((item) => {
            if (isLikelyPlexTrack(item)) {
              return songChildJson(
                item,
                item.parentTitle || null,
                item.parentRatingKey || null,
                null,
                {
                  isDir: false,
                  parent: currentDirectoryId,
                },
              );
            }

            if (isLikelyPlexAlbum(item)) {
              return albumJson(item, {
                ...albumAttrs(item),
                isDir: true,
                parent: currentDirectoryId,
              });
            }

            const folderKey = String(item?.key || '');
            if (!folderKey || !isPlexFolderPathId(folderKey, plexState.musicSectionId)) {
              return '';
            }
            if (currentFolderPath && folderKey === currentFolderPath) {
              return '';
            }

            const title = String(item?.title || item?.name || 'Folder');
            const folderId = encodePlexFolderId(folderKey, plexState.musicSectionId) || folderKey;
            return {
              id: folderId,
              parent: currentDirectoryId,
              isDir: true,
              title,
              name: title,
            };
          })
          .filter(Boolean);

        const container = folderResult.container || {};
        const directoryName = isRootFolder
          ? String(container.title1 || plexState.serverName)
          : String(container.title2 || container.title1 || 'Folder');

        return sendSubsonicOk(
          reply,
          {
            directory: {
              id: currentDirectoryId,
              parent: isRootFolder ? undefined : rootDirectoryId,
              name: directoryName,
              child: children,
            },
          },
        );
      }

      const resolvedArtistDirectoryId = await resolveCachedLibraryRatingKey({
        accountId: account.id,
        plexState,
        request,
        collection: 'artists',
        id,
      }) || id;
      const resolvedAlbumDirectoryId = await resolveCachedLibraryRatingKey({
        accountId: account.id,
        plexState,
        request,
        collection: 'albums',
        id,
      }) || id;

      let artist = null;
      try {
        artist = await getArtist({
          baseUrl: plexState.baseUrl,
          plexToken: plexState.plexToken,
          artistId: resolvedArtistDirectoryId,
        });
      } catch (error) {
        if (!isPlexNotFoundError(error)) {
          throw error;
        }
      }

      if (artist) {
        applyCachedRatingOverridesForAccount({ accountId: account.id, plexState, items: [artist] });
        const albums = await listArtistAlbums({
          baseUrl: plexState.baseUrl,
          plexToken: plexState.plexToken,
          artistId: resolvedArtistDirectoryId,
        });
        applyCachedRatingOverridesForAccount({ accountId: account.id, plexState, items: albums });

        let finalAlbums = albums;
        if (finalAlbums.length === 0) {
          const tracks = await listArtistTracks({
            baseUrl: plexState.baseUrl,
            plexToken: plexState.plexToken,
            artistId: resolvedArtistDirectoryId,
          });
          finalAlbums = deriveAlbumsFromTracks(tracks, artist.ratingKey, artist.title);
        }

        const children = finalAlbums
          .map((album) =>
            albumJson(
              album,
              albumAttrs(album, artist.ratingKey, artist.title),
              artist.ratingKey,
              artist.title,
            ),
          );

        return sendSubsonicOk(
          reply,
          {
            directory: {
              id: artist.ratingKey,
              parent: rootDirectoryId,
              name: artist.title,
              child: children,
            },
          },
        );
      }

      if (!artist) {
        const fallback = await resolveArtistFromCachedLibrary({
          accountId: account.id,
          plexState,
          request,
          artistId: id,
        });
        if (fallback?.artist) {
          const fallbackAlbums = fallback.albums || [];
          const children = fallbackAlbums
            .map((album) =>
              albumJson(
                album,
                albumAttrs(album, fallback.artist.ratingKey, fallback.artist.title),
                fallback.artist.ratingKey,
                fallback.artist.title,
              ),
            );

          return sendSubsonicOk(
            reply,
            {
              directory: {
                id: fallback.artist.ratingKey,
                parent: rootDirectoryId,
                name: fallback.artist.title,
                child: children,
              },
            },
          );
        }
      }

      const album = await getAlbum({
        baseUrl: plexState.baseUrl,
        plexToken: plexState.plexToken,
        albumId: resolvedAlbumDirectoryId,
      });

      if (album) {
        const tracks = await listAlbumTracks({
          baseUrl: plexState.baseUrl,
          plexToken: plexState.plexToken,
          albumId: resolvedAlbumDirectoryId,
        });
        const tracksWithGenre = await hydrateTracksWithGenre({
          baseUrl: plexState.baseUrl,
          plexToken: plexState.plexToken,
          tracks,
          request,
        });
        applyCachedRatingOverridesForAccount({ accountId: account.id, plexState, items: [album, ...tracksWithGenre] });
        const sortedTracks = sortTracksByDiscAndIndex(tracksWithGenre);

        const children = sortedTracks
          .map((track) =>
            songChildJson(track, album.title, album.ratingKey, album, {
              isDir: false,
              parent: album.ratingKey,
            }),
          );

        return sendSubsonicOk(
          reply,
          {
            directory: {
              id: album.ratingKey,
              parent: album.parentRatingKey || rootDirectoryId,
              name: album.title,
              child: children,
            },
          },
        );
      }

      return sendSubsonicError(reply, 70, 'Directory not found');
    } catch (error) {
      request.log.error(error, 'Failed to load music directory');
      return sendSubsonicError(reply, 10, 'Failed to load music directory');
    }
  });

  async function handleAlbumListRequest(request, reply, containerName) {
    const account = await authenticateSubsonicRequest(request, reply, repo, tokenCipher);
    if (!account) {
      return;
    }

    const rawType = String(getRequestParam(request, 'type') || '').trim();
    const type = normalizeAlbumListType(rawType || 'alphabeticalByName');
    if (rawType && !SUPPORTED_ALBUM_LIST_TYPES.has(type)) {
      return sendSubsonicError(reply, 10, 'Invalid or missing type');
    }

    const size = Math.min(parsePositiveInt(getRequestParam(request, 'size'), 10), 500);
    const offset = parseNonNegativeInt(getRequestParam(request, 'offset'), 0);
    const genre = String(getRequestParam(request, 'genre') || '').trim();
    const musicFolderId = String(getRequestParam(request, 'musicFolderId') || '').trim();

    let fromYear = 0;
    let toYear = 0;
    if (type === 'byyear') {
      fromYear = Number.parseInt(String(getRequestParam(request, 'fromYear') || '').trim(), 10);
      toYear = Number.parseInt(String(getRequestParam(request, 'toYear') || '').trim(), 10);
      if (!Number.isFinite(fromYear) || !Number.isFinite(toYear)) {
        return sendSubsonicError(reply, 10, 'Missing fromYear or toYear');
      }
    }

    if (type === 'bygenre' && !genre) {
      return sendSubsonicError(reply, 10, 'Missing genre');
    }

    const context = repo.getAccountPlexContext(account.id);
    const plexState = requiredPlexStateForSubsonic(reply, context, tokenCipher);
    if (!plexState) {
      return;
    }

    if (musicFolderId && musicFolderId !== String(plexState.musicSectionId || '')) {
      reply.header('x-total-count', '0');
      return sendSubsonicOk(reply, { [containerName]: [] });
    }

    try {
      const { total, items } = await queryAlbumListFromCache({
        accountId: account.id,
        plexState,
        request,
        type,
        fromYear,
        toYear,
        genre,
        size,
        offset,
      });
      reply.header('x-total-count', String(total));
      const albumItems = items
        .map((album) =>
          albumJson(
            album,
            containerName === 'albumList2' ? albumId3Attrs(album) : albumAttrs(album),
          ),
        );

      return sendSubsonicOk(reply, { [containerName]: albumItems });
    } catch (error) {
      request.log.error(error, 'Failed to load album list');
      return sendSubsonicError(reply, 10, 'Failed to load album list');
    }
  }

  app.route({
    method: ['GET', 'POST'],
    url: '/rest/getAlbumList2.view',
    async handler(request, reply) {
      return handleAlbumListRequest(request, reply, 'albumList2');
    },
  });

  app.route({
    method: ['GET', 'POST'],
    url: '/rest/getAlbumList.view',
    async handler(request, reply) {
      return handleAlbumListRequest(request, reply, 'albumList');
    },
  });

  app.get('/rest/getCoverArt.view', async (request, reply) => {
    const account = await authenticateSubsonicRequest(request, reply, repo, tokenCipher);
    if (!account) {
      return;
    }

    const id = getRequestParam(request, 'id');
    if (!id) {
      return sendSubsonicError(reply, 70, 'Missing cover id');
    }

    const context = repo.getAccountPlexContext(account.id);
    const plexState = requiredPlexStateForSubsonic(reply, context, tokenCipher);
    if (!plexState) {
      return;
    }

    try {
      let thumbPath = id.startsWith('/') ? id : null;

      if (!thumbPath) {
        const [resolvedAlbumId, resolvedArtistId, resolvedTrackId] = await Promise.all([
          resolveCachedLibraryRatingKey({
            accountId: account.id,
            plexState,
            request,
            collection: 'albums',
            id,
          }),
          resolveCachedLibraryRatingKey({
            accountId: account.id,
            plexState,
            request,
            collection: 'artists',
            id,
          }),
          resolveCachedLibraryRatingKey({
            accountId: account.id,
            plexState,
            request,
            collection: 'tracks',
            id,
          }),
        ]);
        const metadata = await getAlbum({
          baseUrl: plexState.baseUrl,
          plexToken: plexState.plexToken,
          albumId: resolvedAlbumId || id,
        });

        if (metadata) {
          thumbPath = metadata.thumb || metadata.art || null;
        }

        if (!thumbPath) {
          const artist = await getArtist({
            baseUrl: plexState.baseUrl,
            plexToken: plexState.plexToken,
            artistId: resolvedArtistId || id,
          });

          thumbPath = artist?.thumb || artist?.art || null;
        }

        if (!thumbPath) {
          const track = await getTrack({
            baseUrl: plexState.baseUrl,
            plexToken: plexState.plexToken,
            trackId: resolvedTrackId || id,
          });

          thumbPath = track?.thumb || track?.parentThumb || track?.grandparentThumb || null;
        }
      }

      if (!thumbPath) {
        return sendSubsonicError(reply, 70, 'Cover art not found');
      }

      const assetUrl = buildPmsAssetUrl(plexState.baseUrl, plexState.plexToken, thumbPath);
      const upstream = await fetch(assetUrl);

      if (!upstream.ok || !upstream.body) {
        request.log.warn({ status: upstream.status }, 'Failed to proxy cover art');
        return sendSubsonicError(reply, 70, 'Cover art not found');
      }

      reply.code(upstream.status);

      for (const headerName of ['content-type', 'content-length', 'cache-control', 'etag']) {
        const value = upstream.headers.get(headerName);
        if (value) {
          reply.header(headerName, value);
        }
      }

      const proxiedBody = Readable.fromWeb(upstream.body);
      proxiedBody.on('error', (streamError) => {
        if (isAbortError(streamError) || isUpstreamTerminationError(streamError) || isClientDisconnected(request, reply)) {
          return;
        }
        request.log.warn(streamError, 'Upstream stream error while proxying cover art');
      });
      return reply.send(proxiedBody);
    } catch (error) {
      request.log.error(error, 'Failed to proxy cover art');
      return sendSubsonicError(reply, 10, 'Cover art proxy failed');
    }
  });

  app.get('/rest/download.view', async (request, reply) => {
    const account = await authenticateSubsonicRequest(request, reply, repo, tokenCipher);
    if (!account) {
      return;
    }

    const rawTrackId = String(getQueryString(request, 'id') || '').trim();
    if (!rawTrackId) {
      return sendSubsonicError(reply, 70, 'Missing track id');
    }

    const context = repo.getAccountPlexContext(account.id);
    const plexState = requiredPlexStateForSubsonic(reply, context, tokenCipher);
    if (!plexState) {
      return;
    }

    let trackId = rawTrackId;
    try {
      trackId = await resolveCachedLibraryRatingKey({
        accountId: account.id,
        plexState,
        request,
        collection: 'tracks',
        id: rawTrackId,
      }) || rawTrackId;
      const track = await getTrack({
        baseUrl: plexState.baseUrl,
        plexToken: plexState.plexToken,
        trackId,
      });

      if (!track) {
        return sendSubsonicError(reply, 70, 'Track not found');
      }

      const part = partFromTrack(track);
      const partKey = part?.key;

      if (!partKey) {
        return sendSubsonicError(reply, 70, 'Track has no downloadable part');
      }

      const streamUrl = buildPmsAssetUrl(plexState.baseUrl, plexState.plexToken, partKey);
      const rangeHeader = request.headers.range;
      const upstreamController = new AbortController();
      const abortUpstreamOnDisconnect = () => {
        if (!upstreamController.signal.aborted) {
          upstreamController.abort();
        }
      };
      request.raw.once('aborted', abortUpstreamOnDisconnect);
      reply.raw.once('close', abortUpstreamOnDisconnect);

      const upstream = await fetchWithRetry({
        url: streamUrl,
        options: {
          headers: {
            ...(rangeHeader ? { Range: rangeHeader } : {}),
          },
          signal: upstreamController.signal,
        },
        request,
        context: 'track download proxy',
        maxAttempts: 3,
        baseDelayMs: 250,
      });

      if (!upstream.ok || !upstream.body) {
        request.log.warn({ status: upstream.status }, 'Failed to proxy track download');
        return sendSubsonicError(reply, 70, 'Track download unavailable');
      }

      reply.code(upstream.status);

      for (const headerName of [
        'content-type',
        'content-length',
        'content-range',
        'accept-ranges',
        'etag',
        'last-modified',
      ]) {
        const value = upstream.headers.get(headerName);
        if (value) {
          reply.header(headerName, value);
        }
      }

      const fileName = part?.file ? part.file.split(/[/\\]/).pop() : null;
      if (fileName) {
        reply.header(
          'content-disposition',
          `attachment; filename*=UTF-8''${encodeURIComponent(fileName)}`,
        );
      }

      const proxiedBody = Readable.fromWeb(upstream.body);
      const responseBody = new PassThrough();

      proxiedBody.on('error', (streamError) => {
        if (
          isAbortError(streamError) ||
          isUpstreamTerminationError(streamError) ||
          isClientDisconnected(request, reply)
        ) {
          responseBody.end();
          return;
        }
        request.log.warn(streamError, 'Upstream stream error while proxying track download');
        responseBody.destroy(streamError);
      });

      responseBody.on('error', (streamError) => {
        if (
          isAbortError(streamError) ||
          isUpstreamTerminationError(streamError) ||
          isClientDisconnected(request, reply)
        ) {
          return;
        }
        request.log.warn(streamError, 'Response stream error while proxying track download');
      });

      proxiedBody.pipe(responseBody);
      return reply.send(responseBody);
    } catch (error) {
      if (isClientDisconnected(request, reply)) {
        return;
      }
      if (isAbortError(error) || isUpstreamTerminationError(error)) {
        request.log.warn({ err: error, trackId }, 'Upstream download stream terminated before completion');
        return sendSubsonicError(reply, 70, 'Track download unavailable');
      }
      request.log.error(error, 'Failed to proxy download');
      return sendSubsonicError(reply, 10, 'Download proxy failed');
    }
  });

  app.get('/rest/stream.view', async (request, reply) => {
    const account = await authenticateSubsonicRequest(request, reply, repo, tokenCipher);
    if (!account) {
      return;
    }

    const rawTrackId = String(getQueryString(request, 'id') || '').trim();
    if (!rawTrackId) {
      return sendSubsonicError(reply, 70, 'Missing track id');
    }

    const context = repo.getAccountPlexContext(account.id);
    const plexState = requiredPlexStateForSubsonic(reply, context, tokenCipher);
    if (!plexState) {
      return;
    }

    try {
      const trackId = await resolveCachedLibraryRatingKey({
        accountId: account.id,
        plexState,
        request,
        collection: 'tracks',
        id: rawTrackId,
      }) || rawTrackId;
      const track = await getTrack({
        baseUrl: plexState.baseUrl,
        plexToken: plexState.plexToken,
        trackId,
      });

      if (!track) {
        return sendSubsonicError(reply, 70, 'Track not found');
      }

      const part = partFromTrack(track);
      const partKey = part?.key;

      if (!partKey) {
        return sendSubsonicError(reply, 70, 'Track has no playable part');
      }

      const transcodePlan = resolveStreamTranscodePlan({ request, track });
      const clientName = getRequestParam(request, 'c') || 'Subsonic Client';
      const playbackClient = playbackClientContext(account.id, clientName);
      const { state: continuityState } = getPlaybackContinuityState(account.id, clientName);
      const streamPlaybackAuthorityDisabled = Number(continuityState.at || 0) > 0;
      const suppressStreamLoadPlaybackSync = shouldSuppressPlaybackSyncForStreamLoad({
        accountId: account.id,
        clientName,
        trackId,
      }) || streamPlaybackAuthorityDisabled;
      const offsetRaw = getRequestParam(request, 'timeOffset');
      const offsetSeconds = Number.parseFloat(offsetRaw);
      const offsetMs = Number.isFinite(offsetSeconds) && offsetSeconds > 0 ? Math.round(offsetSeconds * 1000) : 0;
      const trackDurationMs = parseNonNegativeInt(track.duration, 0);
      const contentDurationHeader = formatContentDurationHeader(trackDurationMs);
      const playbackStartAt = Date.now();

      if (streamPlaybackAuthorityDisabled) {
        updatePlaybackSessionEstimateFromStream({
          accountId: account.id,
          clientName,
          trackId,
          durationMs: trackDurationMs > 0 ? trackDurationMs : null,
          positionMs: offsetMs,
        });
      }

      const estimatePlaybackPositionMs = (nowMs = Date.now()) => {
        const elapsedMs = Math.max(0, nowMs - playbackStartAt);
        const estimated = offsetMs + elapsedMs;
        if (trackDurationMs > 0) {
          return Math.max(0, Math.min(trackDurationMs, estimated));
        }
        return Math.max(0, estimated);
      };

      let progressTimer = null;
      let progressSyncInFlight = false;
      const clearProgressTimer = () => {
        if (progressTimer) {
          clearInterval(progressTimer);
          progressTimer = null;
        }
      };
      let streamClosed = false;
      let streamTrackingStarted = false;
      let suppressedPromoteTimer = null;
      const clearSuppressedPromoteTimer = () => {
        if (suppressedPromoteTimer) {
          clearTimeout(suppressedPromoteTimer);
          suppressedPromoteTimer = null;
        }
      };

      const startStreamPlaybackTracking = async (positionMs) => {
        if (streamTrackingStarted || streamClosed) {
          return;
        }
        streamTrackingStarted = true;

        try {
          await syncClientPlaybackState({
            accountId: account.id,
            plexState,
            clientName,
            itemId: trackId,
            state: 'playing',
            positionMs,
            durationMs: trackDurationMs,
            request,
          });
        } catch (error) {
          request.log.warn(error, 'Failed to sync stream-start playback status to Plex');
        }

        progressTimer = setInterval(async () => {
          if (progressSyncInFlight) {
            return;
          }

          const current = playbackSessions.get(playbackClient.sessionKey);
          if (!current || current.itemId !== String(trackId) || current.state !== 'playing') {
            return;
          }

          progressSyncInFlight = true;
          try {
            await syncClientPlaybackState({
              accountId: account.id,
              plexState,
              clientName,
              itemId: trackId,
              state: 'playing',
              positionMs: estimatePlaybackPositionMs(),
              durationMs: trackDurationMs,
              request,
            });
          } catch (error) {
            request.log.warn(error, 'Failed to sync stream progress playback status to Plex');
          } finally {
            progressSyncInFlight = false;
          }
        }, STREAM_PROGRESS_HEARTBEAT_MS);

        if (typeof progressTimer.unref === 'function') {
          progressTimer.unref();
        }
      };

      const handleStreamClosed = () => {
        if (streamClosed) {
          return;
        }
        streamClosed = true;

        const closedAt = Date.now();
        clearProgressTimer();
        clearSuppressedPromoteTimer();
        const estimatedAtClose = estimatePlaybackPositionMs(closedAt);
        let currentAtClose = playbackSessions.get(playbackClient.sessionKey);
        if (currentAtClose && currentAtClose.itemId === String(trackId) && currentAtClose.state === 'playing') {
          currentAtClose = {
            ...currentAtClose,
            positionMs: Math.max(Number(currentAtClose.positionMs || 0), estimatedAtClose),
            durationMs: trackDurationMs > 0 ? trackDurationMs : currentAtClose.durationMs,
            estimatedStopAt:
              trackDurationMs > 0
                ? closedAt + Math.max(0, trackDurationMs - Math.max(Number(currentAtClose.positionMs || 0), estimatedAtClose))
                : currentAtClose.estimatedStopAt,
            updatedAt: closedAt,
          };
          playbackSessions.set(playbackClient.sessionKey, currentAtClose);
        }

        const disconnectDelay = (() => {
          if (
            currentAtClose?.state === 'playing' &&
            Number.isFinite(currentAtClose.estimatedStopAt) &&
            currentAtClose.estimatedStopAt > closedAt
          ) {
            return Math.min(
              PLAYBACK_MAX_DISCONNECT_WAIT_MS,
              Math.max(STREAM_DISCONNECT_STOP_DELAY_MS, currentAtClose.estimatedStopAt - closedAt),
            );
          }
          return STREAM_DISCONNECT_STOP_DELAY_MS;
        })();

        const timer = setTimeout(async () => {
          const current = playbackSessions.get(playbackClient.sessionKey);
          if (!current || current.itemId !== String(trackId)) {
            return;
          }
          if (current.state !== 'playing') {
            return;
          }
          if (Number(current.updatedAt || 0) > closedAt) {
            return;
          }

          const stopAt = Date.now();
          const knownDurationMs = Number(current.durationMs || 0);
          let finalPositionMs = Number(current.positionMs || 0);
          const elapsedSinceLastUpdate = Math.max(0, stopAt - Number(current.updatedAt || stopAt));
          finalPositionMs += elapsedSinceLastUpdate;
          if (knownDurationMs > 0) {
            finalPositionMs = Math.min(knownDurationMs, finalPositionMs);
          }

          try {
            await syncClientPlaybackState({
              accountId: account.id,
              plexState,
              clientName,
              itemId: trackId,
              state: 'playing',
              positionMs: finalPositionMs,
              durationMs: knownDurationMs > 0 ? knownDurationMs : null,
              request,
            });

            await syncClientPlaybackState({
              accountId: account.id,
              plexState,
              clientName,
              itemId: trackId,
              state: 'stopped',
              positionMs: finalPositionMs,
              request,
            });
          } catch (error) {
            request.log.warn(error, 'Failed to stop playback after stream disconnect');
          }
        }, disconnectDelay);

        if (typeof timer.unref === 'function') {
          timer.unref();
        }
      };
      if (!streamPlaybackAuthorityDisabled) {
        reply.raw.once('close', handleStreamClosed);
        reply.raw.once('finish', handleStreamClosed);
      }

      if (suppressStreamLoadPlaybackSync) {
        request.log.debug(
          { trackId, clientName, streamPlaybackAuthorityDisabled },
          'Suppressing immediate stream-start playback sync; awaiting continuity/persistence',
        );

        suppressedPromoteTimer = setTimeout(async () => {
          if (streamClosed || streamTrackingStarted) {
            return;
          }

          const stillSuppressed = shouldSuppressPlaybackSyncForStreamLoad({
            accountId: account.id,
            clientName,
            trackId,
          });
          if (!stillSuppressed) {
            void startStreamPlaybackTracking(estimatePlaybackPositionMs());
            return;
          }

          const hasScrobbleDrivenContinuity = Number(continuityState.at || 0) > 0;
          if (hasScrobbleDrivenContinuity) {
            request.log.debug(
              { trackId, clientName },
              'Keeping suppressed stream pending explicit scrobble/queue continuity',
            );
            return;
          }

          // Fallback only for clients that never provide continuity signals.
          void startStreamPlaybackTracking(estimatePlaybackPositionMs());
        }, STREAM_SUPPRESSED_PROMOTE_DELAY_MS);

        if (typeof suppressedPromoteTimer.unref === 'function') {
          suppressedPromoteTimer.unref();
        }
      } else {
        void startStreamPlaybackTracking(offsetMs);
      }

      if (transcodePlan) {
        return await streamTrackWithLocalTranscode({
          request,
          reply,
          plexState,
          track,
          trackId,
          part,
          partKey,
          plan: transcodePlan,
          cacheRoot: transcodeCacheRoot,
        });
      }

      const streamUrl = buildPmsAssetUrl(plexState.baseUrl, plexState.plexToken, partKey);
      const rangeHeader = request.headers.range;
      const upstreamController = new AbortController();
      const abortUpstreamOnDisconnect = () => {
        if (!upstreamController.signal.aborted) {
          upstreamController.abort();
        }
      };
      request.raw.once('aborted', abortUpstreamOnDisconnect);
      reply.raw.once('close', abortUpstreamOnDisconnect);

      const upstream = await fetchWithRetry({
        url: streamUrl,
        options: {
          headers: {
            ...(rangeHeader ? { Range: rangeHeader } : {}),
          },
          signal: upstreamController.signal,
        },
        request,
        context: 'track stream proxy',
        maxAttempts: 3,
        baseDelayMs: 250,
      });

      if (!upstream.ok || !upstream.body) {
        clearProgressTimer();
        clearSuppressedPromoteTimer();
        request.log.warn({ status: upstream.status }, 'Failed to proxy track stream');
        return sendSubsonicError(reply, 70, 'Track stream unavailable');
      }

      reply.code(upstream.status);

      for (const headerName of [
        'content-type',
        'content-length',
        'content-range',
        'accept-ranges',
        'etag',
        'last-modified',
      ]) {
        const value = upstream.headers.get(headerName);
        if (value) {
          reply.header(headerName, value);
        }
      }
      if (contentDurationHeader) {
        reply.header('x-content-duration', contentDurationHeader);
      }

      const proxiedBody = Readable.fromWeb(upstream.body);
      const responseBody = new PassThrough();

      proxiedBody.on('error', (streamError) => {
        if (isAbortError(streamError) || isUpstreamTerminationError(streamError) || isClientDisconnected(request, reply)) {
          request.log.debug({ trackId, clientName }, 'Ignoring expected stream termination');
          responseBody.end();
          return;
        }
        request.log.warn(streamError, 'Upstream stream error while proxying track');
        responseBody.destroy(streamError);
      });

      responseBody.on('error', (streamError) => {
        if (isAbortError(streamError) || isUpstreamTerminationError(streamError) || isClientDisconnected(request, reply)) {
          request.log.debug({ trackId, clientName }, 'Ignoring expected response stream termination');
          return;
        }
        request.log.warn(streamError, 'Response stream error while proxying track');
      });

      proxiedBody.pipe(responseBody);
      return reply.send(responseBody);
    } catch (error) {
      if (isClientDisconnected(request, reply)) {
        request.log.debug({ trackId }, 'Ignoring expected stream disconnect');
        return;
      }
      if (isAbortError(error) || isUpstreamTerminationError(error)) {
        request.log.warn({ err: error, trackId }, 'Upstream stream terminated before completion');
        return sendSubsonicError(reply, 70, 'Track stream unavailable');
      }
      request.log.error(error, 'Failed to stream track');
      return sendSubsonicError(reply, 10, 'Track stream failed');
    }
  });

  app.get('/rest/*', async (request, reply) => {
    const endpointPath = String(request.url || '').split('?')[0] || '/rest/unknown';
    return sendSubsonicError(reply, 10, `Endpoint not implemented: ${endpointPath}`);
  });

  warmAllLinkedLibraryCaches('startup').catch((error) => {
    app.log.warn(error, 'Startup library cache warm-up failed');
  });

  return app;
}
