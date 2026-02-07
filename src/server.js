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

import { createHash, randomUUID } from 'node:crypto';
import { Readable } from 'node:stream';
import Fastify from 'fastify';
import argon2 from 'argon2';
import fastifyCookie from '@fastify/cookie';
import fastifyFormbody from '@fastify/formbody';
import fastifySession from '@fastify/session';
import { loadConfig } from './config.js';
import { createRepositories, migrate, openDatabase } from './db.js';
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
  ratePlexItem,
  removePlexPlaylistItems,
  renamePlexPlaylist,
  searchSectionHubs,
  searchSectionMetadata,
  scrobblePlexItem,
  updatePlexPlaybackStatus,
} from './plex.js';
import { createTokenCipher } from './token-crypto.js';
import { emptyNode, failedResponse, failedResponseJson, node, okResponse, okResponseJson } from './subsonic-xml.js';

const USERNAME_PATTERN = /^[A-Za-z0-9_.-]{3,32}$/;

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
      } catch {}
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

    if (!account.subsonic_password_enc) {
      repo.updateSubsonicPasswordEnc(account.id, tokenCipher.encrypt(decodedPassword));
    }

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
    const artistsXml = groups
      .get(key)
      .sort((a, b) => a.name.localeCompare(b.name))
      .map((artist) =>
        emptyNode('artist', {
          id: artist.id,
          name: artist.name,
          albumCount: artistAlbumCountValue(artist.artist),
          coverArt: artist.id,
          ...subsonicRatingAttrs(artist.artist),
        }),
      )
      .join('');

    return node('index', { name: key }, artistsXml);
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
    const itemsXml = groups
      .get(key)
      .sort((a, b) => a.name.localeCompare(b.name))
      .map((item) =>
        emptyNode('artist', {
          id: item.id,
          name: item.name,
          coverArt: item.coverArt,
        }),
      )
      .join('');

    return node('index', { name: key }, itemsXml);
  });
}

function mediaFromTrack(track) {
  return Array.isArray(track.Media) ? track.Media[0] : null;
}

function partFromTrack(track) {
  const media = mediaFromTrack(track);
  return Array.isArray(media?.Part) ? media.Part[0] : null;
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
  return fallback;
}

function normalizePlexRating(value) {
  const parsed = Number.parseFloat(String(value ?? ''));
  if (!Number.isFinite(parsed)) {
    return null;
  }
  return Math.max(0, Math.min(parsed, 10));
}

function plexRatingToSubsonic(value) {
  const normalized = normalizePlexRating(value);
  if (normalized == null) {
    return undefined;
  }
  return Math.round(normalized / 2);
}

function subsonicRatingAttrs(item) {
  const plexRating = normalizePlexRating(item?.userRating);
  if (plexRating == null) {
    return {};
  }

  const attrs = {
    userRating: plexRatingToSubsonic(plexRating),
  };

  if (plexRating >= 9) {
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

  return {
    id: albumId,
    parent: album.parentRatingKey || fallbackArtistId || undefined,
    isDir: true,
    title,
    name: title,
    album: title,
    artist: artistName,
    artistId: album.parentRatingKey || fallbackArtistId || undefined,
    coverArt: albumId || undefined,
    songCount: album.leafCount || album.childCount || undefined,
    duration: durationSeconds(album.duration),
    created: toIsoFromEpochSeconds(album.addedAt),
    year: album.year,
    ...subsonicRatingAttrs(album),
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
  const genre = firstGenreTag(album) || undefined;
  const played = toIsoFromEpochSeconds(album?.lastViewedAt);

  return {
    id: albumId,
    name,
    artist: artistName,
    artistId: album.parentRatingKey || fallbackArtistId || undefined,
    coverArt: albumId || undefined,
    songCount: songCount || undefined,
    duration: durationSeconds(album.duration),
    playCount: playCount || undefined,
    played,
    created: toIsoFromEpochSeconds(album.addedAt),
    year: album.year,
    genre,
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
    [track?.grandparentTitle, track?.originalTitle],
    'Unknown Artist',
  );
  const coverArt = firstNonEmptyText(
    [albumCoverArt, track?.parentRatingKey, track?.ratingKey],
    undefined,
  );
  const genreTags = allGenreTags(track);
  const genre = genreTags[0] || undefined;
  const genres = genreTags.length > 0 ? genreTags.join('; ') : undefined;
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
  const style = metadataFieldText([track, albumMetadata], ['Style', 'style']);
  const moodValues = metadataFieldValues([track, albumMetadata], ['Mood', 'mood']);
  const mood = moodValues[0] || undefined;
  const moods = moodValues.length > 0 ? moodValues.join('; ') : undefined;
  const language =
    metadataFieldText([track, albumMetadata], ['Language', 'language', 'Lang', 'lang']) || streamLanguage;
  const albumType = metadataFieldText(
    [albumMetadata, track],
    ['albumType', 'AlbumType', 'subtype', 'subType', 'parentSubtype', 'format'],
  );
  const trackNumber = parsePositiveInt(track?.index ?? track?.track, 0);
  const playCount = parseNonNegativeInt(track?.viewCount ?? track?.playCount, 0);
  const played = toIsoFromEpochSeconds(track?.lastViewedAt);

  return {
    id: trackId,
    parent: albumId,
    isDir: false,
    title,
    name: title,
    album: normalizedAlbumTitle,
    albumId,
    artist: normalizedArtist,
    artistId: track.grandparentRatingKey || undefined,
    type: 'music',
    duration: durationSeconds(track.duration),
    track: trackNumber,
    discNumber,
    discSubtitle,
    contentType: detectContentType(track),
    suffix: detectAudioSuffix(track),
    size: part?.size,
    bitRate: media?.bitrate,
    coverArt,
    genre,
    genres,
    country,
    style,
    mood,
    moods,
    language,
    albumType,
    year: track.year,
    played,
    created: toIsoFromEpochSeconds(track.addedAt),
    playCount: playCount || undefined,
    ...subsonicRatingAttrs(track),
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
          'Mood',
          'mood',
          'Language',
          'language',
          'Lang',
          'lang',
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
    const normalizedSynced = synced || lines.some((line) => Number.isFinite(line.start));
    const signature = JSON.stringify({
      lang: normalizedLang,
      synced: normalizedSynced,
      offset: Number.isFinite(offset) ? Math.trunc(offset) : null,
      lines: lines.map((line) => ({
        value: String(line.value || ''),
        start: Number.isFinite(line.start) ? Math.trunc(line.start) : null,
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
      lines: lines.map((line) => {
        const start = Number.isFinite(line.start) ? Math.trunc(line.start) : undefined;
        if (start === undefined) {
          return { value: String(line.value || '') };
        }
        return { value: String(line.value || ''), start };
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

function safeLower(value) {
  return String(value || '').toLowerCase();
}

function includesText(haystack, needle) {
  return safeLower(haystack).includes(safeLower(needle));
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
      list = list.filter((album) => normalizePlexRating(album?.userRating) >= 9);
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
  const pushTag = (value) => {
    const text = String(value || '').trim();
    if (!text) {
      return;
    }
    tags.push(text);
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
    const raw = String(plainGenre);
    if (raw.includes(';')) {
      for (const part of raw.split(';')) {
        pushTag(part);
      }
    } else {
      pushTag(raw);
    }
  }

  return [...new Set(tags)];
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

  const plexTokenCandidates = [];
  if (plexContext.server_token_enc) {
    try {
      const serverToken = decodePlexTokenOrThrow(tokenCipher, plexContext.server_token_enc);
      plexTokenCandidates.push(serverToken);
    } catch {}
  }
  if (plexContext.plex_token_enc) {
    try {
      const accountToken = decodePlexTokenOrThrow(tokenCipher, plexContext.plex_token_enc);
      plexTokenCandidates.push(accountToken);
    } catch {}
  }

  const plexToken = uniqueNonEmptyValues(plexTokenCandidates);
  if (plexToken.length === 0) {
    sendSubsonicError(reply, 10, 'Stored Plex token is unreadable');
    return null;
  }

  return {
    accountId: plexContext.account_id,
    username: plexContext.username,
    plexToken,
    baseUrl: plexContext.server_base_url,
    machineId: plexContext.machine_id,
    musicSectionId: plexContext.music_section_id,
    serverName: plexContext.server_name || 'Plex Music',
  };
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

  if (!tokenCipher.hasExplicitKey) {
    app.log.warn('TOKEN_ENC_KEY missing or invalid. Falling back to hash of SESSION_SECRET for token encryption.');
  }

  await app.register(fastifyCookie);
  await app.register(fastifyFormbody);
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

  app.addHook('onClose', async () => {
    db.close();
  });

  const playbackSessions = new Map();
  const PLAYBACK_RECONCILE_INTERVAL_MS = 15000;
  const PLAYBACK_IDLE_TIMEOUT_MS = 120000;
  const STREAM_DISCONNECT_STOP_DELAY_MS = 4000;
  const PLAYBACK_MAX_DISCONNECT_WAIT_MS = 30 * 60 * 1000;
  const STREAM_PROGRESS_HEARTBEAT_MS = 10000;
  const activeSearchRequests = new Map();
  const searchBrowseCache = new Map();
  const SEARCH_BROWSE_CACHE_TTL_MS = 15000;
  const SEARCH_BROWSE_CACHE_MAX_ENTRIES = 16;

  function pruneSearchBrowseCache(now = Date.now()) {
    for (const [cacheKey, entry] of searchBrowseCache.entries()) {
      if (!entry || entry.expiresAt <= now) {
        searchBrowseCache.delete(cacheKey);
      }
    }

    if (searchBrowseCache.size <= SEARCH_BROWSE_CACHE_MAX_ENTRIES) {
      return;
    }

    const sortedByExpiry = [...searchBrowseCache.entries()]
      .sort((a, b) => (a[1]?.expiresAt || 0) - (b[1]?.expiresAt || 0));
    for (const [cacheKey] of sortedByExpiry) {
      if (searchBrowseCache.size <= SEARCH_BROWSE_CACHE_MAX_ENTRIES) {
        break;
      }
      searchBrowseCache.delete(cacheKey);
    }
  }

  function searchBrowseCacheKey(accountId, plexState) {
    return `${accountId}:${plexState.machineId}:${plexState.musicSectionId}`;
  }

  function getSearchBrowseCacheEntry(cacheKey) {
    const now = Date.now();
    const existing = searchBrowseCache.get(cacheKey);
    if (existing && existing.expiresAt > now) {
      existing.expiresAt = now + SEARCH_BROWSE_CACHE_TTL_MS;
      return existing;
    }

    if (existing) {
      searchBrowseCache.delete(cacheKey);
    }

    const created = {
      expiresAt: now + SEARCH_BROWSE_CACHE_TTL_MS,
      artists: null,
      albums: null,
      tracks: null,
      loadingArtists: null,
      loadingAlbums: null,
      loadingTracks: null,
    };
    searchBrowseCache.set(cacheKey, created);
    pruneSearchBrowseCache(now);
    return created;
  }

  async function getSearchBrowseCollection({ cacheKey, collection, loader }) {
    const entry = getSearchBrowseCacheEntry(cacheKey);
    if (Array.isArray(entry[collection])) {
      return entry[collection];
    }

    const loadingKey = `loading${collection[0].toUpperCase()}${collection.slice(1)}`;
    if (entry[loadingKey]) {
      return entry[loadingKey];
    }

    const pending = (async () => {
      const loaded = await loader();
      return Array.isArray(loaded) ? loaded : [];
    })();
    entry[loadingKey] = pending;

    try {
      const loaded = await pending;
      entry[collection] = loaded;
      entry.expiresAt = Date.now() + SEARCH_BROWSE_CACHE_TTL_MS;
      return loaded;
    } finally {
      if (entry[loadingKey] === pending) {
        entry[loadingKey] = null;
      }
    }
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

  const playbackMaintenanceTimer = setInterval(async () => {
    const now = Date.now();
    const sessions = [...playbackSessions.entries()];

    for (const [sessionKey, session] of sessions) {
      if (!session || session.state === 'stopped') {
        playbackSessions.delete(sessionKey);
        continue;
      }

      if (now - Number(session.updatedAt || 0) > PLAYBACK_IDLE_TIMEOUT_MS) {
        if (
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

    if (!account.subsonic_password_enc) {
      repo.updateSubsonicPasswordEnc(account.id, tokenCipher.encrypt(password));
    }

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

    if (!account.subsonic_password_enc) {
      repo.updateSubsonicPasswordEnc(account.id, tokenCipher.encrypt(password));
    }

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
      } catch {}
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
      node(
        'openSubsonicExtensions',
        {},
        emptyNode('openSubsonicExtension', {
          name: 'songLyrics',
          versions: [1],
        }),
      ),
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
      emptyNode('license', attrs),
    );
  });

  app.get('/rest/ping.view', async (request, reply) => {
    const account = await authenticateSubsonicRequest(request, reply, repo, tokenCipher);
    if (!account) {
      return;
    }

    return sendSubsonicOk(reply, emptyNode('ping'));
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

    const inner = node(
      'musicFolders',
      {},
      emptyNode('musicFolder', { id: plexState.musicSectionId, name: plexState.serverName }),
    );
    return sendSubsonicOk(reply, inner);
  });

  app.get('/rest/getUser.view', async (request, reply) => {
    const account = await authenticateSubsonicRequest(request, reply, repo, tokenCipher);
    if (!account) {
      return;
    }

    return sendSubsonicOk(
      reply,
      emptyNode('user', {
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
      }),
    );
  });

  app.get('/rest/getNowPlaying.view', async (request, reply) => {
    const account = await authenticateSubsonicRequest(request, reply, repo, tokenCipher);
    if (!account) {
      return;
    }

    return sendSubsonicOk(reply, node('nowPlaying'));
  });

  app.get('/rest/getScanStatus.view', async (request, reply) => {
    const account = await authenticateSubsonicRequest(request, reply, repo, tokenCipher);
    if (!account) {
      return;
    }

    return sendSubsonicOk(
      reply,
      emptyNode('scanStatus', {
        scanning: false,
        count: 0,
      }),
    );
  });

  app.get('/rest/startScan.view', async (request, reply) => {
    const account = await authenticateSubsonicRequest(request, reply, repo, tokenCipher);
    if (!account) {
      return;
    }

    return sendSubsonicOk(
      reply,
      emptyNode('scanStatus', {
        scanning: false,
        count: 0,
      }),
    );
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
        listArtists({
          baseUrl: plexState.baseUrl,
          plexToken: plexState.plexToken,
          sectionId: plexState.musicSectionId,
        }),
        listAlbums({
          baseUrl: plexState.baseUrl,
          plexToken: plexState.plexToken,
          sectionId: plexState.musicSectionId,
        }),
        listTracks({
          baseUrl: plexState.baseUrl,
          plexToken: plexState.plexToken,
          sectionId: plexState.musicSectionId,
        }),
      ]);

      const starredArtists = artists
        .filter((artist) => normalizePlexRating(artist.userRating) >= 9)
        .map((artist) =>
          emptyNode('artist', {
            id: artist.ratingKey,
            name: artist.title,
            coverArt: artist.ratingKey,
            ...subsonicRatingAttrs(artist),
          }),
        )
        .join('');

      const starredAlbums = albums
        .filter((album) => normalizePlexRating(album.userRating) >= 9)
        .map((album) => emptyNode('album', albumAttrs(album)))
        .join('');

      const starredSongs = tracks
        .filter((track) => normalizePlexRating(track.userRating) >= 9)
        .map((track) => emptyNode('song', songAttrs(track)))
        .join('');

      return sendSubsonicOk(reply, node('starred', {}, `${starredArtists}${starredAlbums}${starredSongs}`));
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
        listArtists({
          baseUrl: plexState.baseUrl,
          plexToken: plexState.plexToken,
          sectionId: plexState.musicSectionId,
        }),
        listAlbums({
          baseUrl: plexState.baseUrl,
          plexToken: plexState.plexToken,
          sectionId: plexState.musicSectionId,
        }),
        listTracks({
          baseUrl: plexState.baseUrl,
          plexToken: plexState.plexToken,
          sectionId: plexState.musicSectionId,
        }),
      ]);

      const starredArtists = artists
        .filter((artist) => normalizePlexRating(artist.userRating) >= 9)
        .map((artist) =>
          emptyNode('artist', {
            id: artist.ratingKey,
            name: artist.title,
            albumCount: artistAlbumCountValue(artist),
            coverArt: artist.ratingKey,
            ...subsonicRatingAttrs(artist),
          }),
        )
        .join('');

      const starredAlbums = albums
        .filter((album) => normalizePlexRating(album.userRating) >= 9)
        .map((album) => emptyNode('album', albumId3Attrs(album)))
        .join('');

      const starredSongs = tracks
        .filter((track) => normalizePlexRating(track.userRating) >= 9)
        .map((track) => emptyNode('song', songAttrs(track)))
        .join('');

      return sendSubsonicOk(reply, node('starred2', {}, `${starredArtists}${starredAlbums}${starredSongs}`));
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
        const albums = await listAlbums({
          baseUrl: plexState.baseUrl,
          plexToken: plexState.plexToken,
          sectionId: plexState.musicSectionId,
        });

        const counts = new Map();
        for (const album of albums) {
          const albumSongCount = Math.max(1, Number.parseInt(String(album?.leafCount ?? ''), 10) || 0);
          for (const tag of allGenreTags(album)) {
            const normalized = tag.trim();
            if (!normalized) {
              continue;
            }
            const key = safeLower(normalized);
            const current = counts.get(key) || {
              name: normalized,
              songCount: 0,
              albumCount: 0,
            };
            current.songCount += albumSongCount;
            current.albumCount += 1;
            counts.set(key, current);
          }
        }

        const genresXml = [...counts.values()]
          .sort((a, b) => a.name.localeCompare(b.name))
          .map((genre) =>
            node(
              'genre',
              {
                songCount: genre.songCount,
                albumCount: genre.albumCount,
              },
              genre.name,
            ),
          )
          .join('');

        return sendSubsonicOk(reply, node('genres', {}, genresXml));
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
        const albums = await listAlbums({
          baseUrl: plexState.baseUrl,
          plexToken: plexState.plexToken,
          sectionId: plexState.musicSectionId,
        });

        const matchedAlbums = albums.filter((album) =>
          allGenreTags(album).some((tag) => safeLower(tag.trim()) === safeLower(genre)),
        );

        const songs = [];
        for (const album of matchedAlbums) {
          const tracks = await listAlbumTracks({
            baseUrl: plexState.baseUrl,
            plexToken: plexState.plexToken,
            albumId: album.ratingKey,
          });

          for (const track of tracks) {
            songs.push(track);
          }

          if (songs.length >= offset + count) {
            break;
          }
        }

        const page = takePage(songs, offset, count);
        const songXml = page.map((track) => emptyNode('song', songAttrs(track))).join('');
        return sendSubsonicOk(reply, node('songsByGenre', {}, songXml));
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
      const allTracks = await listTracks({
        baseUrl: plexState.baseUrl,
        plexToken: plexState.plexToken,
        sectionId: plexState.musicSectionId,
      });

      const randomTracks = shuffleInPlace(allTracks.slice()).slice(0, size);
      const songXml = randomTracks.map((track) => emptyNode('song', songAttrs(track))).join('');
      return sendSubsonicOk(reply, node('randomSongs', {}, songXml));
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
      const artists = await listArtists({
        baseUrl: plexState.baseUrl,
        plexToken: plexState.plexToken,
        sectionId: plexState.musicSectionId,
      });

      const artist =
        artists.find((item) => safeLower(item.title) === safeLower(artistName)) ||
        artists.find((item) => includesText(item.title, artistName));
      if (!artist) {
        return sendSubsonicOk(reply, node('topSongs'));
      }

      const tracks = await listArtistTracks({
        baseUrl: plexState.baseUrl,
        plexToken: plexState.plexToken,
        artistId: artist.ratingKey,
      });

      const topTracks = tracks.slice(0, size);
      const songXml = topTracks.map((track) => emptyNode('song', songAttrs(track))).join('');
      return sendSubsonicOk(reply, node('topSongs', {}, songXml));
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

        const songXml = tracks.map((track) => emptyNode('song', songAttrs(track))).join('');
        return sendSubsonicOk(reply, node('similarSongs', {}, songXml));
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

        const songXml = tracks.map((track) => emptyNode('song', songAttrs(track))).join('');
        return sendSubsonicOk(reply, node('similarSongs2', {}, songXml));
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

    const id = getRequestParam(request, 'id');
    if (!id) {
      return sendSubsonicError(reply, 70, 'Missing song id');
    }

    const context = repo.getAccountPlexContext(account.id);
    const plexState = requiredPlexStateForSubsonic(reply, context, tokenCipher);
    if (!plexState) {
      return;
    }

    try {
      const track = await getTrack({
        baseUrl: plexState.baseUrl,
        plexToken: plexState.plexToken,
        trackId: id,
      });
      if (!track) {
        return sendSubsonicError(reply, 70, 'Song not found');
      }

      return sendSubsonicOk(reply, node('song', songAttrs(track)));
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
        return sendSubsonicOk(reply, emptyNode('lyrics'));
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
            emptyNode('lyrics', {
              artist: artistQuery || undefined,
              title: titleQuery || undefined,
              value: '',
            }),
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
          emptyNode('lyrics', {
            artist: finalArtist,
            title: finalTitle,
            value: plainLyrics.value,
          }),
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

      const id = getRequestParam(request, 'id');
      if (!id) {
        return sendSubsonicError(reply, 10, 'Required parameter is missing');
      }

      const context = repo.getAccountPlexContext(account.id);
      const plexState = requiredPlexStateForSubsonic(reply, context, tokenCipher);
      if (!plexState) {
        return;
      }
      const lyricsScope = beginSearchRequest(request, account.id);

      try {
        const track = await getTrack({
          baseUrl: plexState.baseUrl,
          plexToken: plexState.plexToken,
          trackId: id,
          signal: lyricsScope.signal,
        });

        if (!track) {
          return sendSubsonicError(reply, 70, 'Song not found');
        }

        const lyricCandidates = await fetchPlexTrackLyricsCandidates({
          baseUrl: plexState.baseUrl,
          plexToken: plexState.plexToken,
          trackId: id,
          signal: lyricsScope.signal,
        });

        const structuredLyrics = extractStructuredLyricsFromTrack(track, lyricCandidates);
        const structuredLyricsXml = structuredLyrics
          .map((lyrics) => {
            const lineXml = lyrics.lines
              .map((line) =>
                node(
                  'line',
                  {
                    start: line.start,
                  },
                  line.value,
                ),
              )
              .join('');

            return node(
              'structuredLyrics',
              {
                displayArtist: lyrics.displayArtist,
                displayTitle: lyrics.displayTitle,
                lang: lyrics.lang,
                synced: lyrics.synced,
                offset: lyrics.offset,
              },
              lineXml,
            );
          })
          .join('');

        return sendSubsonicOk(reply, node('lyricsList', {}, structuredLyricsXml));
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

      if (musicFolderId && musicFolderId !== String(plexState.musicSectionId || '')) {
        return sendSubsonicOk(reply, node('searchResult3'));
      }

      const searchScope = beginSearchRequest(request, account.id);

      try {
        let matchedArtists = [];
        let matchedAlbums = [];
        let matchedTracks = [];

        if (!query) {
          const browseCacheKey = searchBrowseCacheKey(account.id, plexState);
          const [artists, albums, tracks] = await Promise.all([
            artistCount > 0
              ? getSearchBrowseCollection({
                  cacheKey: browseCacheKey,
                  collection: 'artists',
                  loader: async () => {
                    const loaded = await listArtists({
                      baseUrl: plexState.baseUrl,
                      plexToken: plexState.plexToken,
                      sectionId: plexState.musicSectionId,
                    });
                    return [...loaded].sort((a, b) =>
                      String(a?.title || '').localeCompare(String(b?.title || '')),
                    );
                  },
                })
              : [],
            albumCount > 0
              ? getSearchBrowseCollection({
                  cacheKey: browseCacheKey,
                  collection: 'albums',
                  loader: async () => {
                    const loaded = await listAlbums({
                      baseUrl: plexState.baseUrl,
                      plexToken: plexState.plexToken,
                      sectionId: plexState.musicSectionId,
                    });
                    return sortAlbumsByName(loaded);
                  },
                })
              : [],
            songCount > 0
              ? getSearchBrowseCollection({
                  cacheKey: browseCacheKey,
                  collection: 'tracks',
                  loader: async () => {
                    const loaded = await listTracks({
                      baseUrl: plexState.baseUrl,
                      plexToken: plexState.plexToken,
                      sectionId: plexState.musicSectionId,
                    });
                    return sortTracksForLibraryBrowse(loaded);
                  },
                })
              : [],
          ]);

          matchedArtists = takePage(artists, artistOffset, artistCount);
          matchedAlbums = takePage(albums, albumOffset, albumCount);
          matchedTracks = takePage(tracks, songOffset, songCount);
        } else {
          const artistWindow = searchWindowSize(artistOffset, artistCount);
          const albumWindow = searchWindowSize(albumOffset, albumCount);
          const songWindow = searchWindowSize(songOffset, songCount);

          const { artists, albums, tracks } = await runPlexSearch({
            plexState,
            query,
            artistWindow,
            albumWindow,
            songWindow,
            signal: searchScope.signal,
          });

          matchedArtists = takePage(
            artists.filter((artist) => includesText(artist.title, query)),
            artistOffset,
            artistCount,
          );
          matchedAlbums = takePage(
            albums.filter((album) => includesText(album.title, query) || includesText(album.parentTitle, query)),
            albumOffset,
            albumCount,
          );
          matchedTracks = takePage(
            tracks.filter((track) => includesText(track.title, query) || includesText(track.grandparentTitle, query)),
            songOffset,
            songCount,
          );
        }

        const artistXml = matchedArtists
          .map((artist) =>
            emptyNode('artist', {
              id: artist.ratingKey,
              name: artist.title,
              albumCount: artistAlbumCountValue(artist),
              coverArt: artist.ratingKey,
              ...subsonicRatingAttrs(artist),
            }),
          )
          .join('');
        const albumXml = matchedAlbums
          .map((album) => emptyNode('album', albumId3Attrs(album)))
          .join('');
        const songXml = matchedTracks
          .map((track) => emptyNode('song', songAttrs(track)))
          .join('');

        return sendSubsonicOk(reply, node('searchResult3', {}, `${artistXml}${albumXml}${songXml}`));
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
        return sendSubsonicOk(reply, node('searchResult2'));
      }

      const context = repo.getAccountPlexContext(account.id);
      const plexState = requiredPlexStateForSubsonic(reply, context, tokenCipher);
      if (!plexState) {
        return;
      }
      const searchScope = beginSearchRequest(request, account.id);

      try {
        const artistWindow = searchWindowSize(artistOffset, artistCount);
        const albumWindow = searchWindowSize(albumOffset, albumCount);
        const songWindow = searchWindowSize(songOffset, songCount);

        const { artists, albums, tracks } = await runPlexSearch({
          plexState,
          query,
          artistWindow,
          albumWindow,
          songWindow,
          signal: searchScope.signal,
        });

        const matchedArtists = takePage(
          artists.filter((artist) => includesText(artist.title, query)),
          artistOffset,
          artistCount,
        );
        const matchedAlbums = takePage(
          albums.filter((album) => includesText(album.title, query) || includesText(album.parentTitle, query)),
          albumOffset,
          albumCount,
        );
        const matchedTracks = takePage(
          tracks.filter((track) => includesText(track.title, query) || includesText(track.grandparentTitle, query)),
          songOffset,
          songCount,
        );

        const artistXml = matchedArtists
          .map((artist) =>
            emptyNode('artist', {
              id: artist.ratingKey,
              name: artist.title,
              coverArt: artist.ratingKey,
              ...subsonicRatingAttrs(artist),
            }),
          )
          .join('');
        const albumXml = matchedAlbums
          .map((album) => emptyNode('album', albumAttrs(album)))
          .join('');
        const songXml = matchedTracks
          .map((track) => emptyNode('song', songAttrs(track)))
          .join('');

        return sendSubsonicOk(reply, node('searchResult2', {}, `${artistXml}${albumXml}${songXml}`));
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
        return sendSubsonicOk(reply, node('searchResult'));
      }

      const context = repo.getAccountPlexContext(account.id);
      const plexState = requiredPlexStateForSubsonic(reply, context, tokenCipher);
      if (!plexState) {
        return;
      }
      const searchScope = beginSearchRequest(request, account.id);

      try {
        const artistWindow = searchWindowSize(artistOffset, artistCount);
        const albumWindow = searchWindowSize(albumOffset, albumCount);
        const songWindow = searchWindowSize(songOffset, songCount);

        const { artists, albums, tracks } = await runPlexSearch({
          plexState,
          query,
          artistWindow,
          albumWindow,
          songWindow,
          signal: searchScope.signal,
        });

        const matchedArtists = takePage(
          artists.filter((artist) => includesText(artist.title, query)),
          artistOffset,
          artistCount,
        );
        const matchedAlbums = takePage(
          albums.filter((album) => includesText(album.title, query) || includesText(album.parentTitle, query)),
          albumOffset,
          albumCount,
        );
        const matchedTracks = takePage(
          tracks.filter((track) => includesText(track.title, query) || includesText(track.grandparentTitle, query)),
          songOffset,
          songCount,
        );

        const artistXml = matchedArtists
          .map((artist) =>
            emptyNode('artist', {
              id: artist.ratingKey,
              name: artist.title,
              coverArt: artist.ratingKey,
              ...subsonicRatingAttrs(artist),
            }),
          )
          .join('');
        const albumXml = matchedAlbums
          .map((album) => emptyNode('album', albumAttrs(album)))
          .join('');
        const matchXml = matchedTracks
          .map((track) =>
            emptyNode('match', {
              id: track.ratingKey,
              title: track.title,
              album: track.parentTitle,
              artist: track.grandparentTitle,
            }),
          )
          .join('');

        return sendSubsonicOk(reply, node('searchResult', {}, `${artistXml}${albumXml}${matchXml}`));
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

    return sendSubsonicOk(reply, node('bookmarks'));
  });

  app.get('/rest/getInternetRadioStations.view', async (request, reply) => {
    const account = await authenticateSubsonicRequest(request, reply, repo, tokenCipher);
    if (!account) {
      return;
    }

    return sendSubsonicOk(reply, node('internetRadioStations'));
  });

  app.get('/rest/getPlayQueue.view', async (request, reply) => {
    const account = await authenticateSubsonicRequest(request, reply, repo, tokenCipher);
    if (!account) {
      return;
    }

    return sendSubsonicOk(
      reply,
      node(
        'playQueue',
        {
          current: '',
          position: 0,
        },
        '',
      ),
    );
  });

  app.get('/rest/savePlayQueue.view', async (request, reply) => {
    const account = await authenticateSubsonicRequest(request, reply, repo, tokenCipher);
    if (!account) {
      return;
    }

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

      const ids = uniqueNonEmptyValues([
        ...getRequestParamValues(request, 'id'),
        ...getRequestParamValues(request, 'songId'),
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
      const primaryTrackId = ids[0] || '';
      const shouldSyncPlayback =
        Boolean(primaryTrackId) &&
        (!shouldSubmit || ids.length === 1 || hasExplicitState) &&
        (hasPlaybackProgress || hasExplicitState);

      try {
        if (shouldSubmit) {
          await Promise.all(
            ids.map((id) =>
              scrobblePlexItem({
                baseUrl: plexState.baseUrl,
                plexToken: plexState.plexToken,
                itemId: id,
              }),
            ),
          );
        }
      } catch (error) {
        request.log.error(error, 'Failed to sync scrobble to Plex');
        return sendSubsonicError(reply, 10, 'Failed to scrobble');
      }

      try {
        if (shouldSyncPlayback) {
          await syncClientPlaybackState({
            accountId: account.id,
            plexState,
            clientName,
            itemId: primaryTrackId,
            state: playbackState,
            positionMs: playbackPositionMs,
            request,
          });
        }
      } catch (error) {
        request.log.warn(error, 'Failed to sync playback status to Plex');
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

      const ids = uniqueNonEmptyValues([
        ...getRequestParamValues(request, 'id'),
        ...getRequestParamValues(request, 'albumId'),
        ...getRequestParamValues(request, 'artistId'),
      ]);

      if (ids.length === 0) {
        return sendSubsonicError(reply, 10, 'Required parameter is missing');
      }

      const context = repo.getAccountPlexContext(account.id);
      const plexState = requiredPlexStateForSubsonic(reply, context, tokenCipher);
      if (!plexState) {
        return;
      }

      try {
        await Promise.all(
          ids.map((id) =>
            ratePlexItem({
              baseUrl: plexState.baseUrl,
              plexToken: plexState.plexToken,
              itemId: id,
              rating: 10,
            }),
          ),
        );
      } catch (error) {
        request.log.error(error, 'Failed to star item(s) in Plex');
        return sendSubsonicError(reply, 10, 'Failed to star');
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

      const ids = uniqueNonEmptyValues([
        ...getRequestParamValues(request, 'id'),
        ...getRequestParamValues(request, 'albumId'),
        ...getRequestParamValues(request, 'artistId'),
      ]);

      if (ids.length === 0) {
        return sendSubsonicError(reply, 10, 'Required parameter is missing');
      }

      const context = repo.getAccountPlexContext(account.id);
      const plexState = requiredPlexStateForSubsonic(reply, context, tokenCipher);
      if (!plexState) {
        return;
      }

      try {
        await Promise.all(
          ids.map((id) =>
            ratePlexItem({
              baseUrl: plexState.baseUrl,
              plexToken: plexState.plexToken,
              itemId: id,
              rating: 0,
            }),
          ),
        );
      } catch (error) {
        request.log.error(error, 'Failed to unstar item(s) in Plex');
        return sendSubsonicError(reply, 10, 'Failed to unstar');
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

      const plexRating = Math.round((rating / 5) * 10);
      try {
        await ratePlexItem({
          baseUrl: plexState.baseUrl,
          plexToken: plexState.plexToken,
          itemId: id,
          rating: plexRating,
        });
      } catch (error) {
        request.log.error(error, 'Failed to set rating in Plex');
        return sendSubsonicError(reply, 10, 'Failed to set rating');
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
        node(
          'playlist',
          {
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
          '',
        ),
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
      const playlistXml = playlists
        .map((playlist) => emptyNode('playlist', playlistAttrs(playlist, account.username, nowIso)))
        .join('');

      return sendSubsonicOk(reply, node('playlists', {}, playlistXml));
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
        .map((track) => {
          const attrs = songAttrs(track, track.parentTitle || undefined, track.parentRatingKey || undefined);
          return emptyNode('entry', attrs);
        })
        .join('');

      return sendSubsonicOk(reply, node('playlist', playlistAttrs(playlist, account.username, nowIso), entries));
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
      const artists = await listArtists({
        baseUrl: plexState.baseUrl,
        plexToken: plexState.plexToken,
        sectionId: plexState.musicSectionId,
      });

      const indexes = groupArtistsForSubsonic(artists).join('');
      return sendSubsonicOk(reply, node('artists', { ignoredArticles: 'The El La Los Las Le Les' }, indexes));
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

      const indexes = groupNamedEntriesForSubsonic(folderEntries).join('');
      return sendSubsonicOk(
        reply,
        node(
          'indexes',
          {
            ignoredArticles: 'The El La Los Las Le Les',
            lastModified: 0,
          },
          indexes,
        ),
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

    const artistId = getQueryString(request, 'id');
    if (!artistId) {
      return sendSubsonicError(reply, 70, 'Missing artist id');
    }

    const context = repo.getAccountPlexContext(account.id);
    const plexState = requiredPlexStateForSubsonic(reply, context, tokenCipher);
    if (!plexState) {
      return;
    }

    try {
      const artist = await getArtist({
        baseUrl: plexState.baseUrl,
        plexToken: plexState.plexToken,
        artistId,
      });

      if (!artist) {
        return sendSubsonicError(reply, 70, 'Artist not found');
      }

      const albums = await listArtistAlbums({
        baseUrl: plexState.baseUrl,
        plexToken: plexState.plexToken,
        artistId,
      });

      let finalAlbums = albums;
      if (finalAlbums.length === 0) {
        const tracks = await listArtistTracks({
          baseUrl: plexState.baseUrl,
          plexToken: plexState.plexToken,
          artistId,
        });
        finalAlbums = deriveAlbumsFromTracks(tracks, artist.ratingKey, artist.title);
      }

      const albumXml = finalAlbums
        .map((album) => emptyNode('album', albumId3Attrs(album, artist.ratingKey, artist.title)))
        .join('');

      return sendSubsonicOk(
        reply,
        node(
          'artist',
          {
            id: artist.ratingKey,
            name: artist.title,
            albumCount: finalAlbums.length,
            coverArt: artist.ratingKey,
            ...subsonicRatingAttrs(artist),
          },
          albumXml,
        ),
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

    return sendSubsonicOk(reply, node('artistInfo'));
  });

  app.get('/rest/getArtistInfo2.view', async (request, reply) => {
    const account = await authenticateSubsonicRequest(request, reply, repo, tokenCipher);
    if (!account) {
      return;
    }

    return sendSubsonicOk(reply, node('artistInfo2'));
  });

  app.get('/rest/getAlbum.view', async (request, reply) => {
    const account = await authenticateSubsonicRequest(request, reply, repo, tokenCipher);
    if (!account) {
      return;
    }

    const albumId = getQueryString(request, 'id');
    if (!albumId) {
      return sendSubsonicError(reply, 70, 'Missing album id');
    }

    const context = repo.getAccountPlexContext(account.id);
    const plexState = requiredPlexStateForSubsonic(reply, context, tokenCipher);
    if (!plexState) {
      return;
    }

    try {
      const album = await getAlbum({
        baseUrl: plexState.baseUrl,
        plexToken: plexState.plexToken,
        albumId,
      });

      if (!album) {
        return sendSubsonicError(reply, 70, 'Album not found');
      }

      const tracks = await listAlbumTracks({
        baseUrl: plexState.baseUrl,
        plexToken: plexState.plexToken,
        albumId,
      });
      const tracksWithGenre = await hydrateTracksWithGenre({
        baseUrl: plexState.baseUrl,
        plexToken: plexState.plexToken,
        tracks,
        request,
      });
      const sortedTracks = sortTracksByDiscAndIndex(tracksWithGenre);

      const totalDuration = sortedTracks.reduce((sum, track) => sum + durationSeconds(track.duration), 0);

      const songXml = sortedTracks
        .map((track) => emptyNode('song', songAttrs(track, album.title, album.ratingKey, album)))
        .join('');

      return sendSubsonicOk(
        reply,
        node(
          'album',
          {
            ...albumId3Attrs(album, album.parentRatingKey || null, album.parentTitle || null),
            songCount: sortedTracks.length,
            duration: totalDuration,
          },
          songXml,
        ),
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

        const currentFolderPath = isRootFolder ? null : explicitFolderPath;
        const currentDirectoryId = isRootFolder
          ? rootDirectoryId
          : encodePlexFolderId(explicitFolderPath, plexState.musicSectionId) || id;
        const children = folderResult.items
          .map((item) => {
            if (isLikelyPlexTrack(item)) {
              return emptyNode('child', {
                ...songAttrs(item, item.parentTitle || null, item.parentRatingKey || null),
                isDir: false,
                parent: currentDirectoryId,
              });
            }

            if (isLikelyPlexAlbum(item)) {
              return emptyNode('child', {
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
            return emptyNode('child', {
              id: folderId,
              parent: currentDirectoryId,
              isDir: true,
              title,
              name: title,
            });
          })
          .filter(Boolean)
          .join('');

        const container = folderResult.container || {};
        const directoryName = isRootFolder
          ? String(container.title1 || plexState.serverName)
          : String(container.title2 || container.title1 || 'Folder');

        return sendSubsonicOk(
          reply,
          node(
            'directory',
            {
              id: currentDirectoryId,
              parent: isRootFolder ? undefined : rootDirectoryId,
              name: directoryName,
            },
            children,
          ),
        );
      }

      const artist = await getArtist({
        baseUrl: plexState.baseUrl,
        plexToken: plexState.plexToken,
        artistId: id,
      });

      if (artist) {
        const albums = await listArtistAlbums({
          baseUrl: plexState.baseUrl,
          plexToken: plexState.plexToken,
          artistId: id,
        });

        let finalAlbums = albums;
        if (finalAlbums.length === 0) {
          const tracks = await listArtistTracks({
            baseUrl: plexState.baseUrl,
            plexToken: plexState.plexToken,
            artistId: id,
          });
          finalAlbums = deriveAlbumsFromTracks(tracks, artist.ratingKey, artist.title);
        }

        const children = finalAlbums
          .map((album) => emptyNode('child', albumAttrs(album, artist.ratingKey, artist.title)))
          .join('');

        return sendSubsonicOk(
          reply,
          node(
            'directory',
            {
              id: artist.ratingKey,
              parent: rootDirectoryId,
              name: artist.title,
            },
            children,
          ),
        );
      }

      const album = await getAlbum({
        baseUrl: plexState.baseUrl,
        plexToken: plexState.plexToken,
        albumId: id,
      });

      if (album) {
        const tracks = await listAlbumTracks({
          baseUrl: plexState.baseUrl,
          plexToken: plexState.plexToken,
          albumId: id,
        });
        const tracksWithGenre = await hydrateTracksWithGenre({
          baseUrl: plexState.baseUrl,
          plexToken: plexState.plexToken,
          tracks,
          request,
        });
        const sortedTracks = sortTracksByDiscAndIndex(tracksWithGenre);

        const children = sortedTracks
          .map((track) =>
            emptyNode('child', {
              ...songAttrs(track, album.title, album.ratingKey, album),
              isDir: false,
              parent: album.ratingKey,
            }),
          )
          .join('');

        return sendSubsonicOk(
          reply,
          node(
            'directory',
            {
              id: album.ratingKey,
              parent: album.parentRatingKey || rootDirectoryId,
              name: album.title,
            },
            children,
          ),
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
      return sendSubsonicOk(reply, node(containerName));
    }

    try {
      const allAlbums = await listAlbums({
        baseUrl: plexState.baseUrl,
        plexToken: plexState.plexToken,
        sectionId: plexState.musicSectionId,
      });

      const filtered = filterAndSortAlbumList(allAlbums, {
        type,
        fromYear,
        toYear,
        genre,
      });
      const page = sliceAlbumPage(filtered, offset, size);
      reply.header('x-total-count', String(filtered.length));
      const albumXml = page
        .map((album) =>
          emptyNode('album', containerName === 'albumList2' ? albumId3Attrs(album) : albumAttrs(album)),
        )
        .join('');

      return sendSubsonicOk(reply, node(containerName, {}, albumXml));
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
        const metadata = await getAlbum({
          baseUrl: plexState.baseUrl,
          plexToken: plexState.plexToken,
          albumId: id,
        });

        if (metadata) {
          thumbPath = metadata.thumb || metadata.art || null;
        }

        if (!thumbPath) {
          const artist = await getArtist({
            baseUrl: plexState.baseUrl,
            plexToken: plexState.plexToken,
            artistId: id,
          });

          thumbPath = artist?.thumb || artist?.art || null;
        }

        if (!thumbPath) {
          const track = await getTrack({
            baseUrl: plexState.baseUrl,
            plexToken: plexState.plexToken,
            trackId: id,
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

      return reply.send(Readable.fromWeb(upstream.body));
    } catch (error) {
      request.log.error(error, 'Failed to proxy cover art');
      return sendSubsonicError(reply, 10, 'Cover art proxy failed');
    }
  });

  app.get('/rest/stream.view', async (request, reply) => {
    const account = await authenticateSubsonicRequest(request, reply, repo, tokenCipher);
    if (!account) {
      return;
    }

    const trackId = getQueryString(request, 'id');
    if (!trackId) {
      return sendSubsonicError(reply, 70, 'Missing track id');
    }

    const context = repo.getAccountPlexContext(account.id);
    const plexState = requiredPlexStateForSubsonic(reply, context, tokenCipher);
    if (!plexState) {
      return;
    }

    try {
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

      const clientName = getRequestParam(request, 'c') || 'Subsonic Client';
      const playbackClient = playbackClientContext(account.id, clientName);
      const offsetRaw = getRequestParam(request, 'timeOffset');
      const offsetSeconds = Number.parseFloat(offsetRaw);
      const offsetMs = Number.isFinite(offsetSeconds) && offsetSeconds > 0 ? Math.round(offsetSeconds * 1000) : 0;
      const trackDurationMs = parseNonNegativeInt(track.duration, 0);
      const playbackStartAt = Date.now();

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

      try {
        await syncClientPlaybackState({
          accountId: account.id,
          plexState,
          clientName,
          itemId: trackId,
          state: 'playing',
          positionMs: offsetMs,
          durationMs: trackDurationMs,
          request,
        });
      } catch (error) {
        request.log.warn(error, 'Failed to sync stream-start playback status to Plex');
      }

      let streamClosed = false;
      const handleStreamClosed = () => {
        if (streamClosed) {
          return;
        }
        streamClosed = true;

        const closedAt = Date.now();
        clearProgressTimer();
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

      reply.raw.once('close', handleStreamClosed);
      reply.raw.once('finish', handleStreamClosed);

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

      const streamUrl = buildPmsAssetUrl(plexState.baseUrl, plexState.plexToken, partKey);
      const rangeHeader = request.headers.range;
      const upstream = await fetch(streamUrl, {
        headers: {
          ...(rangeHeader ? { Range: rangeHeader } : {}),
        },
      });

      if (!upstream.ok || !upstream.body) {
        clearProgressTimer();
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

      return reply.send(Readable.fromWeb(upstream.body));
    } catch (error) {
      request.log.error(error, 'Failed to proxy stream');
      return sendSubsonicError(reply, 10, 'Stream proxy failed');
    }
  });

  app.get('/rest/*', async (request, reply) => {
    const endpointPath = String(request.url || '').split('?')[0] || '/rest/unknown';
    return sendSubsonicError(reply, 10, `Endpoint not implemented: ${endpointPath}`);
  });

  return app;
}
