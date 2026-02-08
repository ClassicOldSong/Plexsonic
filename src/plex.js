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

import { APP_VERSION } from './version.js';

const PLEX_TV_BASE = 'https://plex.tv';
const PLEX_CLIENTS_BASE = 'https://clients.plex.tv';

function makePlexHeaders(config, token = null) {
  const headers = {
    Accept: 'application/json',
    'X-Plex-Product': config.plexProduct,
    'X-Plex-Version': APP_VERSION,
    'X-Plex-Client-Identifier': config.plexClientIdentifier,
    'X-Plex-Platform': process.platform,
    'X-Plex-Device': 'Plexsonic Bridge',
  };

  if (token) {
    headers['X-Plex-Token'] = token;
  }

  return headers;
}

async function ensureJson(response, context) {
  const body = await response.text();

  if (!response.ok) {
    throw new Error(`${context} failed (${response.status}): ${body.slice(0, 400)}`);
  }

  try {
    return JSON.parse(body);
  } catch (error) {
    throw new Error(`${context} returned non-JSON response: ${error.message}`);
  }
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

function toBool(value) {
  if (typeof value === 'boolean') {
    return value;
  }
  if (typeof value === 'number') {
    return value !== 0;
  }
  if (typeof value === 'string') {
    return value === '1' || value.toLowerCase() === 'true';
  }
  return false;
}

function extractResources(payload) {
  if (Array.isArray(payload)) {
    return payload;
  }

  const container = payload?.MediaContainer ?? payload ?? {};
  if (Array.isArray(container)) {
    return container;
  }

  if (Array.isArray(container.Device)) {
    return container.Device;
  }
  if (container.Device) {
    return [container.Device];
  }

  if (Array.isArray(container.Metadata)) {
    return container.Metadata;
  }
  if (container.Metadata) {
    return [container.Metadata];
  }

  if (Array.isArray(container.resources)) {
    return container.resources;
  }
  if (container.resources) {
    return [container.resources];
  }

  return [];
}

function scoreConnection(entry) {
  const local = entry.local && !entry.relay;
  const isHttp = entry.protocol === 'http' || entry.uri.startsWith('http://');

  if (local && isHttp && entry.uri.includes(entry.address)) {
    return 0;
  }
  if (local && isHttp) {
    return 1;
  }
  if (local) {
    return 2;
  }
  if (isHttp) {
    return 3;
  }
  if (!entry.relay) {
    return 4;
  }
  return 5;
}

function chooseConnectionCandidates(connections) {
  const normalized = connections
    .map((entry) => ({
      uri: entry.uri || '',
      address: entry.address || '',
      port: entry.port || '',
      local: toBool(entry.local),
      relay: toBool(entry.relay),
      protocol: entry.protocol || '',
    }))
    .map((entry) => {
      if (!entry.uri && entry.address && entry.port && entry.protocol) {
        return {
          ...entry,
          uri: `${entry.protocol}://${entry.address}:${entry.port}`,
        };
      }
      return entry;
    })
    .filter((entry) => Boolean(entry.uri));

  if (normalized.length === 0) {
    return [];
  }

  const candidates = [];
  for (const entry of normalized) {
    candidates.push(entry);
    if (entry.local && !entry.relay && entry.address && entry.port) {
      candidates.push({
        ...entry,
        protocol: 'http',
        uri: `http://${entry.address}:${entry.port}`,
      });
    }
  }

  const uniqueCandidates = [];
  const seen = new Set();
  for (const entry of candidates) {
    if (!entry.uri || seen.has(entry.uri)) {
      continue;
    }
    seen.add(entry.uri);
    uniqueCandidates.push(entry);
  }

  uniqueCandidates.sort((a, b) => scoreConnection(a) - scoreConnection(b));

  return uniqueCandidates.map((entry) => entry.uri).filter(Boolean);
}

function chooseBestConnection(connections) {
  const candidates = chooseConnectionCandidates(connections);
  return candidates[0] ?? null;
}

function extractMetadataList(container) {
  if (!container || typeof container !== 'object') {
    return [];
  }

  return asArray(container.Metadata ?? container.Directory ?? container.Video ?? container.Track ?? []);
}

function normalizeLibrarySection(section) {
  return {
    id: String(section.key ?? section.id ?? ''),
    title: section.title || section.name || 'Untitled',
    type: section.type || '',
  };
}

export async function createPlexPin(config, { forwardUrl = null } = {}) {
  const url = new URL('/api/v2/pins', PLEX_TV_BASE);
  url.searchParams.set('strong', 'true');

  const response = await fetch(url, {
    method: 'POST',
    headers: makePlexHeaders(config),
  });

  const payload = await ensureJson(response, 'Plex PIN creation');

  const id = String(payload.id ?? '');
  const code = String(payload.code ?? '');

  if (!id || !code) {
    throw new Error('Plex PIN payload missing id/code');
  }

  return {
    id,
    code,
    authUrl: buildPlexPinAuthUrl(config, code, forwardUrl),
  };
}

export function buildPlexPinAuthUrl(config, code, forwardUrl = null) {
  const params = new URLSearchParams();
  params.set('clientID', config.plexClientIdentifier);
  params.set('code', code);
  params.set('context[device][product]', config.plexProduct);
  if (forwardUrl) {
    params.set('forwardUrl', forwardUrl);
  }

  return `https://app.plex.tv/auth#?${params.toString()}`;
}

export async function pollPlexPin(config, { pinId, code }) {
  const url = new URL(`/api/v2/pins/${encodeURIComponent(pinId)}`, PLEX_TV_BASE);
  url.searchParams.set('code', code);

  const response = await fetch(url, {
    headers: makePlexHeaders(config),
  });

  const payload = await ensureJson(response, 'Plex PIN poll');

  return {
    authToken: payload.authToken || null,
    expiresAt: payload.expiresAt || null,
    expired: toBool(payload.expired),
  };
}

export async function listPlexServers(config, plexToken) {
  const url = new URL('/api/v2/resources', PLEX_CLIENTS_BASE);
  url.searchParams.set('includeHttps', '1');
  url.searchParams.set('includeRelay', '1');
  url.searchParams.set('includeIPv6', '1');

  const response = await fetch(url, {
    headers: makePlexHeaders(config, plexToken),
  });

  const payload = await ensureJson(response, 'Plex resources lookup');
  const resources = extractResources(payload);

  return resources
    .filter((resource) => {
      const provides = String(resource.provides || '')
        .split(',')
        .map((v) => v.trim())
        .filter(Boolean);
      if (provides.includes('server')) {
        return true;
      }
      return String(resource.product || '').toLowerCase() === 'plex media server';
    })
    .map((resource) => {
      const machineId = String(resource.clientIdentifier ?? resource.machineIdentifier ?? resource.uuid ?? '');
      const name = resource.name || resource.product || 'Plex Server';
      const connections = asArray(resource.Connection ?? resource.connections ?? []);
      const connectionUris = chooseConnectionCandidates(connections);
      const baseUrl = chooseBestConnection(connections);
      const accessToken = resource.accessToken || null;

      return {
        machineId,
        name,
        baseUrl,
        connectionUris,
        accessToken,
      };
    })
    .filter((resource) => resource.machineId && resource.baseUrl);
}

function joinBaseAndPath(baseUrl, relativePath) {
  const normalized = baseUrl.endsWith('/') ? baseUrl : `${baseUrl}/`;
  const pathPart = relativePath.startsWith('/') ? relativePath.slice(1) : relativePath;
  return new URL(pathPart, normalized);
}

function normalizePlexTokenCandidates(plexToken) {
  if (Array.isArray(plexToken)) {
    return [...new Set(plexToken.map((token) => String(token || '').trim()).filter(Boolean))];
  }
  const normalized = String(plexToken || '').trim();
  return normalized ? [normalized] : [];
}

function buildPmsUrl(baseUrl, path, searchParams, plexToken) {
  const url = joinBaseAndPath(baseUrl, path);

  if (searchParams) {
    for (const [key, value] of Object.entries(searchParams)) {
      if (value == null) {
        continue;
      }
      url.searchParams.set(key, String(value));
    }
  }

  if (plexToken) {
    url.searchParams.set('X-Plex-Token', plexToken);
  }

  return url;
}

async function fetchPmsJson(baseUrl, plexToken, path, searchParams = null, options = {}) {
  const tokenCandidates = normalizePlexTokenCandidates(plexToken);
  if (tokenCandidates.length === 0) {
    throw new Error('PMS request failed: missing Plex token');
  }

  for (const [index, token] of tokenCandidates.entries()) {
    const url = buildPmsUrl(baseUrl, path, searchParams, token);
    const response = await fetch(url, {
      headers: {
        Accept: 'application/json',
        'X-Plex-Token': token,
      },
      signal: options.signal,
    });

    if (response.status === 401 && index < tokenCandidates.length - 1) {
      await response.arrayBuffer().catch(() => {});
      continue;
    }

    return ensureJson(response, `PMS request ${url.pathname}`);
  }

  throw new Error(`PMS request ${path} failed: unauthorized`);
}

function normalizeSectionFolderPath(rawPath, sectionId) {
  const value = String(rawPath || '');
  if (!value.startsWith(`/library/sections/${encodeURIComponent(String(sectionId))}/folder`)) {
    return null;
  }

  try {
    const parsed = new URL(value, 'http://local.invalid');
    if (!parsed.pathname.startsWith(`/library/sections/${encodeURIComponent(String(sectionId))}/folder`)) {
      return null;
    }
    return `${parsed.pathname}${parsed.search}`;
  } catch {
    return null;
  }
}

async function fetchPms(
  baseUrl,
  plexToken,
  path,
  { method = 'GET', searchParams = null, headers = {}, signal = undefined } = {},
) {
  const tokenCandidates = normalizePlexTokenCandidates(plexToken);
  if (tokenCandidates.length === 0) {
    throw new Error('PMS request failed: missing Plex token');
  }

  for (const [index, token] of tokenCandidates.entries()) {
    const url = buildPmsUrl(baseUrl, path, searchParams, token);
    const response = await fetch(url, {
      method,
      headers: {
        Accept: 'application/json',
        ...headers,
        'X-Plex-Token': token,
      },
      signal,
    });

    const body = await response.text();
    if (response.status === 401 && index < tokenCandidates.length - 1) {
      continue;
    }
    if (!response.ok) {
      throw new Error(`PMS request ${url.pathname} failed (${response.status}): ${body.slice(0, 400)}`);
    }

    return body;
  }

  throw new Error(`PMS request ${path} failed: unauthorized`);
}

function buildMetadataUri(machineId, ids) {
  const normalizedIds = asArray(ids)
    .map((id) => String(id || '').trim())
    .filter(Boolean);

  if (normalizedIds.length === 0) {
    return `server://${machineId}/com.plexapp.plugins.library/library/metadata/`;
  }

  const encodedIds = normalizedIds.map((id) => encodeURIComponent(id)).join(',');
  return `server://${machineId}/com.plexapp.plugins.library/library/metadata/${encodedIds}`;
}

export async function scrobblePlexItem({ baseUrl, plexToken, itemId }) {
  await fetchPms(baseUrl, plexToken, '/:/scrobble', {
    searchParams: {
      identifier: 'com.plexapp.plugins.library',
      key: String(itemId),
    },
  });
}

export async function updatePlexPlaybackStatus({
  baseUrl,
  plexToken,
  itemId,
  state = 'playing',
  positionMs = 0,
  durationMs = null,
  clientIdentifier = null,
  clientName = 'Subsonic Client',
  product = 'Plexsonic Bridge',
  sessionId = null,
}) {
  const normalizedState = (() => {
    const value = String(state || '').toLowerCase();
    if (value === 'paused' || value === 'stopped' || value === 'playing') {
      return value;
    }
    return 'playing';
  })();

  const normalizedPosition = Number.isFinite(positionMs)
    ? Math.max(0, Math.trunc(positionMs))
    : 0;

  const itemKey = `/library/metadata/${encodeURIComponent(String(itemId))}`;
  const timelineHeaders = {
    'X-Plex-Product': String(product || 'Plexsonic Bridge'),
    'X-Plex-Client-Identifier': String(clientIdentifier || 'plexsonic-subsonic'),
    'X-Plex-Device-Name': String(clientName || 'Subsonic Client'),
    'X-Plex-Provides': 'player',
  };

  if (sessionId) {
    timelineHeaders['X-Plex-Session-Identifier'] = String(sessionId);
  }

  const timelineParams = {
    identifier: 'com.plexapp.plugins.library',
    key: itemKey,
    ratingKey: String(itemId),
    state: normalizedState,
    time: normalizedPosition,
    hasMDE: 1,
  };

  if (Number.isFinite(durationMs) && durationMs > 0) {
    timelineParams.duration = Math.max(0, Math.trunc(durationMs));
  }

  try {
    await fetchPms(baseUrl, plexToken, '/:/timeline', {
      searchParams: timelineParams,
      headers: timelineHeaders,
    });
    return;
  } catch {
    await fetchPms(baseUrl, plexToken, '/:/progress', {
      searchParams: {
        identifier: 'com.plexapp.plugins.library',
        key: String(itemId),
        state: normalizedState,
        time: normalizedPosition,
      },
      headers: timelineHeaders,
    });
  }
}

export async function ratePlexItem({ baseUrl, plexToken, itemId, rating }) {
  await fetchPms(baseUrl, plexToken, '/:/rate', {
    searchParams: {
      identifier: 'com.plexapp.plugins.library',
      key: String(itemId),
      rating,
    },
  });
}

export async function createPlexPlaylist({ baseUrl, plexToken, machineId, title, itemIds = [] }) {
  const body = await fetchPms(baseUrl, plexToken, '/playlists', {
    method: 'POST',
    searchParams: {
      type: 'audio',
      title,
      smart: 0,
      uri: buildMetadataUri(machineId, itemIds),
    },
  });

  if (!body) {
    return null;
  }

  const payload = JSON.parse(body);
  return extractMetadataList(payload.MediaContainer)[0] || null;
}

export async function addItemsToPlexPlaylist({ baseUrl, plexToken, machineId, playlistId, itemIds }) {
  const normalized = asArray(itemIds)
    .map((id) => String(id || '').trim())
    .filter(Boolean);

  if (normalized.length === 0) {
    return null;
  }

  const body = await fetchPms(baseUrl, plexToken, `/playlists/${encodeURIComponent(playlistId)}/items`, {
    method: 'PUT',
    searchParams: {
      uri: buildMetadataUri(machineId, normalized),
    },
  });

  if (!body) {
    return null;
  }

  const payload = JSON.parse(body);
  return extractMetadataList(payload.MediaContainer)[0] || null;
}

export async function renamePlexPlaylist({ baseUrl, plexToken, playlistId, title }) {
  await fetchPms(baseUrl, plexToken, `/playlists/${encodeURIComponent(playlistId)}`, {
    method: 'PUT',
    searchParams: {
      title,
    },
  });
}

export async function listPlexPlaylists({ baseUrl, plexToken }) {
  const payload = await fetchPmsJson(baseUrl, plexToken, '/playlists', {
    playlistType: 'audio',
  });
  return extractMetadataList(payload.MediaContainer);
}

export async function listPlexPlaylistItems({ baseUrl, plexToken, playlistId }) {
  const payload = await fetchPmsJson(
    baseUrl,
    plexToken,
    `/playlists/${encodeURIComponent(playlistId)}/items`,
  );
  return extractMetadataList(payload.MediaContainer);
}

export async function deletePlexPlaylist({ baseUrl, plexToken, playlistId }) {
  await fetchPms(baseUrl, plexToken, `/playlists/${encodeURIComponent(playlistId)}`, {
    method: 'DELETE',
  });
}

export async function removePlexPlaylistItems({ baseUrl, plexToken, playlistId, playlistItemIds = [] }) {
  const normalized = asArray(playlistItemIds)
    .map((id) => String(id || '').trim())
    .filter(Boolean);

  if (normalized.length === 0) {
    return;
  }

  await Promise.all(
    normalized.map((itemId) =>
      fetchPms(baseUrl, plexToken, `/playlists/${encodeURIComponent(playlistId)}/items/${encodeURIComponent(itemId)}`, {
        method: 'DELETE',
      }),
    ),
  );
}

export async function listMusicSections({ baseUrl, plexToken }) {
  const payload = await fetchPmsJson(baseUrl, plexToken, '/library/sections');
  const directories = asArray(payload.MediaContainer?.Directory ?? []);

  return directories
    .map(normalizeLibrarySection)
    .filter((section) => section.id)
    .filter((section) => section.type === 'artist' || section.type === 'music');
}

export async function listPlexSectionFolder({ baseUrl, plexToken, sectionId, folderPath = null }) {
  const path = folderPath
    ? normalizeSectionFolderPath(folderPath, sectionId)
    : `/library/sections/${encodeURIComponent(sectionId)}/folder`;

  if (!path) {
    throw new Error('Invalid Plex folder path');
  }

  const payload = await fetchPmsJson(baseUrl, plexToken, path);
  return {
    container: payload?.MediaContainer || {},
    items: extractMetadataList(payload?.MediaContainer),
  };
}

export async function searchSectionMetadata({
  baseUrl,
  plexToken,
  sectionId,
  type = null,
  query,
  limit = 50,
  offset = 0,
  signal = undefined,
}) {
  const normalizedQuery = String(query || '').trim();
  if (!normalizedQuery) {
    return [];
  }

  const normalizedLimit = Math.min(Math.max(Number.parseInt(String(limit), 10) || 50, 1), 500);
  const normalizedOffset = Math.max(Number.parseInt(String(offset), 10) || 0, 0);

  const searchParams = {
    query: normalizedQuery,
    'X-Plex-Container-Start': normalizedOffset,
    'X-Plex-Container-Size': normalizedLimit,
  };
  if (type != null) {
    searchParams.type = Number.parseInt(String(type), 10);
  }

  try {
    const payload = await fetchPmsJson(
      baseUrl,
      plexToken,
      `/library/sections/${encodeURIComponent(sectionId)}/search`,
      searchParams,
      { signal },
    );
    return extractMetadataList(payload.MediaContainer);
  } catch (error) {
    if (error?.name === 'AbortError' || error?.code === 'ABORT_ERR') {
      throw error;
    }
  }

  const fallbackParams = {
    title: normalizedQuery,
    'X-Plex-Container-Start': normalizedOffset,
    'X-Plex-Container-Size': normalizedLimit,
  };
  if (type != null) {
    fallbackParams.type = Number.parseInt(String(type), 10);
  }

  const fallbackPayload = await fetchPmsJson(
    baseUrl,
    plexToken,
    `/library/sections/${encodeURIComponent(sectionId)}/all`,
    fallbackParams,
    { signal },
  );
  return extractMetadataList(fallbackPayload.MediaContainer);
}

function mergeUniqueByRatingKey(primary = [], secondary = []) {
  const seen = new Set();
  const out = [];

  for (const item of [...primary, ...secondary]) {
    const ratingKey = String(item?.ratingKey ?? '');
    if (!ratingKey || seen.has(ratingKey)) {
      continue;
    }
    seen.add(ratingKey);
    out.push(item);
  }

  return out;
}

export async function searchSectionHubs({
  baseUrl,
  plexToken,
  sectionId,
  query,
  limit = 100,
  signal = undefined,
}) {
  const normalizedQuery = String(query || '').trim();
  if (!normalizedQuery) {
    return {
      artists: [],
      albums: [],
      tracks: [],
    };
  }

  const normalizedLimit = Math.min(Math.max(Number.parseInt(String(limit), 10) || 100, 1), 500);
  const payload = await fetchPmsJson(
    baseUrl,
    plexToken,
    '/hubs/search',
    {
      query: normalizedQuery,
      sectionId: String(sectionId),
      limit: normalizedLimit,
      includeExternalMedia: 0,
    },
    { signal },
  );

  const hubs = asArray(payload?.MediaContainer?.Hub ?? []);
  let artists = [];
  let albums = [];
  let tracks = [];

  for (const hub of hubs) {
    const hubType = String(hub?.type || '').toLowerCase();
    const metadata = extractMetadataList(hub);
    if (metadata.length === 0) {
      continue;
    }

    const artistsFromHub = metadata.filter((item) => String(item?.type || '').toLowerCase() === 'artist');
    const albumsFromHub = metadata.filter((item) => String(item?.type || '').toLowerCase() === 'album');
    const tracksFromHub = metadata.filter((item) => String(item?.type || '').toLowerCase() === 'track');

    artists = mergeUniqueByRatingKey(
      artists,
      artistsFromHub.length > 0 ? artistsFromHub : hubType === 'artist' ? metadata : [],
    );
    albums = mergeUniqueByRatingKey(
      albums,
      albumsFromHub.length > 0 ? albumsFromHub : hubType === 'album' ? metadata : [],
    );
    tracks = mergeUniqueByRatingKey(
      tracks,
      tracksFromHub.length > 0 ? tracksFromHub : hubType === 'track' ? metadata : [],
    );
  }

  return {
    artists,
    albums,
    tracks,
  };
}

export async function listArtists({ baseUrl, plexToken, sectionId }) {
  const payload = await fetchPmsJson(baseUrl, plexToken, `/library/sections/${encodeURIComponent(sectionId)}/all`, {
    type: 8,
  });

  return extractMetadataList(payload.MediaContainer);
}

export async function listAlbums({ baseUrl, plexToken, sectionId }) {
  const payload = await fetchPmsJson(baseUrl, plexToken, `/library/sections/${encodeURIComponent(sectionId)}/all`, {
    type: 9,
  });

  return extractMetadataList(payload.MediaContainer);
}

export async function listTracks({ baseUrl, plexToken, sectionId }) {
  const payload = await fetchPmsJson(baseUrl, plexToken, `/library/sections/${encodeURIComponent(sectionId)}/all`, {
    type: 10,
  });

  return extractMetadataList(payload.MediaContainer);
}

export async function getArtist({ baseUrl, plexToken, artistId }) {
  const payload = await fetchPmsJson(baseUrl, plexToken, `/library/metadata/${encodeURIComponent(artistId)}`);
  const item = extractMetadataList(payload.MediaContainer)[0] || null;
  if (!item) {
    return null;
  }
  return String(item.type || '').toLowerCase() === 'artist' ? item : null;
}

export async function listArtistAlbums({ baseUrl, plexToken, artistId }) {
  const payload = await fetchPmsJson(baseUrl, plexToken, `/library/metadata/${encodeURIComponent(artistId)}/children`, {
    type: 9,
  });

  return extractMetadataList(payload.MediaContainer);
}

export async function listArtistTracks({ baseUrl, plexToken, artistId }) {
  const payload = await fetchPmsJson(baseUrl, plexToken, `/library/metadata/${encodeURIComponent(artistId)}/allLeaves`, {
    type: 10,
  });

  return extractMetadataList(payload.MediaContainer);
}

export async function getAlbum({ baseUrl, plexToken, albumId }) {
  const payload = await fetchPmsJson(baseUrl, plexToken, `/library/metadata/${encodeURIComponent(albumId)}`);
  const item = extractMetadataList(payload.MediaContainer)[0] || null;
  if (!item) {
    return null;
  }
  return String(item.type || '').toLowerCase() === 'album' ? item : null;
}

export async function listAlbumTracks({ baseUrl, plexToken, albumId }) {
  const payload = await fetchPmsJson(baseUrl, plexToken, `/library/metadata/${encodeURIComponent(albumId)}/children`, {
    type: 10,
  });

  return extractMetadataList(payload.MediaContainer);
}

export async function getTrack({ baseUrl, plexToken, trackId, signal = undefined }) {
  const payload = await fetchPmsJson(
    baseUrl,
    plexToken,
    `/library/metadata/${encodeURIComponent(trackId)}`,
    null,
    { signal },
  );
  const item = extractMetadataList(payload.MediaContainer)[0] || null;
  if (!item) {
    return null;
  }
  return String(item.type || '').toLowerCase() === 'track' ? item : null;
}

async function fetchPmsText(baseUrl, plexToken, path, { searchParams = null, signal = undefined } = {}) {
  const tokenCandidates = normalizePlexTokenCandidates(plexToken);
  if (tokenCandidates.length === 0) {
    throw new Error('PMS request failed: missing Plex token');
  }

  for (const [index, token] of tokenCandidates.entries()) {
    const url = buildPmsUrl(baseUrl, path, searchParams, token);
    const response = await fetch(url, {
      headers: {
        Accept: '*/*',
        'X-Plex-Token': token,
      },
      signal,
    });

    const body = await response.text();
    if (response.status === 401 && index < tokenCandidates.length - 1) {
      continue;
    }
    if (!response.ok) {
      throw new Error(`PMS request ${url.pathname} failed (${response.status}): ${body.slice(0, 400)}`);
    }

    return body;
  }

  throw new Error(`PMS request ${path} failed: unauthorized`);
}

function normalizePlexKeyPath(key) {
  const raw = String(key || '').trim();
  if (!raw) {
    return null;
  }

  try {
    const parsed = new URL(raw);
    return `${parsed.pathname}${parsed.search}`;
  } catch {
    return raw;
  }
}

function decodeXmlEntities(value) {
  const text = String(value || '');
  return text
    .replace(/&#x([0-9a-fA-F]+);/g, (_match, hex) => {
      const code = Number.parseInt(hex, 16);
      if (!Number.isFinite(code)) {
        return _match;
      }
      try {
        return String.fromCodePoint(code);
      } catch {
        return _match;
      }
    })
    .replace(/&#([0-9]+);/g, (_match, dec) => {
      const code = Number.parseInt(dec, 10);
      if (!Number.isFinite(code)) {
        return _match;
      }
      try {
        return String.fromCodePoint(code);
      } catch {
        return _match;
      }
    })
    .replaceAll('&amp;', '&')
    .replaceAll('&lt;', '<')
    .replaceAll('&gt;', '>')
    .replaceAll('&quot;', '"')
    .replaceAll('&apos;', "'");
}

function parseXmlAttrs(rawAttrs) {
  const attrs = {};
  const source = String(rawAttrs || '');
  const attrPattern = /([A-Za-z0-9:_-]+)="([^"]*)"/g;
  let match = null;
  while ((match = attrPattern.exec(source)) !== null) {
    attrs[match[1]] = decodeXmlEntities(match[2]);
  }
  return attrs;
}

function parseMs(value) {
  const parsed = Number.parseInt(String(value ?? ''), 10);
  if (!Number.isFinite(parsed) || parsed < 0) {
    return undefined;
  }
  return parsed;
}

function parsePlexLyricsXml(xmlText) {
  const xml = String(xmlText || '').trim();
  if (!xml || !xml.includes('<Lyrics')) {
    return [];
  }

  const lyricsPattern = /<Lyrics\b([^>]*)>([\s\S]*?)<\/Lyrics>/gi;
  const out = [];
  let lyricsMatch = null;

  while ((lyricsMatch = lyricsPattern.exec(xml)) !== null) {
    const lyricsAttrs = parseXmlAttrs(lyricsMatch[1]);
    const lyricsInner = String(lyricsMatch[2] || '');
    const timed = String(lyricsAttrs.timed || '') === '1' || String(lyricsAttrs.timed || '').toLowerCase() === 'true';
    const lang = String(lyricsAttrs.lang || '').trim() || 'und';

    const lines = [];
    const linePattern = /<Line\b([^>]*?)(?:\/>|>([\s\S]*?)<\/Line>)/gi;
    let lineMatch = null;

    while ((lineMatch = linePattern.exec(lyricsInner)) !== null) {
      const lineAttrs = parseXmlAttrs(lineMatch[1]);
      const lineInner = String(lineMatch[2] || '');
      const lineStart =
        parseMs(lineAttrs.startOffset) ??
        parseMs(lineAttrs.start) ??
        parseMs(lineAttrs.time);

      const spanPattern = /<Span\b([^>]*?)(?:\/>|>([\s\S]*?)<\/Span>)/gi;
      const spanTexts = [];
      let spanStart = lineStart;
      let spanMatch = null;
      while ((spanMatch = spanPattern.exec(lineInner)) !== null) {
        const spanAttrs = parseXmlAttrs(spanMatch[1]);
        const spanTextAttr = String(spanAttrs.text || '').trim();
        const spanTextInner = decodeXmlEntities(String(spanMatch[2] || '').replace(/<[^>]*>/g, '')).trim();
        const spanText = spanTextAttr || spanTextInner;
        if (spanText) {
          spanTexts.push(spanText);
        }

        const inferredSpanStart =
          parseMs(spanAttrs.startOffset) ??
          parseMs(spanAttrs.start) ??
          parseMs(spanAttrs.time);
        if (spanStart === undefined && inferredSpanStart !== undefined) {
          spanStart = inferredSpanStart;
        }
      }

      const text = spanTexts.join(' ').trim();
      if (!text) {
        continue;
      }

      if (spanStart === undefined) {
        lines.push({ value: text });
      } else {
        lines.push({ value: text, start: spanStart });
      }
    }

    if (lines.length === 0) {
      continue;
    }

    out.push({
      lang,
      synced: timed || lines.some((line) => Number.isFinite(line.start)),
      lines,
    });
  }

  return out;
}

function extractLyricStreamKeysFromMetadataXml(xmlText) {
  const xml = String(xmlText || '');
  if (!xml) {
    return [];
  }

  const keys = new Set();
  const pushKey = (raw) => {
    const normalized = normalizePlexKeyPath(raw);
    if (normalized && normalized.includes('/library/streams/')) {
      keys.add(normalized);
    }
  };

  const streamPattern = /<Stream\b([^>]*?)(?:\/>|>)/gi;
  let streamMatch = null;
  while ((streamMatch = streamPattern.exec(xml)) !== null) {
    const attrs = parseXmlAttrs(streamMatch[1]);
    const streamType = Number.parseInt(String(attrs.streamType ?? ''), 10);
    const lowerType = String(attrs.type || '').toLowerCase();
    const lowerCodec = String(attrs.codec || '').toLowerCase();
    const lowerFormat = String(attrs.format || '').toLowerCase();
    const lowerTitle = String(attrs.title || attrs.displayTitle || '').toLowerCase();
    const looksLyric =
      streamType === 3 ||
      lowerType.includes('lyric') ||
      lowerCodec.includes('lrc') ||
      lowerFormat.includes('lrc') ||
      lowerTitle.includes('lyric');

    if (looksLyric) {
      pushKey(attrs.key);
      const id = String(attrs.id || '').trim();
      if (/^\d+$/.test(id)) {
        pushKey(`/library/streams/${id}`);
      }
    }
  }

  // Some payload variants expose lyric stream id on parent elements instead of Stream key.
  const lyricAttrPattern = /\b([A-Za-z0-9:_-]*lyric[A-Za-z0-9:_-]*stream[A-Za-z0-9:_-]*)="([^"]+)"/gi;
  let lyricAttrMatch = null;
  while ((lyricAttrMatch = lyricAttrPattern.exec(xml)) !== null) {
    const value = String(lyricAttrMatch[2] || '').trim();
    if (/^\d+$/.test(value)) {
      pushKey(`/library/streams/${value}`);
    } else {
      pushKey(value);
    }
  }

  return [...keys];
}

function collectLyricHints(value, out, depth = 0, lyricContext = false) {
  if (value == null || depth > 8) {
    return;
  }

  if (typeof value === 'string') {
    const text = value.trim();
    if (lyricContext && text) {
      out.push(text);
    }
    return;
  }

  if (Array.isArray(value)) {
    for (const entry of value) {
      collectLyricHints(entry, out, depth + 1, lyricContext);
    }
    return;
  }

  if (typeof value !== 'object') {
    return;
  }

  const lowerType = String(value.type || '').toLowerCase();
  const lowerCodec = String(value.codec || '').toLowerCase();
  const lowerFormat = String(value.format || '').toLowerCase();
  const lowerTitle = String(value.title || value.displayTitle || '').toLowerCase();
  const isLyricishObject =
    lowerType.includes('lyric') ||
    lowerCodec.includes('lrc') ||
    lowerFormat.includes('lrc') ||
    lowerTitle.includes('lyric');
  const objectContext = lyricContext || isLyricishObject;

  for (const [key, child] of Object.entries(value)) {
    const lowerKey = key.toLowerCase();
    if (
      lowerKey === 'lyrics' ||
      lowerKey === 'lyric' ||
      lowerKey === 'timedlyrics' ||
      lowerKey === 'structuredlyrics' ||
      lowerKey === 'line' ||
      lowerKey === 'lines'
    ) {
      collectLyricHints(child, out, depth + 1, true);
      continue;
    }

    if (
      objectContext &&
      (lowerKey === 'text' || lowerKey === 'value' || lowerKey === 'line')
    ) {
      collectLyricHints(child, out, depth + 1, true);
      continue;
    }

    if (typeof child === 'object' && child !== null) {
      collectLyricHints(child, out, depth + 1, objectContext);
    }
  }
}

function collectLyricStreamKeys(value, out, depth = 0) {
  if (value == null || depth > 8) {
    return;
  }

  if (Array.isArray(value)) {
    for (const entry of value) {
      collectLyricStreamKeys(entry, out, depth + 1);
    }
    return;
  }

  if (typeof value !== 'object') {
    return;
  }

  const rawKey = normalizePlexKeyPath(value.key);
  const streamType = Number.parseInt(String(value.streamType ?? ''), 10);
  const lowerType = String(value.type || '').toLowerCase();
  const lowerCodec = String(value.codec || '').toLowerCase();
  const lowerFormat = String(value.format || '').toLowerCase();
  const lowerTitle = String(value.title || value.displayTitle || '').toLowerCase();
  const keyLooksLyric = rawKey && (rawKey.includes('/lyrics') || rawKey.includes('/library/streams/'));
  const objectLooksLyric =
    lowerType.includes('lyric') ||
    lowerCodec.includes('lrc') ||
    lowerFormat.includes('lrc') ||
    lowerTitle.includes('lyric') ||
    streamType === 3;

  if (rawKey && (keyLooksLyric || objectLooksLyric)) {
    out.add(rawKey);
  }

  for (const child of Object.values(value)) {
    if (typeof child === 'object' && child !== null) {
      collectLyricStreamKeys(child, out, depth + 1);
    }
  }
}

export async function fetchPlexTrackLyricsCandidates({
  baseUrl,
  plexToken,
  trackId,
  signal = undefined,
}) {
  const metadataPath = `/library/metadata/${encodeURIComponent(trackId)}`;
  const payloads = [];
  const candidates = [];
  const streamKeys = new Set();
  const streamKeysFromXml = new Set();
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
    if (typeof value === 'string') {
      const text = value.trim();
      if (text) {
        candidates.push(text);
      }
      return;
    }
    candidates.push(value);
  };

  const tryJsonPayload = async (path, searchParams = null) => {
    try {
      const payload = await fetchPmsJson(baseUrl, plexToken, path, searchParams, { signal });
      payloads.push(payload);
      return payload;
    } catch (error) {
      if (error?.name === 'AbortError' || error?.code === 'ABORT_ERR') {
        throw error;
      }
      return null;
    }
  };

  const tryTextPayload = async (path, searchParams = null) => {
    try {
      const text = await fetchPmsText(baseUrl, plexToken, path, { searchParams, signal });
      if (!text || !text.trim()) {
        return;
      }
      const parsedXml = parsePlexLyricsXml(text);
      if (parsedXml.length > 0) {
        pushCandidate(parsedXml);
      } else {
        pushCandidate(text);
      }
    } catch (error) {
      if (error?.name === 'AbortError' || error?.code === 'ABORT_ERR') {
        throw error;
      }
    }
  };

  await tryJsonPayload(metadataPath, {
    includeExternalMedia: 1,
    includeLyrics: 1,
    includePreferences: 1,
    asyncAugmentMetadata: 1,
  });
  await tryJsonPayload(`${metadataPath}/lyrics`, { format: 'json' });
  await tryJsonPayload(`${metadataPath}/lyrics`);
  await tryTextPayload(`${metadataPath}/lyrics`, { format: 'xml' });

  // Explicitly parse metadata XML for lyric stream keys/id (more reliable than JSON shape).
  try {
    const metadataXml = await fetchPmsText(baseUrl, plexToken, metadataPath, {
      searchParams: {
        includeExternalMedia: 1,
        includeLyrics: 1,
        includePreferences: 1,
        format: 'xml',
      },
      signal,
    });
    for (const key of extractLyricStreamKeysFromMetadataXml(metadataXml)) {
      streamKeysFromXml.add(key);
    }
  } catch (error) {
    if (error?.name === 'AbortError' || error?.code === 'ABORT_ERR') {
      throw error;
    }
  }

  for (const payload of payloads) {
    pushCandidate(payload?.MediaContainer?.Lyrics);
    pushCandidate(payload?.MediaContainer?.Lyric);
    pushCandidate(payload?.MediaContainer?.Metadata);
    pushCandidate(payload?.MediaContainer?.Track);

    const hintValues = [];
    collectLyricHints(payload, hintValues);
    for (const hint of hintValues) {
      pushCandidate(hint);
    }
  }

  for (const payload of payloads) {
    collectLyricStreamKeys(payload, streamKeys);
  }
  for (const key of streamKeysFromXml) {
    streamKeys.add(key);
  }

  for (const key of streamKeys) {
    try {
      const text = await fetchPmsText(baseUrl, plexToken, key, {
        searchParams: { format: 'xml', 'X-Plex-Text-Format': 'plain' },
        signal,
      });
      if (text && text.trim()) {
        const parsedXml = parsePlexLyricsXml(text);
        if (parsedXml.length > 0) {
          pushCandidate(parsedXml);
        } else {
          pushCandidate(text);
        }
      }
    } catch (error) {
      if (error?.name === 'AbortError' || error?.code === 'ABORT_ERR') {
        throw error;
      }
    }
  }

  return candidates;
}

export function buildPmsAssetUrl(baseUrl, plexToken, relativePath) {
  const primaryToken = normalizePlexTokenCandidates(plexToken)[0] || null;
  const url = joinBaseAndPath(baseUrl, relativePath);
  if (primaryToken) {
    url.searchParams.set('X-Plex-Token', primaryToken);
  }
  return url;
}
