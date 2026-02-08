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

const XML_HEADER = '<?xml version="1.0" encoding="UTF-8"?>';
const XMLNS = 'http://subsonic.org/restapi';
const API_VERSION = '1.16.1';
const SERVER_TYPE = 'Plexsonic';
const SERVER_VERSION = APP_VERSION;
const OPEN_SUBSONIC = true;

const TOKEN_START = '\u0001';
const TOKEN_END = '\u0002';
const TOKEN_PATTERN = /\u0001(\d+)\u0002/g;

let nodeSeq = 0;
const nodeRegistry = new Map();

export function xmlEscape(value) {
  const sanitized = sanitizeXmlText(String(value));
  return sanitized
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&apos;');
}

function sanitizeXmlText(value) {
  let output = '';
  for (const char of value) {
    const codePoint = char.codePointAt(0);
    if (
      codePoint === 0x9 ||
      codePoint === 0xa ||
      codePoint === 0xd ||
      (codePoint >= 0x20 && codePoint <= 0xd7ff) ||
      (codePoint >= 0xe000 && codePoint <= 0xfffd) ||
      (codePoint >= 0x10000 && codePoint <= 0x10ffff)
    ) {
      output += char;
    }
  }
  return output;
}

function storeNode(node) {
  const id = ++nodeSeq;
  nodeRegistry.set(id, node);
  return `${TOKEN_START}${id}${TOKEN_END}`;
}

function parseTokenText(text) {
  const out = [];
  let index = 0;
  let match;

  TOKEN_PATTERN.lastIndex = 0;
  while ((match = TOKEN_PATTERN.exec(text)) !== null) {
    const before = text.slice(index, match.index);
    if (before) {
      out.push(before);
    }

    const nodeId = Number(match[1]);
    const tokenNode = nodeRegistry.get(nodeId);
    if (tokenNode) {
      out.push(tokenNode);
    }

    index = match.index + match[0].length;
  }

  const tail = text.slice(index);
  if (tail) {
    out.push(tail);
  }

  return out;
}

function normalizeChildren(input) {
  if (input == null) {
    return [];
  }
  if (Array.isArray(input)) {
    return input.flatMap((item) => normalizeChildren(item));
  }
  if (typeof input === 'string') {
    return parseTokenText(input);
  }
  if (typeof input === 'object' && input.kind === 'node') {
    return [input];
  }
  return [String(input)];
}

function xmlAttrs(attrs = {}) {
  return Object.entries(attrs)
    .filter(([, value]) => value !== undefined && value !== null)
    .map(([key, value]) => ` ${key}="${xmlEscape(value)}"`)
    .join('');
}

function renderXmlPart(part) {
  if (typeof part === 'string') {
    return xmlEscape(part);
  }
  if (!part || part.kind !== 'node') {
    return '';
  }

  const attrs = xmlAttrs(part.attrs);
  if (part.selfClosing && part.children.length === 0) {
    return `<${part.name}${attrs}/>`;
  }

  const inner = part.children.map(renderXmlPart).join('');
  return `<${part.name}${attrs}>${inner}</${part.name}>`;
}

function renderXmlChildren(inner) {
  return normalizeChildren(inner).map(renderXmlPart).join('');
}

const NUMERIC_ATTRS = new Set([
  'code',
  'count',
  'offset',
  'duration',
  'songCount',
  'albumCount',
  'track',
  'discNumber',
  'bitRate',
  'size',
  'year',
  'userRating',
  'playCount',
  'leafCount',
  'leafCountAdded',
  'leafCountRequested',
  'position',
  'lastModified',
  'start',
]);

const BOOLEAN_ATTRS = new Set([
  'openSubsonic',
  'valid',
  'scanning',
  'isDir',
  'public',
  'scrobblingEnabled',
  'adminRole',
  'settingsRole',
  'downloadRole',
  'uploadRole',
  'playlistRole',
  'coverArtRole',
  'commentRole',
  'podcastRole',
  'streamRole',
  'jukeboxRole',
  'shareRole',
  'videoConversionRole',
  'smart',
  'synced',
  'readonly',
]);

const ARRAY_CHILDREN_BY_PARENT = {
  openSubsonicExtensions: new Set(['openSubsonicExtension']),
  albumList: new Set(['album']),
  albumList2: new Set(['album']),
  artists: new Set(['index']),
  indexes: new Set(['index']),
  index: new Set(['artist']),
  artist: new Set(['album']),
  album: new Set(['song']),
  songsByGenre: new Set(['song']),
  randomSongs: new Set(['song']),
  topSongs: new Set(['song']),
  searchResult: new Set(['artist', 'album', 'match']),
  searchResult2: new Set(['artist', 'album', 'song']),
  searchResult3: new Set(['artist', 'album', 'song']),
  musicFolders: new Set(['musicFolder']),
  genres: new Set(['genre']),
  playlists: new Set(['playlist']),
  directory: new Set(['child']),
  playlist: new Set(['entry']),
  lyricsList: new Set(['structuredLyrics']),
  structuredLyrics: new Set(['line']),
  starred: new Set(['artist', 'album', 'song']),
  starred2: new Set(['artist', 'album', 'song']),
};

function shouldUseArray(parentName, childName) {
  return ARRAY_CHILDREN_BY_PARENT[parentName]?.has(childName) || false;
}

function coerceAttrValue(key, value) {
  if (key === 'genres') {
    const genreNames = (() => {
      if (Array.isArray(value)) {
        return value
          .flatMap((entry) => {
            if (entry == null) {
              return [];
            }
            if (typeof entry === 'string') {
              return [entry];
            }
            if (typeof entry === 'object') {
              return [String(entry.name || entry.tag || entry.value || entry.title || '').trim()];
            }
            return [String(entry).trim()];
          })
          .filter(Boolean);
      }

      const raw = String(value || '').trim();
      if (!raw) {
        return [];
      }
      const parts = raw.includes(';') ? raw.split(';') : raw.split(',');
      return parts.map((part) => part.trim()).filter(Boolean);
    })();

    return genreNames.map((name) => ({ name }));
  }

  if (key === 'moods') {
    if (Array.isArray(value)) {
      return value.map((entry) => String(entry || '').trim()).filter(Boolean);
    }
    const raw = String(value || '').trim();
    if (!raw) {
      return [];
    }
    const parts = raw.includes(';') ? raw.split(';') : raw.split(',');
    return parts.map((part) => part.trim()).filter(Boolean);
  }

  if (BOOLEAN_ATTRS.has(key)) {
    if (value === 'true') {
      return true;
    }
    if (value === 'false') {
      return false;
    }
  }

  if (NUMERIC_ATTRS.has(key) && /^-?\d+$/.test(String(value))) {
    return Number(value);
  }

  return value;
}

function nodeToJson(node) {
  const out = {};
  for (const [key, value] of Object.entries(node.attrs || {})) {
    out[key] = coerceAttrValue(key, value);
  }

  for (const child of node.children || []) {
    if (typeof child === 'string') {
      if (child.trim()) {
        out.value = (out.value || '') + child;
      }
      continue;
    }

    const value = nodeToJson(child);
    if (shouldUseArray(node.name, child.name)) {
      if (!Array.isArray(out[child.name])) {
        out[child.name] = [];
      }
      out[child.name].push(value);
      continue;
    }

    if (Object.prototype.hasOwnProperty.call(out, child.name)) {
      if (!Array.isArray(out[child.name])) {
        out[child.name] = [out[child.name]];
      }
      out[child.name].push(value);
      continue;
    }

    out[child.name] = value;
  }

  const arrayChildren = ARRAY_CHILDREN_BY_PARENT[node.name];
  if (arrayChildren) {
    for (const childName of arrayChildren) {
      if (!Object.prototype.hasOwnProperty.call(out, childName)) {
        out[childName] = [];
      }
    }
  }

  if (node.name === 'openSubsonicExtensions') {
    const extensions = out.openSubsonicExtension;
    if (Array.isArray(extensions)) {
      return extensions;
    }
    return extensions == null ? [] : [extensions];
  }

  return out;
}

function subsonicRoot(status, children = []) {
  return {
    kind: 'node',
    name: 'subsonic-response',
    selfClosing: false,
    attrs: {
      status,
      version: API_VERSION,
      type: SERVER_TYPE,
      serverVersion: SERVER_VERSION,
      openSubsonic: OPEN_SUBSONIC,
      xmlns: XMLNS,
    },
    children,
  };
}

export function emptyNode(name, attrs = {}) {
  return storeNode({
    kind: 'node',
    name,
    attrs,
    children: [],
    selfClosing: true,
  });
}

export function node(name, attrs = {}, inner = '') {
  return storeNode({
    kind: 'node',
    name,
    attrs,
    children: normalizeChildren(inner),
    selfClosing: false,
  });
}

export function okResponse(inner = '') {
  const root = subsonicRoot('ok', normalizeChildren(inner));
  return `${XML_HEADER}${renderXmlPart(root)}`;
}

export function failedResponse(code, message) {
  const errorNode = {
    kind: 'node',
    name: 'error',
    attrs: {
      code,
      message: String(message),
    },
    children: [],
    selfClosing: true,
  };
  const root = subsonicRoot('failed', [errorNode]);
  return `${XML_HEADER}${renderXmlPart(root)}`;
}

export function okResponseJson(inner = '') {
  const root = subsonicRoot('ok', normalizeChildren(inner));
  const json = nodeToJson(root);
  delete json.xmlns;
  return { 'subsonic-response': json };
}

export function failedResponseJson(code, message) {
  const errorNode = {
    kind: 'node',
    name: 'error',
    attrs: {
      code,
      message: String(message),
    },
    children: [],
    selfClosing: true,
  };
  const root = subsonicRoot('failed', [errorNode]);
  const json = nodeToJson(root);
  delete json.xmlns;
  return { 'subsonic-response': json };
}

// Backward-compatible export for older callsites.
export function responseJson(xml) {
  // Kept only for compatibility during migration; no XML parsing path is used by server responses.
  return {
    'subsonic-response': {
      status: 'failed',
      error: {
        code: 10,
        message: 'responseJson(xml) is deprecated',
      },
    },
  };
}
