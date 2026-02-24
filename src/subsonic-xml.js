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
const ROOT_NAME = 'subsonic-response';
const XMLNS = 'http://subsonic.org/restapi';
const API_VERSION = '1.16.1';
const SERVER_TYPE = 'Plexsonic';
const SERVER_VERSION = APP_VERSION;
const OPEN_SUBSONIC = true;

const ROOT_ATTR_KEYS = new Set([
  'status',
  'version',
  'type',
  'serverVersion',
  'openSubsonic',
  'xmlns',
]);

const XML_ATTR_LIST_KEYS = new Set(['genres', 'moods', 'styles', 'recordLabels']);

// Dedicated XML schema rules: these define repeated child elements by parent element.
const ARRAY_CHILDREN_BY_PARENT = {
  openSubsonicExtensions: new Set(['openSubsonicExtension']),
  albumList: new Set(['album']),
  albumList2: new Set(['album']),
  artists: new Set(['index']),
  indexes: new Set(['index']),
  index: new Set(['artist']),
  artist: new Set(['album']),
  album: new Set(['song']),
  albumArtists: new Set(['artist']),
  songsByGenre: new Set(['song']),
  randomSongs: new Set(['song']),
  topSongs: new Set(['song']),
  similarSongs: new Set(['song']),
  similarSongs2: new Set(['song']),
  searchResult: new Set(['artist', 'album', 'match']),
  searchResult2: new Set(['artist', 'album', 'song']),
  searchResult3: new Set(['artist', 'album', 'song']),
  musicFolders: new Set(['musicFolder']),
  genres: new Set(['genre']),
  playlists: new Set(['playlist']),
  directory: new Set(['child']),
  playlist: new Set(['entry']),
  playQueue: new Set(['entry']),
  nowPlaying: new Set(['entry']),
  lyricsList: new Set(['structuredLyrics']),
  structuredLyrics: new Set(['line']),
  starred: new Set(['artist', 'album', 'song']),
  starred2: new Set(['artist', 'album', 'song']),
};

// Dedicated scalar-child rules for XML where values should be child elements, not attributes.
const SCALAR_CHILDREN_BY_PARENT = {
  artistInfo: new Set(['biography', 'musicBrainzId']),
  artistInfo2: new Set(['biography', 'musicBrainzId']),
};

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

export function xmlEscape(value) {
  const sanitized = sanitizeXmlText(String(value));
  return sanitized
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&apos;');
}

function splitList(rawValue) {
  if (Array.isArray(rawValue)) {
    return rawValue.map((entry) => String(entry || '').trim()).filter(Boolean);
  }

  const raw = String(rawValue || '').trim();
  if (!raw) {
    return [];
  }

  const parts = raw.includes(';') ? raw.split(';') : raw.split(',');
  return parts.map((part) => part.trim()).filter(Boolean);
}

function toXmlAttrValue(key, value) {
  if (value === undefined || value === null) {
    return null;
  }

  if (key === 'genres' || key === 'recordLabels') {
    const names = Array.isArray(value)
      ? value
        .map((entry) => {
          if (entry && typeof entry === 'object') {
            return String(entry.name || '').trim();
          }
          return String(entry || '').trim();
        })
        .filter(Boolean)
      : splitList(value);
    return names.join('; ');
  }

  if (key === 'moods' || key === 'styles') {
    return splitList(value).join('; ');
  }

  if (Array.isArray(value)) {
    return value.map((entry) => String(entry)).join(',');
  }

  if (typeof value === 'boolean') {
    return value ? 'true' : 'false';
  }

  return String(value);
}

function xmlAttrs(attrs = {}) {
  return Object.entries(attrs)
    .map(([key, value]) => {
      const attrValue = toXmlAttrValue(key, value);
      if (attrValue == null) {
        return '';
      }
      return ` ${key}="${xmlEscape(attrValue)}"`;
    })
    .join('');
}

function shouldUseArray(parentName, childName) {
  return ARRAY_CHILDREN_BY_PARENT[parentName]?.has(childName) || false;
}

function isScalarChild(parentName, childName) {
  return SCALAR_CHILDREN_BY_PARENT[parentName]?.has(childName) || false;
}

function defaultArrayChildName(parentName) {
  const children = ARRAY_CHILDREN_BY_PARENT[parentName];
  if (!children || children.size !== 1) {
    return null;
  }
  return [...children][0];
}

function isFlattenArtistList(name, value) {
  if ((name !== 'artists' && name !== 'albumArtists') || !Array.isArray(value)) {
    return false;
  }
  if (value.length === 0) {
    return true;
  }
  return value.every((entry) => entry && typeof entry === 'object' && !Array.isArray(entry));
}

function shouldRenderAsChild(parentName, key, value) {
  if (parentName === ROOT_NAME) {
    return !ROOT_ATTR_KEYS.has(key);
  }

  if (key === 'value') {
    return false;
  }

  if (isScalarChild(parentName, key)) {
    return true;
  }

  if (shouldUseArray(parentName, key)) {
    return true;
  }

  if (XML_ATTR_LIST_KEYS.has(key)) {
    return false;
  }

  if (Array.isArray(value)) {
    return value.some((entry) => entry && typeof entry === 'object');
  }

  return Boolean(value && typeof value === 'object');
}

function renderXmlElement(name, value) {
  if (value === undefined || value === null) {
    return `<${name}/>`;
  }

  if (typeof value !== 'object') {
    return `<${name}>${xmlEscape(value)}</${name}>`;
  }

  if (Array.isArray(value)) {
    const childName =
      (name === 'artists' || name === 'albumArtists')
        ? 'artist'
        : defaultArrayChildName(name);
    const attrs = isFlattenArtistList(name, value) ? { flatten: 'true' } : {};

    if (!childName) {
      const text = value.map((entry) => String(entry)).join(', ');
      return `<${name}${xmlAttrs(attrs)}>${xmlEscape(text)}</${name}>`;
    }

    const inner = value.map((entry) => renderXmlElement(childName, entry)).join('');
    if (!inner) {
      return `<${name}${xmlAttrs(attrs)}/>`;
    }

    return `<${name}${xmlAttrs(attrs)}>${inner}</${name}>`;
  }

  const attrs = {};
  let textValue = '';
  const childParts = [];

  for (const [key, childValue] of Object.entries(value)) {
    if (key === 'value') {
      textValue += String(childValue || '');
      continue;
    }

    if (!shouldRenderAsChild(name, key, childValue)) {
      attrs[key] = childValue;
      continue;
    }

    if (Array.isArray(childValue)) {
      if (shouldUseArray(name, key)) {
        for (const entry of childValue) {
          childParts.push(renderXmlElement(key, entry));
        }
      } else {
        childParts.push(renderXmlElement(key, childValue));
      }
      continue;
    }

    childParts.push(renderXmlElement(key, childValue));
  }

  const inner = `${xmlEscape(textValue)}${childParts.join('')}`;
  if (!inner) {
    return `<${name}${xmlAttrs(attrs)}/>`;
  }

  return `<${name}${xmlAttrs(attrs)}>${inner}</${name}>`;
}

function normalizeInner(inner) {
  if (!inner || typeof inner !== 'object' || Array.isArray(inner)) {
    return {};
  }
  const out = {};
  for (const [key, value] of Object.entries(inner)) {
    if (Array.isArray(value)) {
      const childName = defaultArrayChildName(key);
      if (childName && key !== 'artists' && key !== 'albumArtists') {
        out[key] = { [childName]: value };
      } else {
        out[key] = value;
      }
      continue;
    }
    out[key] = value;
  }
  return out;
}

function buildRoot(status, inner = {}) {
  return {
    status,
    version: API_VERSION,
    type: SERVER_TYPE,
    serverVersion: SERVER_VERSION,
    openSubsonic: OPEN_SUBSONIC,
    ...normalizeInner(inner),
  };
}

export function okResponseJson(inner = {}) {
  return {
    [ROOT_NAME]: buildRoot('ok', inner),
  };
}

export function failedResponseJson(code, message) {
  return {
    [ROOT_NAME]: buildRoot('failed', {
      error: {
        code,
        message: String(message),
      },
    }),
  };
}

export function subsonicJsonToXml(payload) {
  const rootValue = payload?.[ROOT_NAME];
  const safeRoot = rootValue && typeof rootValue === 'object' && !Array.isArray(rootValue)
    ? rootValue
    : buildRoot('failed', {
      error: {
        code: 0,
        message: 'Invalid Subsonic payload',
      },
    });

  const xmlRoot = safeRoot.xmlns ? safeRoot : { ...safeRoot, xmlns: XMLNS };
  return `${XML_HEADER}${renderXmlElement(ROOT_NAME, xmlRoot)}`;
}

export function okResponse(inner = {}) {
  return subsonicJsonToXml(okResponseJson(inner));
}

export function failedResponse(code, message) {
  return subsonicJsonToXml(failedResponseJson(code, message));
}
