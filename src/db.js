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

import fs from 'node:fs';
import path from 'node:path';
import Database from 'better-sqlite3';

function ensureDbDir(dbPath) {
  const dir = path.dirname(path.resolve(dbPath));
  fs.mkdirSync(dir, { recursive: true });
}

function nowEpochSeconds() {
  return Math.floor(Date.now() / 1000);
}

export function openDatabase(dbPath) {
  ensureDbDir(dbPath);

  const db = new Database(dbPath);
  db.pragma('journal_mode = WAL');
  db.pragma('foreign_keys = ON');

  return db;
}

export function migrate(db) {
  db.exec(`
    CREATE TABLE IF NOT EXISTS accounts (
      id TEXT PRIMARY KEY,
      username TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      subsonic_password_enc BLOB,
      enabled INTEGER NOT NULL DEFAULT 1,
      created_at INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS plex_links (
      account_id TEXT PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
      plex_token_enc BLOB NOT NULL,
      plex_token_created_at INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS plex_selected_server (
      account_id TEXT PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
      machine_id TEXT NOT NULL,
      name TEXT NOT NULL,
      base_url TEXT NOT NULL,
      server_token_enc BLOB,
      updated_at INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS plex_selected_library (
      account_id TEXT PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
      music_section_id TEXT NOT NULL,
      music_section_name TEXT,
      updated_at INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS plex_pin_sessions (
      id TEXT PRIMARY KEY,
      account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
      pin_id TEXT NOT NULL,
      code TEXT NOT NULL,
      auth_url TEXT NOT NULL,
      created_at INTEGER NOT NULL,
      status TEXT NOT NULL,
      last_polled_at INTEGER
    );

    CREATE INDEX IF NOT EXISTS idx_plex_pin_sessions_account_id
      ON plex_pin_sessions(account_id);

    CREATE INDEX IF NOT EXISTS idx_plex_pin_sessions_status
      ON plex_pin_sessions(status);

    CREATE TABLE IF NOT EXISTS web_sessions (
      session_id TEXT PRIMARY KEY,
      session_json TEXT NOT NULL,
      expires_at INTEGER,
      updated_at INTEGER NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_web_sessions_expires_at
      ON web_sessions(expires_at);
  `);

  const accountColumns = db.prepare(`PRAGMA table_info(accounts)`).all();
  const hasSubsonicPasswordEnc = accountColumns.some((column) => column.name === 'subsonic_password_enc');
  if (!hasSubsonicPasswordEnc) {
    db.exec('ALTER TABLE accounts ADD COLUMN subsonic_password_enc BLOB');
  }

  const selectedLibraryColumns = db.prepare(`PRAGMA table_info(plex_selected_library)`).all();
  const hasMusicSectionName = selectedLibraryColumns.some((column) => column.name === 'music_section_name');
  if (!hasMusicSectionName) {
    db.exec('ALTER TABLE plex_selected_library ADD COLUMN music_section_name TEXT');
  }

  const selectedServerColumns = db.prepare(`PRAGMA table_info(plex_selected_server)`).all();
  const hasServerTokenEnc = selectedServerColumns.some((column) => column.name === 'server_token_enc');
  if (!hasServerTokenEnc) {
    db.exec('ALTER TABLE plex_selected_server ADD COLUMN server_token_enc BLOB');
  }
}

export function createRepositories(db) {
  const createAccountStmt = db.prepare(`
    INSERT INTO accounts (id, username, password_hash, subsonic_password_enc, enabled, created_at)
    VALUES (@id, @username, @password_hash, @subsonic_password_enc, 1, @created_at)
  `);

  const getAccountByUsernameStmt = db.prepare(`
    SELECT id, username, password_hash, subsonic_password_enc, enabled, created_at
    FROM accounts
    WHERE username = ?
  `);

  const getAccountByIdStmt = db.prepare(`
    SELECT id, username, enabled, created_at
    FROM accounts
    WHERE id = ?
  `);

  const updateSubsonicPasswordEncStmt = db.prepare(`
    UPDATE accounts
    SET subsonic_password_enc = @subsonic_password_enc
    WHERE id = @id
  `);

  const updateAccountPasswordStmt = db.prepare(`
    UPDATE accounts
    SET password_hash = @password_hash,
        subsonic_password_enc = @subsonic_password_enc
    WHERE id = @id
  `);

  const hasAnyAccountStmt = db.prepare(`
    SELECT 1 AS exists_flag
    FROM accounts
    LIMIT 1
  `);

  const upsertPlexLinkStmt = db.prepare(`
    INSERT INTO plex_links (account_id, plex_token_enc, plex_token_created_at)
    VALUES (@account_id, @plex_token_enc, @plex_token_created_at)
    ON CONFLICT(account_id)
    DO UPDATE SET
      plex_token_enc = excluded.plex_token_enc,
      plex_token_created_at = excluded.plex_token_created_at
  `);

  const getPlexLinkByAccountIdStmt = db.prepare(`
    SELECT account_id, plex_token_enc, plex_token_created_at
    FROM plex_links
    WHERE account_id = ?
  `);

  const upsertSelectedServerStmt = db.prepare(`
    INSERT INTO plex_selected_server (account_id, machine_id, name, base_url, server_token_enc, updated_at)
    VALUES (@account_id, @machine_id, @name, @base_url, @server_token_enc, @updated_at)
    ON CONFLICT(account_id)
    DO UPDATE SET
      machine_id = excluded.machine_id,
      name = excluded.name,
      base_url = excluded.base_url,
      server_token_enc = excluded.server_token_enc,
      updated_at = excluded.updated_at
  `);

  const getSelectedServerByAccountIdStmt = db.prepare(`
    SELECT account_id, machine_id, name, base_url, server_token_enc, updated_at
    FROM plex_selected_server
    WHERE account_id = ?
  `);

  const upsertSelectedLibraryStmt = db.prepare(`
    INSERT INTO plex_selected_library (account_id, music_section_id, music_section_name, updated_at)
    VALUES (@account_id, @music_section_id, @music_section_name, @updated_at)
    ON CONFLICT(account_id)
    DO UPDATE SET
      music_section_id = excluded.music_section_id,
      music_section_name = excluded.music_section_name,
      updated_at = excluded.updated_at
  `);

  const getSelectedLibraryByAccountIdStmt = db.prepare(`
    SELECT account_id, music_section_id, music_section_name, updated_at
    FROM plex_selected_library
    WHERE account_id = ?
  `);

  const createPinSessionStmt = db.prepare(`
    INSERT INTO plex_pin_sessions (
      id,
      account_id,
      pin_id,
      code,
      auth_url,
      created_at,
      status,
      last_polled_at
    ) VALUES (
      @id,
      @account_id,
      @pin_id,
      @code,
      @auth_url,
      @created_at,
      @status,
      NULL
    )
  `);

  const getPinSessionByIdStmt = db.prepare(`
    SELECT id, account_id, pin_id, code, auth_url, created_at, status, last_polled_at
    FROM plex_pin_sessions
    WHERE id = ?
  `);

  const updatePinSessionPollTimeStmt = db.prepare(`
    UPDATE plex_pin_sessions
    SET last_polled_at = @last_polled_at
    WHERE id = @id
  `);

  const updatePinSessionStatusStmt = db.prepare(`
    UPDATE plex_pin_sessions
    SET status = @status
    WHERE id = @id
  `);

  const getAccountPlexContextStmt = db.prepare(`
    SELECT
      a.id AS account_id,
      a.username AS username,
      a.enabled AS enabled,
      pl.plex_token_enc AS plex_token_enc,
      pss.machine_id AS machine_id,
      pss.name AS server_name,
      pss.base_url AS server_base_url,
      pss.server_token_enc AS server_token_enc,
      psl.music_section_id AS music_section_id,
      psl.music_section_name AS music_section_name
    FROM accounts a
    LEFT JOIN plex_links pl ON pl.account_id = a.id
    LEFT JOIN plex_selected_server pss ON pss.account_id = a.id
    LEFT JOIN plex_selected_library psl ON psl.account_id = a.id
    WHERE a.id = ?
  `);

  const deletePlexLinkStmt = db.prepare(`
    DELETE FROM plex_links
    WHERE account_id = ?
  `);

  const deleteSelectedServerStmt = db.prepare(`
    DELETE FROM plex_selected_server
    WHERE account_id = ?
  `);

  const deleteSelectedLibraryStmt = db.prepare(`
    DELETE FROM plex_selected_library
    WHERE account_id = ?
  `);

  const deletePinSessionsStmt = db.prepare(`
    DELETE FROM plex_pin_sessions
    WHERE account_id = ?
  `);

  return {
    createAccount({ id, username, passwordHash, subsonicPasswordEnc = null }) {
      createAccountStmt.run({
        id,
        username,
        password_hash: passwordHash,
        subsonic_password_enc: subsonicPasswordEnc,
        created_at: nowEpochSeconds(),
      });
    },

    getAccountByUsername(username) {
      return getAccountByUsernameStmt.get(username) || null;
    },

    getAccountById(accountId) {
      return getAccountByIdStmt.get(accountId) || null;
    },

    updateSubsonicPasswordEnc(accountId, subsonicPasswordEnc) {
      updateSubsonicPasswordEncStmt.run({
        id: accountId,
        subsonic_password_enc: subsonicPasswordEnc,
      });
    },

    updateAccountPassword({ accountId, passwordHash, subsonicPasswordEnc }) {
      updateAccountPasswordStmt.run({
        id: accountId,
        password_hash: passwordHash,
        subsonic_password_enc: subsonicPasswordEnc,
      });
    },

    hasAnyAccount() {
      return Boolean(hasAnyAccountStmt.get());
    },

    upsertPlexLink({ accountId, encryptedToken }) {
      upsertPlexLinkStmt.run({
        account_id: accountId,
        plex_token_enc: encryptedToken,
        plex_token_created_at: nowEpochSeconds(),
      });
    },

    getPlexLinkByAccountId(accountId) {
      return getPlexLinkByAccountIdStmt.get(accountId) || null;
    },

    upsertSelectedServer({ accountId, machineId, name, baseUrl, encryptedServerToken = null }) {
      upsertSelectedServerStmt.run({
        account_id: accountId,
        machine_id: machineId,
        name,
        base_url: baseUrl,
        server_token_enc: encryptedServerToken,
        updated_at: nowEpochSeconds(),
      });
    },

    getSelectedServerByAccountId(accountId) {
      return getSelectedServerByAccountIdStmt.get(accountId) || null;
    },

    upsertSelectedLibrary({ accountId, musicSectionId, musicSectionName = null }) {
      upsertSelectedLibraryStmt.run({
        account_id: accountId,
        music_section_id: musicSectionId,
        music_section_name: musicSectionName,
        updated_at: nowEpochSeconds(),
      });
    },

    getSelectedLibraryByAccountId(accountId) {
      return getSelectedLibraryByAccountIdStmt.get(accountId) || null;
    },

    createPinSession({ id, accountId, pinId, code, authUrl }) {
      createPinSessionStmt.run({
        id,
        account_id: accountId,
        pin_id: pinId,
        code,
        auth_url: authUrl,
        created_at: nowEpochSeconds(),
        status: 'pending',
      });
    },

    getPinSessionById(id) {
      return getPinSessionByIdStmt.get(id) || null;
    },

    updatePinSessionPollTime(id) {
      updatePinSessionPollTimeStmt.run({
        id,
        last_polled_at: nowEpochSeconds(),
      });
    },

    updatePinSessionStatus(id, status) {
      updatePinSessionStatusStmt.run({ id, status });
    },

    markPinLinkedAndStoreToken({ pinSessionId, accountId, encryptedToken }) {
      const tx = db.transaction(() => {
        upsertPlexLinkStmt.run({
          account_id: accountId,
          plex_token_enc: encryptedToken,
          plex_token_created_at: nowEpochSeconds(),
        });
        updatePinSessionStatusStmt.run({ id: pinSessionId, status: 'linked' });
        updatePinSessionPollTimeStmt.run({ id: pinSessionId, last_polled_at: nowEpochSeconds() });
      });

      tx();
    },

    getAccountPlexContext(accountId) {
      return getAccountPlexContextStmt.get(accountId) || null;
    },

    unlinkPlex(accountId) {
      const tx = db.transaction(() => {
        deleteSelectedLibraryStmt.run(accountId);
        deleteSelectedServerStmt.run(accountId);
        deletePlexLinkStmt.run(accountId);
        deletePinSessionsStmt.run(accountId);
      });

      tx();
    },
  };
}
