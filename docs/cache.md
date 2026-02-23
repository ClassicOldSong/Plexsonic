# Plex Metadata Cache

This project uses a JSON-first, WAL-backed SQLite cache for Plex metadata.
Responses are built from normalized cache rows, then mapped to Subsonic JSON; XML is only serialized at response time.

## 1. Storage Model

- Credentials/session DB: `SQLITE_PATH` (default `./data/app.db`)
- Cache DB: `CACHE_SQLITE_PATH` (default `./data/cache.db`)
- Both are opened with:
  - `PRAGMA journal_mode = WAL`
  - `PRAGMA foreign_keys = ON`

Code:
- `src/db.js` (`openDatabase`, `migrate`, `migrateCache`)
- `src/server.js` (`buildServer`)

## 2. Cache Schema (Normalized, Typed Tables)

State table:
- `plex_library_cache_state`
  - One row per `cache_key`
  - Tracks `last_fingerprint`, `last_checked_at`, `last_synced_at`, `dirty`, `updated_at`

Entity tables:
- `plex_library_cache_artists`
- `plex_library_cache_albums`
- `plex_library_cache_tracks`

Relation tables:
- `plex_library_cache_album_genres`
- `plex_library_cache_track_genres`
- `plex_library_cache_track_artists`
- `plex_library_cache_track_album_artists`

There is no `plex_library_cache_items` JSON blob table anymore.

## 3. Cache Key

Cache key format:
- `${plexAccountScope}:${machineId}:${musicSectionId}`

`plexAccountScope` is derived from the linked Plex account token (hashed), not the local Plexsonic account ID.
This lets multiple local Plexsonic accounts linked to the same Plex account share one cache for the same server/library.

## 4. No In-Memory Metadata Cache

The metadata source of truth is SQLite.

In-memory maps are coordination-only:
- `cacheWarmupInFlight`
- `cacheCollectionLoadInFlight`
- `cacheRefreshInFlight`
- `cacheChangeCheckInFlight`

They deduplicate concurrent work but do not store canonical metadata payloads.

## 5. Read Path

Read helpers (`ensureSearchBrowseCollectionReady`, `query*` functions) work as follows:

1. If any cache exists, run debounced change check (`maybeCheckLibraryChanges`).
2. If cache is marked dirty, refresh first (`ensureDirtySearchBrowseRefresh(..., wait: true)`).
3. If the requested collection is missing, load it from Plex in foreground.
4. Serve from SQLite.
5. If data is stale by debounce window, schedule background refresh.

Debounce values:
- Revalidate debounce: `15s`
- Fingerprint check debounce: `15s`

## 6. Write/Refresh Path

`loadSearchBrowseCollection`:

1. Loads from Plex (`listArtists`, `listAlbums`, `listTracks`)
2. Builds typed row payloads
3. Replaces one collection atomically (delete + insert in transaction)
4. Updates `plex_library_cache_state`

`refreshSearchBrowseCollectionsForCacheKey` refreshes collections sequentially to reduce peak memory.
Startup warm-up also runs sequentially per linked library for the same reason.

## 7. Warm-Up Triggers

- Startup: `warmAllLinkedLibraryCaches('startup')`
- Library selection in Web UI: `warmLibraryCacheForAccount(..., reason: 'library-selected', forceRefresh: true)`
- First request for a missing collection: foreground load

## 8. Invalidation / Update Triggers

### A) Plex webhooks (`POST /webhooks/plex`)

- Full dirty mark for library/media change events (for example add/delete/library events)
- Rating events (`media.rate`, `media.unrate`) try direct cache patch first; fallback to dirty mark

### B) Manual scan (`/rest/startScan.view`)

- Triggers Plex refresh
- Marks the selected cache key dirty

### C) Fingerprint drift detection

`maybeCheckLibraryChanges` compares current fingerprint against stored fingerprint.
If changed, cache is marked dirty and refreshed.

## 9. Rating Consistency

For `star`, `unstar`, and `setRating`:

1. Apply to Plex
2. Patch typed cache rows immediately (`artists` / `albums` / `tracks` user rating fields)
3. If immediate patch cannot locate target rows, mark cache dirty

There is no short-lived in-memory rating overlay anymore.

## 10. Cache-First Coverage

These now query SQLite cache directly (paged SQL where applicable):

- `/rest/search.view`
- `/rest/search2.view`
- `/rest/search3.view`
- `/rest/getGenres.view`
- `/rest/getSongsByGenre.view`
- `/rest/getAlbumList.view`
- `/rest/getAlbumList2.view`

ID resolution for `local://...`, `plex://...`, metadata paths, and numeric IDs is also cache-first.

## 11. Still Plex-Direct Paths

Some endpoints still fetch Plex directly by design, especially:

- stream/download/cover-art proxy
- lyrics
- similar songs/top songs
- playlist operations
- some detailed metadata fetches as fallback paths

## 12. Failure Behavior

- Background refresh failure: continue serving persisted SQLite data
- Dirty refresh with `wait: true`: failures are swallowed to preserve availability
- If a collection was previously synced and is truly empty, return empty list without forced reload

## 13. Cache Schema Compatibility Note

The cache is disposable.
If an older cache schema is detected (for example missing new typed columns), cache tables are dropped and recreated automatically during `migrateCache`.
