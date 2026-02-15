# Plexsonic

Plexsonic is a local bridge that exposes a Plex music library through Subsonic/OpenSubsonic-compatible endpoints.

It provides:
- Local account signup/login
- Plex account linking via Plex PIN
- Plex server and music library selection
- Subsonic-compatible `/rest/*.view` API for clients
- Web test page for manual API checks
- Playback/scrobble/rating/playlist actions mapped to Plex

To support this project, please subscribe to my [Patreon](https://www.patreon.com/ClassicOldSong).

[![Support me on Patreon](https://img.shields.io/endpoint.svg?url=https%3A%2F%2Fshieldsio-patreon.vercel.app%2Fapi%3Fusername%3DClassicOldsong%26type%3Dpatrons&style=for-the-badge)](https://patreon.com/ClassicOldsong)

## Requirements

- Node.js 18+ (Node 20 recommended)
- `pnpm`
- A reachable Plex Media Server with a music library
- A Plex account with access to that server

## Install

```bash
pnpm install
cp .env.example .env
```

### Global CLI install

Install globally from this repo:

```bash
pnpm add -g plexsonic
# or
npm install -g plexsonic
```

Then run:

```bash
plexsonic
```

## Configuration

Edit `.env`:

```env
PORT=3127
BIND_HOST=127.0.0.1
BASE_URL=
SQLITE_PATH=./data/app.db
SESSION_SECRET=replace-with-a-long-random-secret
TOKEN_ENC_KEY=
PLEX_PRODUCT=Plexsonic Bridge
PLEX_CLIENT_IDENTIFIER=
PLEX_WEBHOOK_TOKEN=
LICENSE_EMAIL=
PLEX_INSECURE_TLS=0
LOG_LEVEL=warn
LOG_REQUESTS=0
```

### Important env vars

- `PORT`: HTTP port (default `3127`).
- `BIND_HOST`: listen interface (`127.0.0.1` local only, `0.0.0.0` for LAN).
- `BASE_URL`: optional public URL override used for callback generation. If empty, origin is derived from request headers.
- `PLEX_WEBHOOK_TOKEN`: optional shared secret for `/webhooks/plex`. If set, webhook calls must provide this token.
- `SESSION_SECRET`: cookie/session signing secret. Keep stable across restarts.
- `TOKEN_ENC_KEY`: optional but recommended 32-byte key (hex or base64) used to encrypt stored Plex tokens.
- `LOG_LEVEL`: logger level (`trace`, `debug`, `info`, `warn`, `error`, `fatal`).
- `LOG_REQUESTS`: set to `1` to enable incoming request logs. Very verbose, and can expose login credentials. (`0` by default).

Generate secrets (examples):

```bash
# SESSION_SECRET
openssl rand -hex 32

# TOKEN_ENC_KEY (hex)
openssl rand -hex 32
```

## Run

```bash
pnpm start
```

Or, if installed globally:

```bash
plexsonic
```

Dev mode:

```bash
pnpm dev
```

## Docker

Build and run with Compose:

```bash
docker compose up -d --build
```

Notes:
- Compose maps `3127:3127`.
- `./data` is mounted to `/app/data` for SQLite persistence.
- `docker-compose.yml` uses `${VAR:-default}` interpolation.
- You should change at least:
  - `SESSION_SECRET`
  - `TOKEN_ENC_KEY` (recommended)
  - `BASE_URL` only if auto-detected origin is wrong in your proxy/network setup

Override via CLI (without editing compose):

```bash
SESSION_SECRET='replace-me' \
TOKEN_ENC_KEY='your-32-byte-key' \
BASE_URL='http://192.168.1.50:3127' \
docker compose up -d --build
```

Or with an env file:

```bash
docker compose --env-file .env up -d --build
```

Stop:

```bash
docker compose down
```

Health check:

```bash
curl http://127.0.0.1:3127/health
```

## Web Setup Flow

1. Open `http://127.0.0.1:3127/signup`
2. Create a local Plexsonic account
3. Link Plex (`/link/plex`) and complete PIN auth
4. Select Plex server
5. Select music library
6. Open `/test` to run quick API checks

## Using From Subsonic/OpenSubsonic Clients

Use:
- Server URL: `http://<host>:3127`
- Username/password: your local Plexsonic account

### Endpoint suffix compatibility

Both endpoint styles are accepted:
- `/rest/getArtists.view`
- `/rest/getArtists`

### Star/Like Mapping (Plex)

Plexsonic maps Subsonic rating + star state into a single Plex numeric rating:
- Odd points = rated only (not liked): `1, 3, 5, 7, 9`
- Even points = liked: `2, 4, 6, 8, 10`
- `0` = no rating and not liked

Behavior:
- `setRating(r)` updates stars and keeps current like state when possible.
- `star` toggles like on and keeps star level. If unrated, it becomes `10` points (liked + 5+star).
- `unstar` toggles like off and keeps star level.

## Expose to LAN

Set:

```env
BIND_HOST=0.0.0.0
# Optional when auto-detection is not correct:
# BASE_URL=http://<your-lan-ip>:3127
```

Then:
- Open firewall inbound TCP `3127`
- Keep it LAN-only (do not expose directly to the internet)

If you run behind a reverse proxy, forward `X-Forwarded-Proto` and `X-Forwarded-Host` so Plex PIN callbacks use the correct public origin.

Without HTTPS, credentials travel unencrypted on your network.

## Plex Webhooks (Optional, Recommended)

Webhook purpose: Plex notifies Plexsonic on library/media events so Plexsonic can refresh caches faster and reduce stale results.

Plex does not auto-discover Plexsonic. You must add the webhook URL in Plex Media Server settings.

1. Open Plex Media Server settings, then `Network` -> `Webhooks`.
2. Add your Plexsonic endpoint URL.
Without token: `http://<your-host>:3127/webhooks/plex`
With token: `http://<your-host>:3127/webhooks/plex?token=<PLEX_WEBHOOK_TOKEN>`
3. Save settings in Plex.

Notes:
- `BASE_URL` is not required for webhook processing.
- Webhook URL must be reachable by your Plex Media Server (LAN IP/hostname or public URL, depending on your setup).

## Notes

- This project currently targets practical client compatibility over strict parity with any single server implementation.
- Some Subsonic features may be partially implemented or client-dependent.

## License

Apache-2.0
