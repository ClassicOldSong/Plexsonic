FROM node:24-alpine AS base

ENV PNPM_HOME=/pnpm
ENV PATH=${PNPM_HOME}:${PATH}

WORKDIR /app

RUN corepack enable

FROM base AS deps

COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./

RUN pnpm install --frozen-lockfile --prod

# Verify the bundled native binaries on the target platform without a compiler.
RUN node --input-type=module -e '\
  import assert from "node:assert/strict"; \
  import Database from "better-sqlite3"; \
  import argon2 from "argon2"; \
  const db = new Database(":memory:"); \
  assert.equal(db.prepare("SELECT 1").pluck().get(), 1); \
  db.close(); \
  const hash = await argon2.hash("build-check"); \
  assert.equal(await argon2.verify(hash, "build-check"), true);'

FROM base AS runtime

ENV NODE_ENV=production

WORKDIR /app

RUN apk add --no-cache ffmpeg

COPY --from=deps /app/node_modules ./node_modules
COPY package.json ./
COPY src ./src

RUN mkdir -p /app/data

EXPOSE 3127

CMD ["node", "src/index.js"]
