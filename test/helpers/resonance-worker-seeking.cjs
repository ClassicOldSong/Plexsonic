// Run the production media-worker command handler against the Plexsonic fixture.
const assert = require('node:assert/strict');
const { pathToFileURL } = require('node:url');
const media = require('media');

(async () => {
  const moduleUrl = pathToFileURL(process.env.RESONANCE_PLAYER_MODULE);
  const { SubsonicPlaybackController } = await import(moduleUrl.href);
  const { startMediaWorker } = await import(new URL('media_worker_runtime.js', moduleUrl).href);
  let send;
  let waiter;
  let played = false;
  const waitForMessage = (predicate) => new Promise((resolve, reject) => {
    waiter = { predicate, resolve, reject };
  });
  startMediaWorker({
    parentPort: {
      on(event, callback) { send = callback; }, close() {},
      postMessage(message) {
        if (message.type === 'state') {
          console.error(JSON.stringify({ state: message.state, position: message.currentTime }));
          if (message.state === 'playing') played = true;
          if (message.state === 'error') waiter?.reject(new Error(message.error || 'worker playback failed'));
        }
        if (waiter?.predicate(message)) {
          const pending = waiter;
          waiter = null;
          pending.resolve(message);
        }
      },
    },
    registerNodeModulesPath() {}, os: require('node:os'), vfsRoot: '/proc/resonance',
    media, audio: require('audio'), runtimeProcess: process,
    createPlaybackController: (source, options) => new SubsonicPlaybackController(media, source, options),
  });
  const positions = [];
  try {
    for (const target of [0, 120.125, 40.5, 90.25]) {
      const loaded = waitForMessage((message) => message.type === 'state' && message.state === 'loaded'
        && Math.abs(message.currentTime - target) < 0.001);
      if (target === 0) {
        send({ type: 'open', sessionId: 1, shouldPlay: false, startTime: 0,
          path: { streamSourceKind: 'subsonic', url: process.env.TRANSCODE_URL,
            extensionsUrl: process.env.EXTENSIONS_URL, duration: 180 },
          bufferPolicy: { readChunkBytes: 8192, maxSourceBufferBytes: 65536 },
        });
      } else {
        send({ type: 'seek', sessionId: 1, seconds: target });
      }
      const state = await loaded;
      positions.push(state.currentTime);
      assert.equal(state.duration, 180);
      assert.equal(state.decoderInfo.durationUs, 180000000);
      assert.equal(state.decoderInfo.seekable, false);
    }
    assert.equal(played, false, 'paused worker seeks must not start physical audio output');
  } finally {
    const closed = waitForMessage((message) => message.type === 'reply' && message.requestId === 9);
    send({ type: 'shutdown', requestId: 9 });
    await closed;
  }
  console.log(JSON.stringify({ positions, paused: !played, shutdownCompleted: true }));
})().catch(error => { console.error(error); process.exitCode = 1; });
