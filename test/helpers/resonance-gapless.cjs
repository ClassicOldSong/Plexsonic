// Production session/native HTTP/decoder; only the hardware destination is replaced.
const assert = require('node:assert/strict');
const { pathToFileURL } = require('node:url');
const { Writable } = require('node:stream');
const media = require('media');

(async () => {
  const { SubsonicPlaybackController } = await import(pathToFileURL(process.env.RESONANCE_PLAYER_MODULE).href);
  let bytes = 0, opens = 0, finals = 0, prepared = false;
  const changes = [];
  let resolveEnded, rejectEnded;
  const ended = new Promise((resolve, reject) => { resolveEnded = resolve; rejectEnded = reject; });
  const source = url => ({ streamSourceKind: 'subsonic', url,
    extensionsUrl: process.env.EXTENSIONS_URL, duration: 60 });
  function PlaybackController(nativeSource, options) {
    const native = new media.PlaybackController(nativeSource, {
      ...options,
      audio: { sink: { open(request) {
        opens++;
        assert.equal(request.rate, 44100);
        assert.equal(request.channels, 2);
        const writable = new Writable({
          highWaterMark: 4096,
          write(chunk, encoding, callback) {
            bytes += chunk.length;
            const firstWrite = !prepared;
            if (!prepared) {
              prepared = true;
              // Begin B only after A has emitted PCM, while A's upstream is held.
              setImmediate(() => {
                session.prepareNext(source(process.env.SUCCESSOR_URL)).then(() => {
                  console.log('GAPLESS_PREPARED');
                }, rejectEnded);
              });
            }
            // A real paused/buffered consumer may retain both HTTP sources past
            // the native 30-second idle deadline. Do not shorten that deadline.
            setTimeout(callback, firstWrite ? Number(process.env.GAPLESS_HOLD_MS) || 2 : 2);
          },
          final(callback) {
            assert.notEqual(session.state, 'ended');
            setTimeout(() => { finals++; callback(); }, 20);
          },
        });
        native.onAudioOpened({ openId: request.openId, writable, control() {}, status: {
          sampleFormat: request.format, sampleRate: request.rate, channels: request.channels,
          interleaved: true, latency: 200000, frameBytes: request.channels * 2,
          periodFrames: 960, periodBytes: 960 * request.channels * 2,
          bufferFrames: 9600, bufferBytes: 9600 * request.channels * 2,
        } });
      } } },
    });
    return native;
  }
  const session = new SubsonicPlaybackController({ PlaybackController, ManagedAudioSink: media.ManagedAudioSink },
    source(process.env.TRANSCODE_URL), {
      video: { enabled: false },
      bufferPolicy: { readChunkBytes: 8192, maxSourceBufferBytes: 65536 },
      onStateChange(state) {
        console.error(JSON.stringify({ at: Date.now(), state, bytes, time: session.getCurrentTime() }));
        if (state === 'loaded') session.play();
        if (state === 'error') rejectEnded(session.getError());
        if (state === 'ended') resolveEnded();
      },
      onSourceChange(event) { changes.push(event.reason); },
    });
  try {
    session.load();
    await ended;
    assert.equal(opens, 1);
    assert.equal(finals, 1);
    assert.deepEqual(changes, ['gapless']);
    assert.ok(bytes >= 120 * 44100 * 4 && bytes < 120 * 44100 * 4 + 2 * 2304 * 4,
      `both complete MP3 tracks must drain: ${bytes}`);
    console.log(JSON.stringify({ bytes, opens, finals, changes }));
  } finally { session.close(); }
})().catch(error => { console.error(error); process.exitCode = 1; });
