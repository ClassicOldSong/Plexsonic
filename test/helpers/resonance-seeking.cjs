// Exercise the real player session and native decoder with a headless PCM sink.
const assert = require('node:assert/strict');
const { pathToFileURL } = require('node:url');
const { Writable } = require('node:stream');
const media = require('media');

(async () => {
  const { SubsonicPlaybackController } = await import(pathToFileURL(process.env.RESONANCE_PLAYER_MODULE).href);
  const outputs = [];
  // Only the audio destination is substituted; HTTP, decoding, cancellation,
  // controller seeks and the app's restart/timeline policy all remain real.
  function CountingPlaybackController(source, options, reference = false) {
    const output = { bytes: 0, finalCompleted: false, chunks: [] };
    outputs.push(output);
    const native = new media.PlaybackController(source, {
      ...options,
      audio: { sink: { open(request) {
        assert.equal(request.rate, 44100);
        const writable = new Writable({
          highWaterMark: 16384,
          write(chunk, encoding, callback) {
            output.bytes += chunk.length;
            if (cached) output.chunks.push(Buffer.from(chunk));
            if (reference) callback();
            else setTimeout(callback, 2);
          },
          final(callback) {
            assert.notEqual(native.state, 'ended');
            setTimeout(() => { output.finalCompleted = true; callback(); }, 20);
          },
        });
        native.onAudioOpened({
          openId: request.openId, writable, control() {},
          status: {
            sampleFormat: request.format, sampleRate: request.rate, channels: request.channels,
            interleaved: true, latency: 200000, frameBytes: request.channels * 2,
            periodFrames: 960, periodBytes: 960 * request.channels * 2,
            bufferFrames: 9600, bufferBytes: 9600 * request.channels * 2,
          },
        });
      } } },
    });
    return native;
  }

  const cached = process.env.SEEK_MODE === 'cached';
  let phase = 0;
  const positions = [];
  let resolveEnded;
  let rejectEnded;
  const ended = new Promise((resolve, reject) => { resolveEnded = resolve; rejectEnded = reject; });
  const session = new SubsonicPlaybackController({
    PlaybackController: CountingPlaybackController, ManagedAudioSink: media.ManagedAudioSink,
  }, {
    streamSourceKind: 'subsonic', url: process.env.TRANSCODE_URL,
    extensionsUrl: process.env.EXTENSIONS_URL, duration: 180,
  }, {
    video: { enabled: false },
    bufferPolicy: { readChunkBytes: 8192, maxSourceBufferBytes: 65536 },
    onStateChange(state) {
      console.error(JSON.stringify({ at: Date.now(), mode: process.env.SEEK_MODE, phase, state, position: session.getCurrentTime() }));
      try {
        if (state === 'error') throw session.getError();
        if (state === 'ended') { resolveEnded(); return; }
        if (state !== 'loaded') return;
        assert.equal(session.getDuration(), 180, 'suffix/padding must not replace full duration');
        positions.push(session.getCurrentTime());
        if (phase === 0) {
          assert.equal(session.getDecoderInfo().seekable, cached);
          phase = 1;
          session.seek(120.1254);
        } else if (phase === 1) {
          assert.ok(Math.abs(session.getCurrentTime() - 120.125) < 0.05);
          phase = 2;
          session.seek(40.5);
        } else if (phase === 2) {
          assert.ok(Math.abs(session.getCurrentTime() - 40.5) < 0.05);
          // Cached native seeks can notify synchronously at submission. The
          // first target is not superseded until the second call is issued.
          phase = -1;
          session.seek(150);
          phase = 3;
          session.seek(90.25);
        } else if (phase === 3) {
          assert.ok(Math.abs(session.getCurrentTime() - 90.25) < 0.05, 'latest absolute seek must win');
          assert.equal(outputs.reduce((sum, output) => sum + output.bytes, 0), 0, 'paused seeks must not emit PCM');
          phase = 4;
          session.play();
        }
      } catch (error) { rejectEnded(error); }
    },
  });
  process.once('beforeExit', () => {
    if (phase !== 4 || session.state !== 'closed') {
      console.error(`Seek sequence did not finish: phase=${phase}, state=${session.state}`);
      process.exitCode = 1;
    }
  });
  try {
    session.load();
    await ended;
    const output = outputs[outputs.length - 1];
    const expectedBytes = (180 - 90.25) * 44100 * 2 * 2;
    assert.equal(output.finalCompleted, true);
    const generations = outputs.length;
    if (cached) {
      assert.equal(generations, 1, 'cached seeks must reuse the native controller');
      // mpg123 uses fuzzy seeking for cached MP3s without a Xing index. Its
      // decoded start can include extra frames, independently reproduced with
      // plain libmpg123. Validate the complete contiguous suffix through EOF
      // against an unseeked native decode, rather than a fresh-encode size bound.
      let baseline;
      try {
        await new Promise((resolve, reject) => {
          baseline = CountingPlaybackController(process.env.TRANSCODE_URL, {
            video: { enabled: false },
            bufferPolicy: { readChunkBytes: 8192, maxSourceBufferBytes: 65536 },
            onStateChange(state) {
              console.error(JSON.stringify({ at: Date.now(), mode: 'cached-reference', state }));
              if (state === 'loaded') baseline.play();
              if (state === 'ended') resolve();
              if (state === 'error') reject(baseline.getError());
            },
          }, true);
          baseline.load();
        });
        const fullPcm = Buffer.concat(outputs.at(-1).chunks);
        const seekPcm = Buffer.concat(output.chunks);
        assert.ok(seekPcm.length >= expectedBytes && seekPcm.length < fullPcm.length);
        const suffix = fullPcm.subarray(fullPcm.length - seekPcm.length);
        for (let i = 0; i < seekPcm.length; i += 2) {
          // Independent mpg123 decoder histories differ by at most one S16
          // quantization unit; missing/repeated noise samples fail this check.
          if (Math.abs(seekPcm.readInt16LE(i) - suffix.readInt16LE(i)) > 1) {
            assert.fail(`cached PCM discontinuity at byte ${i}`);
          }
        }
      } finally {
        baseline?.close();
      }
    } else {
      assert.ok(output.bytes >= expectedBytes && output.bytes < expectedBytes + 2304 * 4,
        `${process.env.SEEK_MODE} decoded ${output.bytes} bytes, expected ${expectedBytes} plus at most 2304 padded samples`);
    }
    console.log(JSON.stringify({ positions, bytes: output.bytes, generations, finalCompleted: output.finalCompleted }));
  } finally {
    session.close();
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
