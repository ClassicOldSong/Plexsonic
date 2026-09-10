// Run with an installed Resonance runtime. A delayed counting sink exercises
// native decoder/backpressure/finalization without opening an audio device.
const { PlaybackController } = require('media');
const { Writable } = require('stream');

(async () => {
  let bytes = 0;
  let finalCompleted = false;
  let before;
  let resolveEnded;
  let rejectEnded;
  const ended = new Promise((resolve, reject) => {
    resolveEnded = resolve;
    rejectEnded = reject;
  });
  const controller = new PlaybackController({
    src: process.env.TRANSCODE_URL,
    // Keep the response larger than the source queue so EOF is exercised
    // while compressed input is paused, as with full-length songs.
    bufferPolicy: { readChunkBytes: 8192, maxSourceBufferBytes: 65536 },
  }, {
    video: { enabled: false },
    audio: { sink: { open(request) {
      const writable = new Writable({
        highWaterMark: 16384,
        write(chunk, encoding, callback) {
          bytes += chunk.length;
          setTimeout(callback, 2);
        },
        final(callback) {
          if (controller.state === 'ended') throw new Error('Playback ended before sink finalization');
          setTimeout(() => { finalCompleted = true; callback(); }, 100);
        },
      });
      controller.onAudioOpened({
        openId: request.openId,
        writable,
        control() {},
        status: {
          sampleFormat: request.format, sampleRate: request.rate, channels: request.channels,
          interleaved: true, latency: 200000, frameBytes: request.channels * 2,
          periodFrames: 960, periodBytes: 960 * request.channels * 2,
          bufferFrames: 9600, bufferBytes: 9600 * request.channels * 2,
        },
      });
    } } },
    onStateChange(state) {
      if (state === 'loaded') {
        const info = controller.getInfo().decoder;
        before = { provider: info.provider, durationUs: info.durationUs, seekable: info.seekable };
        controller.play();
      } else if (state === 'ended') {
        resolveEnded();
      } else if (state === 'error') {
        rejectEnded(new Error(controller.errorMessage()));
      }
    },
  });
  try {
    controller.load();
    await ended;
    console.log(JSON.stringify({ before, bytes, finalCompleted, currentTime: controller.currentTime }));
  } finally {
    controller.close();
  }
})().catch((error) => { console.error(error); process.exitCode = 1; });
