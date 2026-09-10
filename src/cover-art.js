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

import { execFile } from 'node:child_process';
import { pipeline } from 'node:stream/promises';

export async function resizeCoverArt(source, size, signal) {
  let ffmpeg;
  const output = new Promise((resolve, reject) => {
    ffmpeg = execFile('ffmpeg', [
      '-hide_banner', '-loglevel', 'error', '-nostdin',
      '-i', 'pipe:0',
      '-map', '0:v:0', '-frames:v', '1',
      '-vf', `crop=w='min(iw,ih)':h='min(iw,ih)':exact=1,scale=w='min(${size},iw)':h='min(${size},ih)',setsar=1`,
      '-threads', '1', '-c:v', 'png', '-f', 'image2pipe', 'pipe:1',
    ], {
      encoding: 'buffer',
      maxBuffer: 64 * 1024 * 1024,
      timeout: 30000,
      killSignal: 'SIGKILL',
      signal,
    }, (error, stdout) => {
      if (error) {
        reject(error);
      } else if (stdout.length === 0) {
        reject(new Error('FFmpeg returned no cover image'));
      } else {
        resolve(stdout);
      }
    });
  });

  try {
    const [image] = await Promise.all([
      output,
      pipeline(source, ffmpeg.stdin, { signal }).catch((error) => {
        // One frame is enough; FFmpeg may close stdin before an animated image ends.
        // The process result still determines whether decoding succeeded.
        if (error.code !== 'EPIPE') {
          throw error;
        }
      }),
    ]);
    return image;
  } finally {
    source.destroy();
    if (ffmpeg.exitCode === null && ffmpeg.signalCode === null) {
      ffmpeg.kill('SIGKILL');
    }
  }
}
