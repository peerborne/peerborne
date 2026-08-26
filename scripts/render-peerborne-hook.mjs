#!/usr/bin/env node

import { chromium } from '@playwright/test';
import {
  mkdirSync,
  mkdtempSync,
  rmSync,
  statSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { spawnSync } from 'node:child_process';

const scriptPath = fileURLToPath(import.meta.url);
const root = resolve(dirname(scriptPath), '..');
const sourcePath = resolve(root, 'scripts/peerborne-hook.html');
const outputPath = resolve(root, '.github/assets/peerborne-hook.gif');
const width = 960;
const height = 540;
const durationSeconds = 8;
const framesPerSecond = 10;
const frameCount = durationSeconds * framesPerSecond;
const maximumBytes = 3 * 1024 * 1024;

function run(command, args) {
  const result = spawnSync(command, args, { encoding: 'utf8' });
  if (result.status !== 0) {
    const failure = [
      `status ${result.status ?? 'unknown'}`,
      result.signal ? `signal ${result.signal}` : undefined,
      result.error?.message,
    ].filter(Boolean);
    const output = result.stderr || result.stdout;
    throw new Error(
      `${command} failed (${failure.join(', ')})${output ? `:\n${output}` : ''}`,
    );
  }
}

async function render() {
  mkdirSync(dirname(outputPath), { recursive: true });
  const framesDirectory = mkdtempSync(join(tmpdir(), 'peerborne-hook-'));

  try {
    const browser = await chromium.launch({ headless: true });
    try {
      const page = await browser.newPage({
        deviceScaleFactor: 1,
        viewport: { width, height },
      });
      await page.goto(pathToFileURL(sourcePath).href);
      await page.evaluate(async () => {
        await document.fonts.ready;
        const animations = document.getAnimations();
        for (const animation of animations) {
          animation.pause();
          animation.currentTime = 0;
        }
        window.__peerborneHookAnimations = animations;
      });

      for (let frame = 0; frame < frameCount; frame += 1) {
        const currentTime = (frame * 1000) / framesPerSecond;
        await page.evaluate((time) => {
          for (const animation of window.__peerborneHookAnimations) {
            animation.currentTime = time;
          }
        }, currentTime);
        await page.screenshot({
          animations: 'allow',
          path: join(framesDirectory, `frame-${String(frame).padStart(3, '0')}.png`),
        });
      }
    } finally {
      await browser.close();
    }

    run('ffmpeg', [
      '-y',
      '-hide_banner',
      '-loglevel',
      'error',
      '-framerate',
      String(framesPerSecond),
      '-i',
      join(framesDirectory, 'frame-%03d.png'),
      '-filter_complex',
      '[0:v]split[s0][s1];[s0]palettegen=max_colors=72:stats_mode=diff[p];[s1][p]paletteuse=dither=bayer:bayer_scale=4:diff_mode=rectangle',
      '-gifflags',
      '+transdiff',
      '-loop',
      '-1',
      outputPath,
    ]);

    const size = statSync(outputPath).size;
    if (size > maximumBytes) {
      throw new Error(
        `Generated GIF is ${size} bytes; expected no more than ${maximumBytes}`,
      );
    }
    console.log(
      `Generated ${outputPath} (${width}x${height}, ${durationSeconds}s, ${size} bytes)`,
    );
  } finally {
    rmSync(framesDirectory, { recursive: true, force: true });
  }
}

await render();
