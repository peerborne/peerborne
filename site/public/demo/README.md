# Sync story assets

`SyncStory.astro` is the interactive landing component. Its six frames live in
`site/src/lib/sync-story.ts`; the GIF and SVG poster use that same story data.
All displayed traffic, timing, byte counts, and epoch transitions are simulated.
No cryptographic material or real user payloads are used.

From the repository root with Node.js 22.19.0, installed workspace dependencies,
and `ffmpeg` on PATH:

```sh
node site/scripts/generate-sync-assets.mjs --gif
```

This uses the Sharp renderer installed with Astro. It writes the README GIF,
static SVG poster, and 1200×630 social card in the shared 8-bit palette, with
square panels and vector pixel lettering. Omitting `--gif` regenerates the
poster and social card without requiring ffmpeg. The GIF plays once; the live
component provides pause, replay, next-step, and step-selection controls and
starts on a static final frame when reduced motion is preferred.

`yarn workspace @peerborne/site sync:check` verifies that the committed SVG
assets match the generator without rewriting files or requiring ffmpeg. The
site build runs this check. PNG and GIF rendering uses host fonts and is kept
out of the byte-for-byte SVG check.

The storyboard is: synced → A edits → B disconnects → both edit → reconnect →
converge. Concurrent list additions both survive; one scalar value is selected
in the scripted result. An epoch change is sample overlay text, not a consequence
of reconnecting. This is not a networking or security acceptance test.

Use `sync-preview.svg` when an animated asset is unsuitable. The runtime diagram
and its Mermaid source live in `site/public/diagrams/`.
