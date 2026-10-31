# Diagram layout sources

These source SVGs preserve the hand-authored layouts and technical descriptions
of the diagrams that predate the shared generator. They are inputs, not served
assets. Edit the content or geometry here, then run:

```sh
yarn workspace @peerborne/site diagrams:generate
```

`figure-theme.mjs` applies the same 8-bit palette, pixel headings, square shapes,
monospace labels, and hard shadows to these layouts and the programmatic
diagrams. It fits labels to their containers after the font change. The generator
writes the site assets and its `--check` mode detects stale output.

The runtime layout writes `site/public/diagrams/runtime.svg`; the remaining
layouts write `site/src/assets/diagrams/`. Mermaid source is kept separately.
