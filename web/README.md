# Lockkeeper web UI

Stage **U0** of ADR 0006: a real frontend (Vite, React, TypeScript, Tailwind, shadcn-style components)
running on **mocked data only**. Every screen shows a permanent "demo data" banner. Nothing here talks
to a database yet; the Go server (`lockkeeper serve`) arrives in stage U1.

```sh
make web-install   # npm ci, exact versions from package-lock.json, no lifecycle scripts
make web-dev       # http://127.0.0.1:5173
make web-test      # typecheck + unit/a11y tests (includes measured colour contrast)
make web-build     # production build into web/dist
make build-ui      # build the UI, embed it, and build the single lockkeeper binary; then: ./lockkeeper serve
make web-audit     # npm audit for production dependencies
```

- Design source of truth: `../design-system/lockkeeper/MASTER.md` (read its "Lockkeeper decisions" block first).
- All colours are semantic tokens in `src/index.css`; `src/design/contrast.test.ts` measures every pair.
- UI languages: Indonesian and English, one JSON file per namespace in `src/i18n/{en,id}/`; a test keeps them in sync.
- Data goes through `src/api/client.ts` (`LockkeeperApi`). Stage U2 swaps the mock for HTTP behind the same interface.
- Dependencies are pinned exactly and were chosen from versions at least two weeks old (SPEC T22).
