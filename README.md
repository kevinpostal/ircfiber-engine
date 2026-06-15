# IRC Fiber

A modern IRC client built with a **D (LDC)** backend and **Svelte 5** frontend, styled after IRCCloud.

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | D (LDC2) via [hunt-framework](https://github.com/huntlabs/hunt-framework) |
| Frontend | Svelte 5 + TypeScript |
| Styling | SCSS (split into partials) |
| CSS Icons | Font Awesome |
| Monospace | Hack font |
| Build (FE) | Vite |

## Quick Start

```bash
# Build and run the D backend
make

# In another terminal, build the frontend
cd frontend
npm install
npm run build

# Or run the dev server
npm run dev
```

Open `http://localhost:8080` (or the port configured in the backend).

## Project Structure

```
├── source/          D backend source
├── views/           Diet template views
├── frontend/
│   ├── src/
│   │   ├── components/  Svelte components
│   │   ├── lib/         Utility modules
│   │   ├── stores/      Svelte stores
│   │   └── styles/      SCSS partials
│   │       ├── base/
│   │       ├── components/
│   │       ├── layout/
│   │       └── themes/
│   └── package.json
├── public/
│   └── dist/        Built frontend output
└── Makefile
```

## Development

```bash
# Watch mode for frontend
cd frontend && npm run dev
```

## License

Private.
