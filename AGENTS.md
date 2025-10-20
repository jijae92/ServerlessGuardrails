# Repository Guidelines

ServerlessGuardrails is still a lightweight scaffold, so these guidelines explain the preferred layout and workflows as the codebase grows. Treat them as the baseline for new contributions and propose adjustments in a pull request discussion when you see a better path.

## Project Structure & Module Organization
- Keep runtime code under `src/`; group Lambda handlers by domain (`src/compliance/handler.ts`) and share utilities through `src/lib/`.
- Store infrastructure definitions in `infra/` (AWS CDK or Serverless Framework). If you add infrastructure, include a README in that folder describing deployment parameters.
- Place tests in `tests/` using mirrored directories (`tests/compliance/handler.test.ts`) so reviewers can quickly find coverage.
- Put design docs, ADRs, and sample payloads in `docs/` or `assets/` so they do not drift into the runtime packages.

## Build, Test, and Development Commands
- `npm install` – install dependencies (run after cloning or when `package.json` changes).
- `npm run build` – transpile TypeScript to JavaScript. Failing builds should block deployment-focused PRs.
- `npm run deploy -- --stage <env>` – deploy through the Serverless Framework or CDK CLI wrapper; document required environment variables in `infra/README.md`.
- `npm test` – execute the Jest suite; prefer running with `--watch` when iterating locally.
- `npm run lint` – apply ESLint + Prettier rules; ensure the working tree is clean before pushing.

## Coding Style & Naming Conventions
- Prefer TypeScript with strict mode enabled; use 2-space indentation and single quotes.
- Export one primary handler per file, naming it `<Domain><Action>Handler` (for example, `ComplianceScanHandler`).
- Use camelCase for variables/functions, PascalCase for classes/types, and kebab-case for file names except AWS handler entry points.
- Run `npm run lint -- --fix` before committing; do not disable lint rules without linking to a ticket.

## Testing Guidelines
- Write unit tests in Jest; let filenames end with `.test.ts`.
- Target ≥80% branch coverage for new modules; add integration tests under `tests/integration/` when touching external APIs.
- Seed mocks under `tests/fixtures/` and clearly name them after the scenario (`baselinePayload.json`).

## Commit & Pull Request Guidelines
- Follow Conventional Commits (`feat:`, `fix:`, `chore:`) with concise, imperative subject lines.
- Reference issues in the PR description and note any configuration changes or secrets required.
- Include test evidence (`npm test`, `npm run lint`, deployment dry run) in the PR checklist.
- Request a review from at least one maintainer and wait for CI green before merging.

## Security & Configuration Tips
- Never commit AWS credentials or `.env` files; use parameter stores or Git-ignored templates (`.env.example`).
- Document IAM policy changes in the PR description and explain blast-radius restrictions.
- Rotate local API keys regularly and store them via the team-approved secrets manager.
