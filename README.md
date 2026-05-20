# Prism

I was tired of code review bots that only look at diffs.

Prism is an AI-powered code review bot that receives GitHub PR webhooks, analyzes diffs using MiMo V2.5 Pro's 1M context window, and posts inline review comments. Unlike other tools, Prism reads the *entire file* for context, not just the changed lines.

## Features

- **Full-context review** — MiMo V2.5 Pro's 1M context window means Prism reads your whole file, not just the diff
- **Static analysis built-in** — Catches hardcoded secrets, SQL injection, command injection, and common bugs before the LLM even runs
- **Multiple review modes** — Full, security-focused, style-focused, or quick scans
- **Inline comments** — Posts comments exactly where the issue is, not as a wall of text
- **Smart filtering** — Ignores lock files, minified code, and respects `# prism: ignore` directives
- **Async everything** — Built on FastAPI + httpx for high throughput
- **Docker-ready** — One command to deploy

## Quick Start

### 1. Clone and configure

```bash
git clone https://github.com/Kynareth01/prism.git
cd prism
cp .env.example .env
# Edit .env with your GitHub token, webhook secret, and LLM API key
```

### 2. Run with Docker

```bash
docker compose up --build
```

### 3. Run locally

```bash
pip install -e ".[dev]"
python -m prism.app
```

### 4. Configure GitHub webhook

1. Go to your repo → Settings → Webhooks → Add webhook
2. Payload URL: `https://your-server.com/webhook`
3. Content type: `application/json`
4. Secret: Same as `GITHUB_WEBHOOK_SECRET` in your `.env`
5. Events: Pull requests

## Review Modes

Trigger different modes via PR labels or body directives:

| Mode | Label | Directive | What it does |
|------|-------|-----------|-------------|
| Full | `prism:full` | `/review full` | Complete review: bugs, security, style, performance |
| Security | `prism:security` | `/review security` | Focus on vulnerabilities and secrets |
| Style | `prism:style` | `/review style` | Code quality and readability |
| Quick | `prism:quick` | `/review quick` | Fast scan, only critical issues |

## Static Analysis Rules

Prism runs rule-based analysis on every diff, catching issues instantly:

- **SEC001-SEC006** — Hardcoded secrets, API keys, AWS keys, private keys, GitHub tokens
- **SEC010-SEC014** — SQL injection, command injection, eval/exec usage
- **STY001-STY006** — TODO comments, bare excepts, print statements, magic numbers
- **BUG001-BUG004** — Mutable defaults, None comparison, assert in production

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/webhook` | POST | GitHub webhook receiver |
| `/health` | GET | Health check with stats |
| `/review/{owner}/{repo}/{pr}` | POST | Manually trigger review |
| `/` | GET | API info |
| `/docs` | GET | Swagger documentation |

## Manual Review

Trigger a review manually via the API:

```bash
curl -X POST http://localhost:8080/review/Kynareth01/prism/42?mode=security
```

## Architecture

```
prism/
├── __init__.py          # Package metadata
├── config.py            # Environment-based configuration
├── github_client.py     # Async GitHub API client with retry
├── reviewer.py          # Core review engine + diff parser
├── analyzer.py          # Static analysis (secrets, injection, style)
├── models.py            # Pydantic models for all data structures
├── prompts.py           # LLM prompt templates per review mode
└── app.py               # FastAPI webhook server

agents/
├── base.py              # Abstract agent interface
├── code_reviewer.py     # LLM-powered code review agent
└── security_scanner.py  # Security-focused analysis agent
```

## Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Run with coverage
pytest --cov=prism --cov-report=html

# Lint
ruff check prism/ agents/ tests/

# Type check
mypy prism/ agents/
```

## License

MIT — see [LICENSE](LICENSE).
