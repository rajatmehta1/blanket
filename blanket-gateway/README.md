# Blanket Gateway

REST API gateway for Blanket — an AI code governance platform.

## Setup

```bash
# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env with your Neon database URL

# Run the server
uvicorn app.main:app --reload --port 8001
```

## API

All endpoints (except health checks) require an `X-API-Key` header.

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | Health check |
| GET | `/health` | Health check |
| GET | `/api/v1/projects` | List projects |
| POST | `/api/v1/projects` | Create project |
| GET | `/api/v1/projects/{id}` | Get project |
| PATCH | `/api/v1/projects/{id}` | Update project |
| DELETE | `/api/v1/projects/{id}` | Delete project |
| GET | `/api/v1/policies` | List policies |
| POST | `/api/v1/policies` | Create policy |
| GET | `/api/v1/policies/{id}` | Get policy |
| PATCH | `/api/v1/policies/{id}` | Update policy |
| DELETE | `/api/v1/policies/{id}` | Delete policy |
| GET | `/api/v1/projects/{id}/policies` | List assignments |
| POST | `/api/v1/projects/{id}/policies` | Assign policy |
| PATCH | `/api/v1/projects/{id}/policies/{pid}` | Toggle assignment |
| DELETE | `/api/v1/projects/{id}/policies/{pid}` | Remove assignment |
| GET | `/api/v1/activity` | List enforcement logs |
| GET | `/api/v1/activity/{id}` | Get enforcement log |
| GET | `/api/v1/templates` | List policy templates |
| GET | `/api/v1/templates/{id}` | Get template |
| POST | `/api/v1/templates/{id}/instantiate` | Create policy from template |

Interactive docs available at `/docs` (Swagger UI) and `/redoc`.
