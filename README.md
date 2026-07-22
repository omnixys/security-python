# omnixys-security

Omnixys shared security package with JWT validation, auth middleware, and rate limiting.

## Installation

```bash
pip install omnixys-security
```

## Features

- JWT token validation
- Security middleware for FastAPI
- Rate limiting with configurable policies
- Request context management

## Usage

```python
from omnixys_security import JwtValidator, SecurityMiddleware, RateLimiter, RateLimitMiddleware
```

## License

GPL-3.0-or-later
