# PostgreSQL JWT

Simple PostgreSQL functions for generating and verifying JWT tokens directly inside your database.

This repository is meant to be easy to reuse: if you want JWT token generation and verification in your own PostgreSQL setup, you can copy the SQL from `pgjwt.sql` and run it in your database.

## What This Script Does

The SQL script creates functions that let you:

- generate signed JWT tokens
- verify JWT signatures and expiration
- issue both access and refresh tokens
- issue a new access token from a valid refresh token

Included functions:

- `base64_url_encoder(input bytea)`
- `base64_url_decoder(input text)`
- `sign(data text)`
- `generate_token(header jsonb, payload jsonb)`
- `issue_tokens(sub uuid, tenant uuid, role text, permissions text[])`
- `issue_access_token(refresh_token text)`
- `verify_token(token text)`

## Requirements

- PostgreSQL
- `pgcrypto` extension enabled
- a JWT secret stored in PostgreSQL as `app.jwt_secret`

`pgjwt.sql` already creates the `pgcrypto` extension if it is not installed:

```sql
CREATE EXTENSION IF NOT EXISTS pgcrypto;
```

## Before Running The Main Script

This project reads the secret from:

```sql
current_setting('app.jwt_secret')
```

That means you should set `app.jwt_secret` before using the JWT functions.

You can do that in one of these ways.

### Option 1: Set It For The Current Session

Useful for local testing:

```sql
SET app.jwt_secret = 'replace-with-a-strong-random-secret';
```

### Option 2: Set It For A Database

Useful when you want the setting to persist for all future connections to one database:

```sql
ALTER DATABASE your_database_name
SET app.jwt_secret = 'replace-with-a-strong-random-secret';
```

Reconnect after running the command so the new setting is available in your session.

### Option 3: Set It For A Role

Useful if a specific database role should always use the same JWT secret:

```sql
ALTER ROLE your_role_name
SET app.jwt_secret = 'replace-with-a-strong-random-secret';
```

Reconnect after running the command so the new setting is available in your session.

## Installation

1. Set `app.jwt_secret` using one of the methods above.
2. Open your PostgreSQL client.
3. Run the contents of `pgjwt.sql`.

Example with `psql`:

```bash
psql -d your_database_name -f pgjwt.sql
```

## Usage Examples

### Issue Access And Refresh Tokens

```sql
SELECT issue_tokens(
    '11111111-1111-1111-1111-111111111111'::uuid,
    '22222222-2222-2222-2222-222222222222'::uuid,
    'authenticated',
    ARRAY['read:profile', 'write:profile']
);
```

Returns JSON like:

```json
{
  "access_token": "...",
  "refresh_token": "...",
  "token_type": "Bearer"
}
```

### Verify A Token

```sql
SELECT verify_token('your.jwt.token');
```

If the token is valid, the decoded payload is returned as `jsonb`.

### Generate A New Access Token From A Refresh Token

```sql
SELECT issue_access_token('your.refresh.token');
```

## Token Behavior

- access token expiry: 30 minutes
- refresh token expiry: 7 days
- signing algorithm: `HS256`
- token type claims used by this script: `ACCESS` and `REFRESH`

## Notes

- `verify_token` checks token format, signature, and expiration.
- `issue_access_token` only accepts tokens with `"type": "REFRESH"`.
- If the secret is missing, token signing and verification will fail.
- Keep your JWT secret private and use a strong random value in production.

## Reuse In Your Own Database

If you only need the functionality, you can simply:

1. copy `pgjwt.sql`
2. set `app.jwt_secret`
3. run the script in your database

That is enough to start issuing and verifying JWTs from PostgreSQL.
