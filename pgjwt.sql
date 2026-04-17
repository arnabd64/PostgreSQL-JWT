CREATE EXTENSION IF NOT EXISTS pgcrypto;


CREATE OR REPLACE FUNCTION base64_url_encoder (input BYTEA)
RETURNS TEXT
LANGUAGE SQL
IMMUTABLE STRICT
AS $$
/*
Encode raw bytes into JWT-safe Base64URL text.
Process:
1. Standard Base64 encode.
2. Replace '+' with '-' and '/' with '_'.
3. Strip line breaks and trailing '=' padding.
*/
SELECT
    rtrim(
        replace(
            replace(
                replace(
                    encode(input, 'base64'), 
                    E'\n', ''
                ),
                '+', '-'
            ),
            '/', '_'
        ),
        '='
    );
$$;


CREATE OR REPLACE FUNCTION base64_url_decoder (input TEXT)
RETURNS BYTEA
LANGUAGE SQL
IMMUTABLE STRICT
AS $$
/*
Decode JWT-style Base64URL text back to raw bytes.
Process:
1. Normalize URL-safe symbols used in this token format.
2. Right-pad with '=' so length is divisible by 4.
3. Decode into BYTEA.
*/
SELECT
    decode(
        rpad(
            replace(
                replace(
                    input,
                    '+', '-'
                ),
                '/', '_'
            ),
            4 * ((length(input) + 3) / 4),
            '='
        )
    );
$$;


CREATE OR REPLACE FUNCTION sign(data TEXT)
RETURNS BYTEA
LANGUAGE SQL
STABLE STRICT
AS $$
/*
Create an HMAC-SHA256 signature for the input payload
using the secret in `app.jwt_secret`.
*/
SELECT hmac(data, current_setting('app.jwt_secret'), 'sha256');
$$;



CREATE OR REPLACE FUNCTION generate_token (header JSONB, payload JSONB)
RETURNS TEXT
LANGUAGE SQL
IMMUTABLE STRICT
AS $$
/*
Build a signed JWT from a header and payload.
Token format: base64url(header).base64url(payload).base64url(signature)
*/
WITH
    -- 1) Base64URL encode header and payload JSON.
    encoded AS (
        SELECT
            base64_url_encoder(header::TEXT::BYTEA) AS h,
            base64_url_encoder(payload::TEXT::BYTEA) AS p
    ),

    -- 2) Prepare the string to be signed: "<header>.<payload>".
    signables AS (
        SELECT
            h || '.' || p AS data,
            h,
            p
        FROM
            encoded
    ),

    -- 3) Compute signature and encode it for transport.
    signature AS (
        SELECT
            base64_url_encoder(sign(data)) AS s
        FROM
            signables
    )


-- 4) Assemble final JWT string.
SELECT
    h || '.' || p || '.' || s
FROM
    signables, signature
$$;


CREATE OR REPLACE FUNCTION issue_tokens (
    sub UUID,
    tenant UUID,
    role TEXT,
    permissions TEXT[]
)
RETURNS JSONB
LANGUAGE plpgsql
AS $$
/*
Issue an access token and refresh token for a user identity.
Inputs:
- `sub`: user id
- `tenant`: tenant id
- `role`: current role
- `permissions`: granted permissions
Returns a JSON object with `{access_token, refresh_token, token_type}`.
*/
DECLARE
    iat BIGINT := EXTRACT(EPOCH FROM NOW())::BIGINT;
    access_payload JSONB;
    refresh_payload JSONB;
    header JSONB := jsonb_build_object('typ', 'JWT', 'alg', 'HS256');

BEGIN
    -- 1) Build claim sets with shared identity claims and per-token expiry.
    access_payload := jsonb_build_object(
        'sub', sub,
        'tenant', tenant,
        'role', role,
        'permissions', permissions,
        'iat', iat,
        'exp', iat + 1800, -- 30 mins
        'type', 'ACCESS'
    );

    refresh_payload := jsonb_build_object(
        'sub', sub,
        'tenant', tenant,
        'role', role,
        'permissions', permissions,
        'iat', iat,
        'exp', iat + 604800,
        'type', 'REFRESH'
    );

    -- 2) Sign and return both tokens.
    RETURN jsonb_build_object(
        'access_token', generate_token(header, access_payload),
        'refresh_token', generate_token(header, refresh_payload),
        'token_type', 'Bearer'
    );
END;
$$;


CREATE OR REPLACE FUNCTION issue_access_token (refresh_token TEXT)
RETURNS JSONB
LANGUAGE plpgsql
STABLE STRICT
AS $$
/*
Mint a new access token from a valid refresh token.
Returns `{access_token, refresh_token, token_type}`.
*/
DECLARE
    refresh_payload JSONB;
    access_payload JSONB;
    iat BIGINT := EXTRACT(EPOCH FROM NOW())::BIGINT;
    header JSONB := jsonb_build_object('typ', 'JWT', 'alg', 'HS256');
BEGIN
    -- 1) Validate signature/expiry and decode refresh claims.
    refresh_payload := verify_token(refresh_token);

    IF refresh_payload->>'type' <> 'REFRESH' THEN
        RAISE EXCEPTION 'Invalid token type. Expected REFRESH token';
    END IF;

    -- 2) Reuse identity claims, then replace time-bound access claims.
    access_payload := (refresh_payload - 'iat' - 'exp' - 'type')
        || jsonb_build_object(
            'iat', iat,
            'exp', iat + 1800, -- 30 mins
            'type', 'ACCESS'
        );

    RETURN jsonb_build_object(
        'access_token', generate_token(header, access_payload),
        'refresh_token', refresh_token,
        'token_type', 'Bearer'
    );
END;
$$;


CREATE OR REPLACE FUNCTION verify_token (token TEXT)
RETURNS JSONB
LANGUAGE plpgsql
STABLE STRICT
AS $$
/*
Validate a JWT and return its payload JSON.
Checks:
1. Format (`header.payload.signature`)
2. Signature integrity
3. Expiration (`exp`)
*/
DECLARE
    parts TEXT[];
    payload JSONB;
    calculated_signature TEXT;

BEGIN
    -- 1) Split JWT into 3 sections: header, payload, signature.
    parts := string_to_array(token, '.');

    IF array_length(parts, 1) <> 3 THEN
        RAISE EXCEPTION 'Invalid token format';
    END IF;


    -- 2) Recompute signature from header+payload and compare.
    calculated_signature := base64_url_encoder(sign(parts[1] || '.' || parts[2]));

    IF parts[3] <> calculated_signature THEN
        RAISE EXCEPTION 'Invalid Signature';
    END IF;

    -- 3) Decode payload JSON and enforce expiration.
    payload := convert_from(base64_url_decoder(parts[2]), 'UTF8')::JSONB;

    IF (payload->>'exp')::BIGINT < EXTRACT(EPOCH FROM NOW())::BIGINT THEN
        RAISE EXCEPTION 'Token has Expired';
    END IF;

    RETURN payload;
END;
$$;
