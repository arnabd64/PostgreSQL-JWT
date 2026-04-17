ARG POSTGRES_TAG=16
FROM postgres:${POSTGRES_TAG}

# Initialize the database with the pgjwt functions on first container start.
COPY pgjwt.sql /docker-entrypoint-initdb.d/01-pgjwt.sql

HEALTHCHECK \
    --interval=90s \ 
    --timeout=5s \
    --start-period=15s \
    --retries=3 \
	CMD pg_isready -U postgres
