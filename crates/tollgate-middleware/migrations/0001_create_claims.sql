-- The claims ledger: one row per ACCEPTED payment claim, owed until settled.
--
-- Every column is the verbatim material a settlement worker needs to redeem the
-- EIP-3009 authorization on-chain, so nothing here may be lossy: the signed
-- fields are stored exactly as they were signed.
--
-- Deliberately NOT `IF NOT EXISTS`: sqlx's `_sqlx_migrations` table already
-- guarantees this runs at most once per database, so the clause could only ever
-- mask a PRE-EXISTING, foreign `claims` table — which would boot green and then
-- fail every accepted payment AFTER its nonce was burned. Failing the migration
-- puts that failure at startup, where it belongs.
CREATE TABLE claims (
    payer        TEXT          NOT NULL,
    nonce        TEXT          NOT NULL,
    payee        TEXT          NOT NULL,
    signature    TEXT          NOT NULL,
    value        TEXT          NOT NULL,
    valid_after  TEXT          NOT NULL,
    -- uint256 seconds: a valid authorization can name a validBefore that
    -- overflows BIGINT, and this column is ordered on, so it must be numeric.
    valid_before NUMERIC(78,0) NOT NULL,
    asset        TEXT          NOT NULL,
    network      TEXT          NOT NULL,
    accepted_at  TIMESTAMPTZ   NOT NULL DEFAULT now(),
    -- NULL = owed. This nullable timestamp IS the whole status field; no enum.
    settled_at   TIMESTAMPTZ,
    -- The canonical replay identity (both parts lowercased by the writer), which
    -- makes a duplicate INSERT a no-op instead of a double-spend.
    PRIMARY KEY (payer, nonce)
);
