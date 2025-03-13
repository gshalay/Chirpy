-- name: CreateRefreshToken :one
INSERT INTO refresh_tokens(token, created_at, updated_at, user_id, expires_at, revoked_at) 
VALUES(
    $1,
    NOW(),
    NOW(),
    $2,
    NOW() + INTERVAL '60 days',
    NULL
)
RETURNING *;

INSERT INTO chirps(id, created_at, updated_at, body, user_id)
VALUES(
    gen_random_uuid(), NOW(), NOW(), $1, $2
)
RETURNING *;

-- name: GetRefreshTokenByUserID :one
SELECT * FROM refresh_tokens
WHERE user_id = $1
LIMIT 1;

-- name: GetRefreshTokenByToken :one
SELECT * FROM refresh_tokens
WHERE token = $1
LIMIT 1;


-- name: RevokeToken :one
UPDATE refresh_tokens
    SET revoked_at = NOW(),
        updated_at = NOW()
    WHERE token = $1
RETURNING *;

-- name: ReinstateToken :one
UPDATE refresh_tokens
    SET revoked_at = NULL,
        updated_at = NOW()
    WHERE token = $1
RETURNING *;

-- name: DeleteToken :exec
DELETE FROM refresh_tokens
WHERE token = $1;
    