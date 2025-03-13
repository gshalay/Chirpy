-- name: CreateUser :one
INSERT INTO users(id, created_at, updated_at, email, hashed_password)
VALUES(
    gen_random_uuid(), NOW(), NOW(), $1, $2
)
RETURNING *;

-- name: GetUserById :one
SELECT * FROM users 
WHERE id = $1
LIMIT 1;

-- name: GetUserByEmail :one
SELECT * FROM users 
WHERE email = $1
LIMIT 1;

-- name: UpdateUsersEmailAndPassword :one
UPDATE users
    SET email = $2,
        hashed_password = $3
    WHERE id = $1
RETURNING *;

-- name: DeleteAllUsers :exec
DELETE FROM users;

-- name: GetUserByRefreshToken :one
SELECT refresh_tokens.token, refresh_tokens.created_at, refresh_tokens.updated_at, refresh_tokens.user_id, refresh_tokens.expires_at, refresh_tokens.revoked_at, 
    users.id, users.created_at, users.updated_at, users.email, users.hashed_password 
    FROM users
INNER JOIN refresh_tokens ON
users.id = refresh_tokens.user_id
WHERE refresh_tokens.token = $1
LIMIT 1;

-- name: UpgradeUserToChirpyRed :one
UPDATE users
    SET is_chirpy_red = TRUE
    WHERE id = $1
RETURNING *;