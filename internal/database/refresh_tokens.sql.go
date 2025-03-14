// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.28.0
// source: refresh_tokens.sql

package database

import (
	"context"

	"github.com/google/uuid"
)

const createRefreshToken = `-- name: CreateRefreshToken :one
INSERT INTO refresh_tokens(token, created_at, updated_at, user_id, expires_at, revoked_at) 
VALUES(
    $1,
    NOW(),
    NOW(),
    $2,
    NOW() + INTERVAL '60 days',
    NULL
)
RETURNING token, created_at, updated_at, user_id, expires_at, revoked_at
`

type CreateRefreshTokenParams struct {
	Token  string
	UserID uuid.UUID
}

func (q *Queries) CreateRefreshToken(ctx context.Context, arg CreateRefreshTokenParams) (RefreshToken, error) {
	row := q.db.QueryRowContext(ctx, createRefreshToken, arg.Token, arg.UserID)
	var i RefreshToken
	err := row.Scan(
		&i.Token,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.UserID,
		&i.ExpiresAt,
		&i.RevokedAt,
	)
	return i, err
}

const deleteToken = `-- name: DeleteToken :exec
DELETE FROM refresh_tokens
WHERE token = $1
`

func (q *Queries) DeleteToken(ctx context.Context, token string) error {
	_, err := q.db.ExecContext(ctx, deleteToken, token)
	return err
}

const getRefreshTokenByToken = `-- name: GetRefreshTokenByToken :one
SELECT token, created_at, updated_at, user_id, expires_at, revoked_at FROM refresh_tokens
WHERE token = $1
LIMIT 1
`

func (q *Queries) GetRefreshTokenByToken(ctx context.Context, token string) (RefreshToken, error) {
	row := q.db.QueryRowContext(ctx, getRefreshTokenByToken, token)
	var i RefreshToken
	err := row.Scan(
		&i.Token,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.UserID,
		&i.ExpiresAt,
		&i.RevokedAt,
	)
	return i, err
}

const getRefreshTokenByUserID = `-- name: GetRefreshTokenByUserID :one
SELECT token, created_at, updated_at, user_id, expires_at, revoked_at FROM refresh_tokens
WHERE user_id = $1
LIMIT 1
`

func (q *Queries) GetRefreshTokenByUserID(ctx context.Context, userID uuid.UUID) (RefreshToken, error) {
	row := q.db.QueryRowContext(ctx, getRefreshTokenByUserID, userID)
	var i RefreshToken
	err := row.Scan(
		&i.Token,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.UserID,
		&i.ExpiresAt,
		&i.RevokedAt,
	)
	return i, err
}

const reinstateToken = `-- name: ReinstateToken :one
UPDATE refresh_tokens
    SET revoked_at = NULL,
        updated_at = NOW()
    WHERE token = $1
RETURNING token, created_at, updated_at, user_id, expires_at, revoked_at
`

func (q *Queries) ReinstateToken(ctx context.Context, token string) (RefreshToken, error) {
	row := q.db.QueryRowContext(ctx, reinstateToken, token)
	var i RefreshToken
	err := row.Scan(
		&i.Token,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.UserID,
		&i.ExpiresAt,
		&i.RevokedAt,
	)
	return i, err
}

const revokeToken = `-- name: RevokeToken :one
UPDATE refresh_tokens
    SET revoked_at = NOW(),
        updated_at = NOW()
    WHERE token = $1
RETURNING token, created_at, updated_at, user_id, expires_at, revoked_at
`

func (q *Queries) RevokeToken(ctx context.Context, token string) (RefreshToken, error) {
	row := q.db.QueryRowContext(ctx, revokeToken, token)
	var i RefreshToken
	err := row.Scan(
		&i.Token,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.UserID,
		&i.ExpiresAt,
		&i.RevokedAt,
	)
	return i, err
}
