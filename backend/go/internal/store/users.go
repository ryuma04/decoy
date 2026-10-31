package store

import (
	"context"
	"time"
)

type User struct {
	UserID       string
	Email        string
	PasswordHash string
	Role         string
	CreatedAt    time.Time
}

// UpsertUser creates the user or resets its password hash and role.
func (s *Store) UpsertUser(ctx context.Context, email, passwordHash, role string) error {
	_, err := s.Pool.Exec(ctx, `INSERT INTO users (email, password_hash, role) VALUES (lower($1), $2, $3)
		ON CONFLICT (email) DO UPDATE SET password_hash = EXCLUDED.password_hash, role = EXCLUDED.role`,
		email, passwordHash, role)
	return err
}

func (s *Store) UserByEmail(ctx context.Context, email string) (User, error) {
	var u User
	err := s.Pool.QueryRow(ctx, `SELECT user_id, email, password_hash, role, created_at FROM users WHERE email = lower($1)`,
		email).Scan(&u.UserID, &u.Email, &u.PasswordHash, &u.Role, &u.CreatedAt)
	return u, notFound(err)
}

func (s *Store) UserByID(ctx context.Context, id string) (User, error) {
	var u User
	err := s.Pool.QueryRow(ctx, `SELECT user_id, email, password_hash, role, created_at FROM users WHERE user_id::text = $1`,
		id).Scan(&u.UserID, &u.Email, &u.PasswordHash, &u.Role, &u.CreatedAt)
	return u, notFound(err)
}
