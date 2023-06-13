package login

import (
	"database/sql"
	"log"
)

const (
	CREATE_CLIENTS_TABLE_SQL = `CREATE TABLE IF NOT EXISTS clients(` +
		`id INTEGER PRIMARY KEY AUTOINCREMENT,` +
		`client_id TEXT not null,` +
		`client_secret TEXT not null` +
		`);`
	CREATE_ISSUED_KEYS_TABLE_SQL = `CREATE TABLE IF NOT EXISTS issued_keys (` +
		`id INTEGER PRIMARY KEY AUTOINCREMENT,` +
		`client_id TEXT not null,` +
		`access_token TEXT,` +
		`token_type TEXT,` +
		`expires_in INTEGER` +
		`);`
	INSERT_ISSUED_KEY_SQL    = `INSERT INTO issued_keys (client_id, access_token, token_type, expires_in) VALUES (?, ?, ?, ?);`
	SELECT_CLIENT_SECRET_SQL = "SELECT client_secret FROM clients WHERE client_id = ?"
)

type RepoImpl struct {
	db *sql.DB
}

func NewRepository(db *sql.DB) RepoImpl {
	return RepoImpl{db: db}
}

func (r *RepoImpl) CreateTables() error {
	_, err := r.db.Exec(CREATE_ISSUED_KEYS_TABLE_SQL)
	if err != nil {
		log.Printf("error creating keys table : %#v", err)
		return err
	}
	_, err = r.db.Exec(CREATE_CLIENTS_TABLE_SQL)
	if err != nil {
		log.Printf("error creating clients table : %#v", err)
	}
	return err
}

func (r *RepoImpl) Insert(clientID, accessToken, tokenType string, expiresIn int64) error {
	_, err := r.db.Exec(INSERT_ISSUED_KEY_SQL, clientID, accessToken, tokenType, expiresIn)
	return err
}

func (r *RepoImpl) Verify(clientID string) (string, error) {
	var hashedSecret string
	err := r.db.QueryRow(SELECT_CLIENT_SECRET_SQL, clientID).Scan(&hashedSecret)
	if err != nil {
		return hashedSecret, err
	}
	return hashedSecret, nil
}
