package login

import (
	"database/sql"
	"fmt"
	"log"
)

type RepoImpl struct {
	db *sql.DB
}

func NewRepository(db *sql.DB) RepoImpl {
	return RepoImpl{db: db}
}

func (r *RepoImpl) CreateTables() error {
	_, err := r.db.Exec(`CREATE TABLE IF NOT EXISTS jwt_private_keys (` +
		`id INTEGER PRIMARY KEY AUTOINCREMENT,` +
		`key_name TEXT not null,` +
		`private_key TEXT not null` +
		`);`)
	if err != nil {
		log.Printf("error creating jwt_private_keys table : %#v", err)
		return err
	}
	_, err = r.db.Exec(`CREATE TABLE IF NOT EXISTS clients (` +
		`id INTEGER PRIMARY KEY AUTOINCREMENT,` +
		`client_id TEXT not null,` +
		`client_secret TEXT not null,` +
		`key_name TEXT not null` +
		`);`)
	if err != nil {
		log.Printf("error creating clients table : %#v", err)
		return err
	}
	_, err = r.db.Exec(`CREATE TABLE IF NOT EXISTS audit (` +
		`id INTEGER PRIMARY KEY AUTOINCREMENT,` +
		`client_id TEXT not null,` +
		`access_token TEXT,` +
		`token_type TEXT,` +
		`expires_in INTEGER` +
		`);`)
	if err != nil {
		log.Printf("error creating audit table : %#v", err)
	}
	return err
}

func (r *RepoImpl) InsertAudit(clientID, accessToken, tokenType string, expiresIn int64) error {
	_, err := r.db.Exec(`INSERT INTO audit `+
		`(client_id, access_token, token_type, expires_in) `+
		`VALUES (?, ?, ?, ?);`,
		clientID,
		accessToken,
		tokenType,
		expiresIn,
	)
	return err
}

func (r *RepoImpl) InsertClient(clientID string, clientSecret []byte, keyName string) error {
	// checking key exists
	var count int
	err := r.db.QueryRow(`SELECT COUNT(*) FROM jwt_private_keys WHERE key_name = ?`, keyName).Scan(&count)
	if err != nil {
		return err
	}
	if count == 0 {
		return fmt.Errorf("key named %q doesn't exists", keyName)
	}
	// create record
	_, err = r.db.Exec(`INSERT INTO clients (client_id, client_secret, key_name) VALUES (?, ?, ?)`, clientID, clientSecret, keyName)
	return err
}

func (r *RepoImpl) GetClientSecretAndPrivateKeyByClientID(clientID string) (string, []byte, error) {
	var hashedSecret string
	var privateKey []byte
	err := r.db.QueryRow(`SELECT clients.client_secret AS client_secret, `+
		` jwt_private_keys.private_key AS private_key `+
		`FROM clients `+
		`INNER JOIN jwt_private_keys `+
		`ON clients.key_name = jwt_private_keys.key_name `+
		`WHERE client_id = ?`, clientID).
		Scan(&hashedSecret, &privateKey)
	if err != nil {
		return hashedSecret, privateKey, err
	}
	return hashedSecret, privateKey, nil
}

func (r *RepoImpl) SavePrivateKey(keyName string, keyData []byte) error {
	// checking a key with the same name already exists and replace it
	var count int
	err := r.db.QueryRow(`SELECT COUNT(*) FROM jwt_private_keys WHERE key_name = ?`, keyName).Scan(&count)
	if err != nil {
		return err
	}
	if count == 0 {
		_, err := r.db.Exec("INSERT INTO jwt_private_keys (key_name, private_key) VALUES (?, ?)", keyName, keyData)
		if err != nil {
			return err
		}
		return nil
	}

	// performing update, a key with the same name exists
	_, err = r.db.Exec("UPDATE jwt_private_keys SET private_key = ? WHERE key_name = ?", keyName, keyData)
	if err != nil {
		return err
	}

	return nil
}

func (r *RepoImpl) GetSigningKeyFromAuditedToken(tokenString string) ([]byte, error) {
	row := r.db.QueryRow(
		`SELECT jwt_private_keys.private_key `+
			`FROM audit `+
			`INNER JOIN clients ON audit.client_id = clients.client_id `+
			`INNER JOIN jwt_private_keys ON clients.key_name = jwt_private_keys.key_name `+
			`WHERE audit.access_token =  ?`,
		tokenString,
	)

	var privateKeyPEM []byte
	err := row.Scan(&privateKeyPEM)
	if err != nil {
		return nil, err
	}
	return privateKeyPEM, nil
}

func (r *RepoImpl) ListAllSigningKeys() ([]string, [][]byte, error) {
	rows, err := r.db.Query(`SELECT key_name, private_key FROM jwt_private_keys`)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()

	keyNames := make([]string, 0)
	privateKeys := make([][]byte, 0)
	for rows.Next() {

		var keyName string
		var privateKey []byte

		err := rows.Scan(&keyName, &privateKey)
		if err != nil {
			return nil, nil, err
		}

		keyNames = append(keyNames, keyName)
		privateKeys = append(privateKeys, privateKey)
	}

	if err := rows.Err(); err != nil {
		return nil, nil, err
	}

	return keyNames, privateKeys, nil
}
