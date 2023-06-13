package login

type RepoMock struct {
	clientFound bool
}

func NewMock(clientFound bool) RepoMock {
	return RepoMock{clientFound: clientFound}
}

func (r *RepoMock) Verify(clientID, clientSecret string) (bool, error) {
	return r.clientFound, nil
}
