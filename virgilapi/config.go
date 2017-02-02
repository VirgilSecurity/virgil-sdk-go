package virgilapi

type Config struct {
	Token          string
	Credentials    AppCredentials
	ClientParams   *ClientParams
	KeyStoragePath string
}
