package appConfig

type Client struct {
	Debug         bool   `json:"debug"`
	Identifier    string `json:"identifier"`
	ServerAddress string `json:"serverAddress"`
	SignatureKey  string `json:"signatureKey"`
	Proxy         Proxy  `json:"proxy"`
	ControlPath   string `json:"controlPath"`
	ControlMethod string `json:"controlMethod"`
}

type Proxy struct {
	Http HTTPConfig `json:"http"`
}

type HTTPConfig struct {
	Domain  string            `json:"domain"`
	Target  string            `json:"target"`
	Rewrite []HTTPRewriteRule `json:"rewrite"`
}

type HTTPRewriteRule struct {
	From string `json:"from"`
	To   string `json:"to"`
}
