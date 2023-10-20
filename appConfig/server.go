package appConfig

type Server struct {
	Debug          bool     `json:"debug"`
	SignatureKey   string   `json:"signatureKey"`
	Listen         string   `json:"listen"`
	AllowedHosts   []string `json:"allowedHosts"`
	AllowedClients []string `json:"allowedClients"`
	ControlPath    string   `json:"controlPath"`
	ControlMethod  string   `json:"controlMethod"`
}
