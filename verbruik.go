package session_to_jwt

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// Meting van het verbruik per gebruiker (waterworks#923).
//
// Om een rate limit per gebruiker op een meting te kunnen baseren telt de proxy
// hoeveel verzoeken één gebruiker per venster doet. Aan het eind van elk venster
// gaat het aantal van elke gebruiker die in dat venster actief was als één
// waarneming in een histogram. Het histogram heeft geen label per gebruiker: de
// uitkomst is de verdeling ("p99 van de verzoeken per gebruiker per minuut"),
// niet wie hoeveel deed.
//
// Geteld worden alleen verzoeken waar de proxy een JWT op zet (cookie- en
// bearer-pad). Websocket-upgrades en verzoeken zonder sessie tellen niet mee.
// De telling is per proces: met meerdere replica's ziet elke pod zijn eigen deel.

const (
	// korteVenster is de tik van de meting; het lange venster is een veelvoud.
	korteVenster      = 10 * time.Second
	tikkenPerLang     = 6
	labelKort         = "10s"
	labelLang         = "60s"
	hasuraUserIDClaim = "x-hasura-user-id"
)

// verbruikBuckets: fijn rond de waarden waar een limiet zou komen te liggen.
var verbruikBuckets = []float64{1, 2, 5, 10, 20, 35, 50, 75, 100, 150, 200, 300, 500, 1000, 2000}

// Verbruik telt verzoeken per gebruiker in het lopende korte en lange venster.
type Verbruik struct {
	mu     sync.Mutex
	kort   map[string]int
	lang   map[string]int
	tikken int
	hist   *prometheus.HistogramVec
}

// NewVerbruik maakt een teller met een eigen histogram (nog niet geregistreerd).
func NewVerbruik() *Verbruik {
	return &Verbruik{
		kort: make(map[string]int),
		lang: make(map[string]int),
		hist: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "session_to_jwt_verzoeken_per_gebruiker",
			Help:    "Aantal verzoeken met JWT van één gebruiker binnen één venster; één waarneming per actieve gebruiker per venster.",
			Buckets: verbruikBuckets,
		}, []string{"venster"}),
	}
}

// Tel telt één verzoek voor de gebruiker van deze JWT. Een token waar geen
// gebruiker uit te lezen is, telt niet mee.
func (v *Verbruik) Tel(jwt []byte) {
	id := gebruikerUitJWT(jwt)
	if id == "" {
		return
	}
	v.mu.Lock()
	v.kort[id]++
	v.lang[id]++
	v.mu.Unlock()
}

// Tik sluit het korte venster af, en elke tikkenPerLang-de keer ook het lange.
func (v *Verbruik) Tik() {
	v.mu.Lock()
	kort := v.kort
	v.kort = make(map[string]int)
	v.tikken++
	var lang map[string]int
	if v.tikken%tikkenPerLang == 0 {
		lang = v.lang
		v.lang = make(map[string]int)
	}
	v.mu.Unlock()

	for _, n := range kort {
		v.hist.WithLabelValues(labelKort).Observe(float64(n))
	}
	for _, n := range lang {
		v.hist.WithLabelValues(labelLang).Observe(float64(n))
	}
}

// Registreer hangt het histogram aan een registry. Caddy maakt bij elke
// config-load een nieuwe registry en roept Provision per handler aan; dubbel
// registreren is daarom geen fout.
func (v *Verbruik) Registreer(reg prometheus.Registerer) error {
	if reg == nil {
		return nil
	}
	var al prometheus.AlreadyRegisteredError
	if err := reg.Register(v.hist); err != nil && !errors.As(err, &al) {
		return err
	}
	return nil
}

func (v *Verbruik) loop() {
	t := time.NewTicker(korteVenster)
	defer t.Stop()
	for range t.C {
		v.Tik()
	}
}

// gebruikerUitJWT leest het gebruikers-id uit de payload van een JWT, zonder
// de handtekening te controleren: het token komt van het eigen token-endpoint
// en het id dient alleen als sleutel voor de telling. Eerst `sub`, anders de
// Hasura-claim `x-hasura-user-id`.
func gebruikerUitJWT(jwt []byte) string {
	eerste := bytes.IndexByte(jwt, '.')
	if eerste < 0 {
		return ""
	}
	rest := jwt[eerste+1:]
	tweede := bytes.IndexByte(rest, '.')
	if tweede < 0 {
		return ""
	}
	payload := make([]byte, base64.RawURLEncoding.DecodedLen(tweede))
	n, err := base64.RawURLEncoding.Decode(payload, rest[:tweede])
	if err != nil {
		return ""
	}
	var claims struct {
		Sub    any            `json:"sub"`
		Hasura map[string]any `json:"https://hasura.io/jwt/claims"`
	}
	if err := json.Unmarshal(payload[:n], &claims); err != nil {
		return ""
	}
	if id := claimTekst(claims.Sub); id != "" {
		return id
	}
	return claimTekst(claims.Hasura[hasuraUserIDClaim])
}

// claimTekst maakt van een claim (string of getal) een sleutel; leeg als hij ontbreekt.
func claimTekst(c any) string {
	switch w := c.(type) {
	case nil:
		return ""
	case string:
		return w
	case float64:
		return fmt.Sprintf("%.0f", w)
	default:
		return fmt.Sprint(w)
	}
}

// sharedVerbruik is één proces-brede teller, gedeeld door alle handlers.
var (
	sharedVerbruik     *Verbruik
	sharedVerbruikOnce sync.Once
)

// SharedVerbruik geeft de proces-brede teller (lazy, incl. de tik-goroutine).
func SharedVerbruik() *Verbruik {
	sharedVerbruikOnce.Do(func() {
		sharedVerbruik = NewVerbruik()
		go sharedVerbruik.loop()
	})
	return sharedVerbruik
}
