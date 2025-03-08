package main

import (
	"chirpy/internal/auth"
	"chirpy/internal/database"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/google/uuid"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

const (
	MAX_CHIRP_LEN     = 140
	CENSOR            = "****"
	ERR_ENCODE_RESP   = "Error encoding response"
	ERR_DECODE_PARAMS = "Error decoding parameters"
)

type RequestError struct {
	Error string `json:"error"`
}

type ApiConfig struct {
	fileServerHits atomic.Int32
	dbQueries      *database.Queries
}

func (cfg *ApiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(respWriter http.ResponseWriter, req *http.Request) {
		cfg.fileServerHits.Add(1)
		next.ServeHTTP(respWriter, req)
	})
}

func getRequestError(message, logErr string) []byte {
	reqErr := RequestError{Error: message}
	retVal, err := json.Marshal(reqErr)
	if err != nil {
		log.Printf("%s: %s", logErr, err)
	}

	return retVal
}

func (cfg *ApiConfig) handlerReset(respWriter http.ResponseWriter, req *http.Request) {
	req.Header.Set("Content-Type", "text/plain; charset=utf-8")

	godotenv.Load()
	platform := os.Getenv("PLATFORM")

	if platform == "dev" {
		respWriter.WriteHeader(200)
		cfg.fileServerHits.Store(0)
		cfg.dbQueries.DeleteAllUsers(req.Context())
		log.Println("Deleted all users.")
		content := fmt.Sprintf("Hits: %v\n", cfg.fileServerHits.Load())

		_, err := respWriter.Write([]byte(content))
		if err != nil {
			fmt.Printf("%v\n", fmt.Errorf("%v", err))
		}
		return
	} else {
		respWriter.WriteHeader(403)
		return
	}
}

func (cfg *ApiConfig) handlerMetrics(respWriter http.ResponseWriter, req *http.Request) {
	fileContent, err := os.ReadFile("metrics_template.html")
	if err != nil {
		log.Fatal(err)
	}

	text := string(fileContent)
	hits := strconv.Itoa(int(cfg.fileServerHits.Load()))
	text = strings.ReplaceAll(text, "[hits]", string(hits))

	os.WriteFile("metrics.html", []byte(text), 0644)

	http.ServeFile(respWriter, req, "metrics.html")
}

func main() {
	godotenv.Load()
	dbURL := os.Getenv("DB_URL")
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		fmt.Printf("error: Couldn't connect to database: %s\n", err)
	}

	// Init app config and setup query boilerplate.
	apiCfg := ApiConfig{}
	apiCfg.fileServerHits.Store(0)
	apiCfg.dbQueries = database.New(db)

	mux := http.NewServeMux()
	mux.Handle("/app/", apiCfg.middlewareMetricsInc(http.StripPrefix("/app", http.FileServer(http.Dir(".")))))
	mux.HandleFunc("GET /api/healthz", handlerHealthz)
	mux.HandleFunc("GET /admin/metrics", apiCfg.handlerMetrics)
	mux.HandleFunc("POST /admin/reset", apiCfg.handlerReset)
	mux.HandleFunc("POST /api/chirps", apiCfg.handlerChirps)
	mux.HandleFunc("GET /api/chirps", apiCfg.handlerGetAllChirps)
	mux.HandleFunc("GET /api/chirps/{chirpID}", apiCfg.handlerGetChirpById)
	mux.HandleFunc("POST /api/login", apiCfg.handlerLogin)
	mux.HandleFunc("POST /api/users", apiCfg.handlerUsers)
	httpServer := http.Server{Handler: mux, Addr: ":8080"}

	httpServer.ListenAndServe()
}

func handlerHealthz(respWriter http.ResponseWriter, req *http.Request) {
	req.Header.Set("Content-Type", "text/plain; charset=utf-8")

	respWriter.WriteHeader(200)
	_, err := respWriter.Write([]byte("OK\n"))
	if err != nil {
		fmt.Printf("%v\n", fmt.Errorf("%v", err))
	}
}

func middlewareLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s", r.Method, r.URL.Path)
		next.ServeHTTP(w, r)
	})
}

func (cfg *ApiConfig) handlerChirps(respWriter http.ResponseWriter, req *http.Request) {
	type RequestParameters struct {
		Body   string `json:"body"`
		UserId string `json:"user_id"`
	}

	type RequestSuccess struct {
		Id        string `json:"id"`
		CreatedAt string `json:"created_at"`
		UpdatedAt string `json:"updated_at"`
		Body      string `json:"body"`
		UserId    string `json:"user_id"`
	}

	req.Header.Set("Content-Type", "application/json")

	decoder := json.NewDecoder(req.Body)
	params := RequestParameters{}
	err := decoder.Decode(&params)
	if err != nil {
		retVal := getRequestError(err.Error(), "Error decoding parameters.")
		respWriter.WriteHeader(500)
		respWriter.Write(retVal)
		return
	} else {
		if len(params.Body) > MAX_CHIRP_LEN {
			retVal := getRequestError("error: Chirp is too long", "Error encoding response.")
			respWriter.WriteHeader(400)
			respWriter.Write(retVal)
			return
		}

		words_to_censor := []string{"kerfuffle", "sharbert", "fornax"}
		pattern := `\\s+`
		re := regexp.MustCompile(pattern)
		params.Body = re.ReplaceAllString(params.Body, " ")
		body_words := strings.Split(strings.Trim(params.Body, " "), " ")

		cleaned_body := ""
		for i, word := range body_words {
			to_add := word

			if slices.Contains(words_to_censor, strings.ToLower(word)) {
				to_add = CENSOR
			}

			if i < len(body_words)-1 {
				to_add += " "
			}

			cleaned_body += to_add
		}

		uid, err := uuid.Parse(params.UserId)
		if err != nil {
			retVal := getRequestError("error: user id invalid", "Error encoding response.")
			respWriter.WriteHeader(400)
			respWriter.Write(retVal)
			return
		}

		createParams := database.CreateChirpParams{Body: params.Body, UserID: uid}
		createdChirp, err := cfg.dbQueries.CreateChirp(req.Context(), createParams)
		if err != nil {
			retVal := getRequestError("error: user id invalid", "Error encoding response.")
			respWriter.WriteHeader(400)
			respWriter.Write(retVal)
			return
		}

		success := RequestSuccess{Id: createdChirp.ID.String(), Body: createParams.Body, CreatedAt: createdChirp.CreatedAt.String(), UpdatedAt: createdChirp.UpdatedAt.String(), UserId: params.UserId}
		retVal, err := json.Marshal(success)
		if err != nil {
			log.Printf("Error encoding parameters: %s", err)
		}

		respWriter.WriteHeader(201)
		respWriter.Write(retVal)
		return
	}
}

func (cfg *ApiConfig) handlerUsers(respWriter http.ResponseWriter, req *http.Request) {
	type RequestParameters struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	type RequestSuccess struct {
		Id        string `json:"id"`
		CreatedAt string `json:"created_at"`
		UpdatedAt string `json:"updated_at"`
		Email     string `json:"email"`
	}

	req.Header.Set("Content-Type", "application/json")

	decoder := json.NewDecoder(req.Body)
	params := RequestParameters{}
	err := decoder.Decode(&params)
	if err != nil {
		retVal := getRequestError(err.Error(), "Error encoding parameters.")
		respWriter.WriteHeader(500)
		respWriter.Write(retVal)
		return
	} else {
		if params.Password == "" {
			retVal := getRequestError("error: no password provided", "Error encoding parameters.")
			respWriter.WriteHeader(500)
			respWriter.Write(retVal)
			return
		}

		hash, err := auth.HashPassword(params.Password)
		if err != nil {
			retVal := getRequestError("error: couldn't create user by email.", "Error encoding parameters.")
			respWriter.WriteHeader(400)
			respWriter.Write(retVal)
			return
		}

		createdUser, err := cfg.dbQueries.CreateUser(req.Context(), database.CreateUserParams{Email: params.Email, HashedPassword: hash})
		if err != nil {
			retVal := getRequestError("error: couldn't create user by email.", "Error encoding parameters.")
			respWriter.WriteHeader(400)
			respWriter.Write(retVal)
			return
		}

		success := RequestSuccess{Id: createdUser.ID.String(), CreatedAt: createdUser.CreatedAt.String(), UpdatedAt: createdUser.UpdatedAt.String(), Email: createdUser.Email}
		retVal, err := json.Marshal(success)
		if err != nil {
			log.Printf("Error encoding parameters: %s", err)
		}

		respWriter.WriteHeader(201)
		respWriter.Write(retVal)
		return
	}
}

func (cfg *ApiConfig) handlerGetAllChirps(respWriter http.ResponseWriter, req *http.Request) {
	type Chirp struct {
		Id        string `json:"id"`
		CreatedAt string `json:"created_at"`
		UpdatedAt string `json:"updated_at"`
		Body      string `json:"body"`
		UserId    string `json:"user_id"`
	}

	req.Header.Set("Content-Type", "application/json")

	chirps, err := cfg.dbQueries.GetAllChirps(req.Context())
	if err != nil {
		log.Printf("Error getting all chirps: %s", err)
	}

	var jsonSlice []Chirp

	for _, chirp := range chirps {
		currentChirp := Chirp{Id: chirp.ID.String(), CreatedAt: chirp.CreatedAt.String(), UpdatedAt: chirp.UpdatedAt.String(), Body: chirp.Body, UserId: chirp.UserID.String()}
		jsonSlice = append(jsonSlice, currentChirp)
	}

	retVal, err := json.Marshal(jsonSlice)
	if err != nil {
		log.Printf("Error encoding parameters: %s", err)
	}

	respWriter.WriteHeader(200)
	respWriter.Write(retVal)
}

func (cfg *ApiConfig) handlerGetChirpById(respWriter http.ResponseWriter, req *http.Request) {
	type Chirp struct {
		Id        string `json:"id"`
		CreatedAt string `json:"created_at"`
		UpdatedAt string `json:"updated_at"`
		Body      string `json:"body"`
		UserId    string `json:"user_id"`
	}

	req.Header.Set("Content-Type", "application/json")
	idStr := req.PathValue("chirpID")

	id, err := uuid.Parse(idStr)
	if err != nil {
		log.Printf("Couldn't parse UUID: %s", err)
	}

	chirpById, err := cfg.dbQueries.GetChirpById(req.Context(), id)
	if err != nil {
		log.Printf("Error getting chirp with id %s: %s", id, err)
	}

	chirp := Chirp{Id: chirpById.ID.String(), Body: chirpById.Body, CreatedAt: chirpById.CreatedAt.String(), UpdatedAt: chirpById.UpdatedAt.String(), UserId: chirpById.UserID.String()}

	retVal, err := json.Marshal(chirp)
	if err != nil {
		log.Printf("Error encoding parameters: %s", err)
	}

	respWriter.WriteHeader(200)
	respWriter.Write(retVal)
}

func (cfg *ApiConfig) handlerLogin(respWriter http.ResponseWriter, req *http.Request) {
	type RequestParameters struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	type RequestSuccess struct {
		Id        string `json:"id"`
		CreatedAt string `json:"created_at"`
		UpdatedAt string `json:"updated_at"`
		Email     string `json:"email"`
	}

	req.Header.Set("Content-Type", "application/json")

	decoder := json.NewDecoder(req.Body)
	params := RequestParameters{}
	err := decoder.Decode(&params)
	if err != nil {
		retVal := getRequestError(err.Error(), "Error encoding parameters.")
		respWriter.WriteHeader(500)
		respWriter.Write(retVal)
		return
	} else {
		if params.Password == "" {
			retVal := getRequestError("error: no password provided", "Error encoding parameters.")
			respWriter.WriteHeader(400)
			respWriter.Write(retVal)
			return
		}

		existingUser, err := cfg.dbQueries.GetUserByEmail(req.Context(), params.Email)
		if err != nil {
			retVal := getRequestError("error: incorrect email or password.", "Error encoding parameters.")
			respWriter.WriteHeader(401)
			respWriter.Write(retVal)
			return
		}

		err = auth.CheckPasswordHash(params.Password, existingUser.HashedPassword)
		if err != nil {
			retVal := getRequestError("error: incorrect email or password.", "Error encoding parameters.")
			respWriter.WriteHeader(401)
			respWriter.Write(retVal)
			return
		}

		if err != nil {
			retVal := getRequestError("error: couldn't create user by email.", "Error encoding parameters.")
			respWriter.WriteHeader(400)
			respWriter.Write(retVal)
			return
		}

		success := RequestSuccess{Id: existingUser.ID.String(), CreatedAt: existingUser.CreatedAt.String(), UpdatedAt: existingUser.UpdatedAt.String(), Email: existingUser.Email}
		retVal, err := json.Marshal(success)
		if err != nil {
			log.Printf("Error encoding parameters: %s", err)
		}

		respWriter.WriteHeader(200)
		respWriter.Write(retVal)
		return
	}
}
