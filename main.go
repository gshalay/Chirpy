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
	"time"

	"github.com/google/uuid"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

const (
	MAX_CHIRP_LEN     = 140
	CENSOR            = "****"
	ERR_ENCODE_RESP   = "Error encoding response"
	ERR_DECODE_PARAMS = "Error decoding parameters"
	SECONDS_IN_HOUR   = 3600
)

type RequestError struct {
	Error string `json:"error"`
}

type ApiConfig struct {
	fileServerHits atomic.Int32
	dbQueries      *database.Queries
	secret         string
	polkaKey       string
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
	apiCfg.secret = os.Getenv("SECRET")
	apiCfg.polkaKey = os.Getenv("POLKA_KEY")

	mux := http.NewServeMux()
	mux.Handle("/app/", apiCfg.middlewareMetricsInc(http.StripPrefix("/app", http.FileServer(http.Dir(".")))))
	mux.HandleFunc("GET /api/healthz", handlerHealthz)
	mux.HandleFunc("GET /admin/metrics", apiCfg.handlerMetrics)
	mux.HandleFunc("POST /admin/reset", apiCfg.handlerReset)
	mux.HandleFunc("POST /api/chirps", apiCfg.handlerChirps)
	mux.HandleFunc("GET /api/chirps", apiCfg.handlerGetAllChirps)
	mux.HandleFunc("GET /api/chirps/{chirpID}", apiCfg.handlerGetChirpById)
	mux.HandleFunc("DELETE /api/chirps/{chirpID}", apiCfg.handlerDeleteChirpById)
	mux.HandleFunc("POST /api/login", apiCfg.handlerLogin)
	mux.HandleFunc("POST /api/users", apiCfg.handlerUsers)
	mux.HandleFunc("PUT /api/users", apiCfg.handlerUpdateUsersInfo)
	mux.HandleFunc("POST /api/refresh", apiCfg.handlerRefresh)
	mux.HandleFunc("POST /api/revoke", apiCfg.handlerRevoke)
	mux.HandleFunc("POST /api/polka/webhooks", apiCfg.handlerWebhooks)
	httpServer := http.Server{Handler: mux, Addr: ":8080"}

	err = httpServer.ListenAndServe()
	if err != nil {
		fmt.Printf("Couldn't start server: %v\n", err)
	}
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
		Body string `json:"body"`
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

		// Check Auth Token
		token, err := auth.GetBearerToken(req.Header)
		if err != nil {
			retVal := getRequestError("error: couldn't fetch auth token", "error encoding response")
			respWriter.WriteHeader(401)
			respWriter.Write(retVal)
			return
		}

		tokenUUID, err := auth.ValidateJWT(token, cfg.secret)

		if err != nil || tokenUUID == uuid.Nil {
			retVal := getRequestError(fmt.Sprintf("invalid auth token: %v", err), "authentication failed")
			respWriter.WriteHeader(401)
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

		createParams := database.CreateChirpParams{Body: params.Body, UserID: tokenUUID}
		createdChirp, err := cfg.dbQueries.CreateChirp(req.Context(), createParams)
		if err != nil {
			retVal := getRequestError("error: user id invalid", "Error encoding response.")
			respWriter.WriteHeader(400)
			respWriter.Write(retVal)
			return
		}

		success := RequestSuccess{Id: createdChirp.ID.String(), Body: createParams.Body, CreatedAt: createdChirp.CreatedAt.String(), UpdatedAt: createdChirp.UpdatedAt.String(), UserId: tokenUUID.String()}
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
		Email            string `json:"email"`
		Password         string `json:"password"`
		ExpiresInSeconds string `json:"expires_in_seconds"`
	}

	type RequestSuccess struct {
		Id          string `json:"id"`
		CreatedAt   string `json:"created_at"`
		UpdatedAt   string `json:"updated_at"`
		Email       string `json:"email"`
		IsChirpyRed bool   `json:"is_chirpy_red"`
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

		hashedPassword, err := auth.HashPassword(params.Password)
		if err != nil {
			retVal := getRequestError("error: couldn't create user by email.", "Error encoding parameters.")
			respWriter.WriteHeader(400)
			respWriter.Write(retVal)
			return
		}

		createdUser, err := cfg.dbQueries.CreateUser(req.Context(), database.CreateUserParams{Email: params.Email, HashedPassword: hashedPassword})
		if err != nil {
			retVal := getRequestError("error: couldn't create user by email.", "Error encoding parameters.")
			respWriter.WriteHeader(400)
			respWriter.Write(retVal)
			return
		}

		success := RequestSuccess{Id: createdUser.ID.String(), CreatedAt: createdUser.CreatedAt.String(), UpdatedAt: createdUser.UpdatedAt.String(), Email: createdUser.Email, IsChirpyRed: createdUser.IsChirpyRed}
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
		respWriter.WriteHeader(404)
		return
	}

	chirp := Chirp{Id: chirpById.ID.String(), Body: chirpById.Body, CreatedAt: chirpById.CreatedAt.String(), UpdatedAt: chirpById.UpdatedAt.String(), UserId: chirpById.UserID.String()}

	retVal, err := json.Marshal(chirp)
	if err != nil {
		log.Printf("Error encoding parameters: %s", err)
	}

	respWriter.WriteHeader(200)
	respWriter.Write(retVal)
}

func (cfg *ApiConfig) handlerDeleteChirpById(respWriter http.ResponseWriter, req *http.Request) {
	req.Header.Set("Content-Type", "application/json")
	idStr := req.PathValue("chirpID")

	id, err := uuid.Parse(idStr)
	if err != nil {
		log.Printf("Couldn't parse UUID: %s", err)
	}

	accessToken, err := auth.GetBearerToken(req.Header)
	if err != nil {
		retVal := getRequestError("error: couldn't get access token.", "Error encoding parameters.")
		respWriter.WriteHeader(401)
		respWriter.Write(retVal)
		return
	}

	tokenUUID, err := auth.ValidateJWT(accessToken, cfg.secret)
	if err != nil {
		retVal := getRequestError("error: access token invalid.", "Error encoding parameters.")
		respWriter.WriteHeader(403)
		respWriter.Write(retVal)
		return
	} else if tokenUUID == uuid.Nil {
		retVal := getRequestError("error: access token invalid.", "Error encoding parameters.")
		respWriter.WriteHeader(404)
		respWriter.Write(retVal)
		return
	}

	chirpById, err := cfg.dbQueries.GetChirpById(req.Context(), id)
	if err != nil {
		retVal := getRequestError(fmt.Sprintf("Error getting chirp with id %s: %s", id, err), "Error encoding parameters.")
		respWriter.WriteHeader(404)
		respWriter.Write(retVal)
		return
	}

	if tokenUUID != chirpById.UserID {
		retVal := getRequestError("error: mismatched user ids.", "Error encoding parameters.")
		respWriter.WriteHeader(403)
		respWriter.Write(retVal)
		return
	}

	err = cfg.dbQueries.DeleteChirpById(req.Context(), chirpById.ID)
	if err != nil {
		retVal := getRequestError("error: couldn't delete chiro", "Error encoding parameters.")
		respWriter.WriteHeader(404)
		respWriter.Write(retVal)
		return
	}
	respWriter.WriteHeader(204)
}

func (cfg *ApiConfig) handlerLogin(respWriter http.ResponseWriter, req *http.Request) {
	type RequestParameters struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	type RequestSuccess struct {
		Id           string `json:"id"`
		CreatedAt    string `json:"created_at"`
		UpdatedAt    string `json:"updated_at"`
		Email        string `json:"email"`
		Token        string `json:"token"`
		RefreshToken string `json:"refresh_token"`
		IsChirpyRed  bool   `json:"is_chirpy_red"`
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

		refreshToken, err := cfg.dbQueries.GetRefreshTokenByUserID(req.Context(), existingUser.ID)
		if err != nil {
			// No refresh token exists in db. Create one for them.
			token, err := auth.MakeRefreshToken()
			if err != nil {
				retVal := getRequestError("error: couldn't create refresh token.", "Error creating token.")
				respWriter.WriteHeader(401)
				respWriter.Write(retVal)
				return
			}

			refreshToken, err = cfg.dbQueries.CreateRefreshToken(req.Context(), database.CreateRefreshTokenParams{Token: token, UserID: existingUser.ID})
			if err != nil {
				retVal := getRequestError("error: couldn't create refresh token.", "Error encoding parameters.")
				respWriter.WriteHeader(401)
				respWriter.Write(retVal)
				return
			}
		} else if time.Now().After(refreshToken.ExpiresAt) {
			// Current refresh token is expired. Create a new one for them, but delete the old one first.
			err := cfg.dbQueries.DeleteToken(req.Context(), refreshToken.Token)
			if err != nil {
				retVal := getRequestError("error: couldn't create new token after old one expired.", "Error creating new token.")
				respWriter.WriteHeader(401)
				respWriter.Write(retVal)
				return
			}

			token, err := auth.MakeRefreshToken()
			if err != nil {
				retVal := getRequestError("error: couldn't create refresh token.", "Error creating token.")
				respWriter.WriteHeader(401)
				respWriter.Write(retVal)
				return
			}

			refreshToken, err = cfg.dbQueries.CreateRefreshToken(req.Context(), database.CreateRefreshTokenParams{Token: token, UserID: existingUser.ID})
			if err != nil {
				retVal := getRequestError("error: couldn't create refresh token.", "Error encoding parameters.")
				respWriter.WriteHeader(401)
				respWriter.Write(retVal)
				return
			}
		} else {
			// Refresh token exists, reinstate it by setting the revoked at field to null.
			_, err := cfg.dbQueries.ReinstateToken(req.Context(), refreshToken.Token)
			if err != nil {
				retVal := getRequestError("error: couldn't reinstate refresh token.", "token error.")
				respWriter.WriteHeader(401)
				respWriter.Write(retVal)
				return
			}
		}

		token, err := auth.MakeJWT(existingUser.ID, cfg.secret)
		if err != nil {
			retVal := getRequestError("error: couldn't create authentication token.", "Error creating token.")
			respWriter.WriteHeader(400)
			respWriter.Write(retVal)
			return
		}

		success := RequestSuccess{Id: existingUser.ID.String(), CreatedAt: existingUser.CreatedAt.String(), UpdatedAt: existingUser.UpdatedAt.String(), Email: existingUser.Email, Token: token, RefreshToken: refreshToken.Token, IsChirpyRed: existingUser.IsChirpyRed}
		retVal, err := json.Marshal(success)
		if err != nil {
			log.Printf("Error encoding parameters: %s", err)
		}

		respWriter.WriteHeader(200)
		respWriter.Write(retVal)
		return
	}
}

func (cfg *ApiConfig) handlerRefresh(respWriter http.ResponseWriter, req *http.Request) {
	type RequestSuccess struct {
		Token string `json:"token"`
	}

	req.Header.Set("Content-Type", "application/json")
	reqRefreshToken, err := auth.GetBearerToken(req.Header)

	fmt.Printf("ref token - %s\n", reqRefreshToken)

	if err != nil {
		log.Printf("error getting auth token: %v\n", err)
		respWriter.WriteHeader(401)
		return
	}

	resultRow, err := cfg.dbQueries.GetUserByRefreshToken(req.Context(), reqRefreshToken)
	if err != nil {
		log.Printf("invalid token: %v", err)
		respWriter.WriteHeader(401)
		return
	}

	fmt.Printf("expires - %s\n", resultRow.ExpiresAt)
	fmt.Printf("revoked - %v\n", resultRow.RevokedAt)

	if time.Now().After(resultRow.ExpiresAt) {
		log.Printf("refresh token expired.\n")
		respWriter.WriteHeader(401)
		return
	}

	refreshToken, err := cfg.dbQueries.GetRefreshTokenByToken(req.Context(), reqRefreshToken)
	if err != nil {
		log.Printf("invalid token: %v", err)
		respWriter.WriteHeader(401)
		return
	}

	if refreshToken.RevokedAt.Valid {
		log.Printf("error: token revoked\n")
		respWriter.WriteHeader(401)
		return
	}

	accessToken, err := auth.MakeJWT(resultRow.UserID, cfg.secret)
	if err != nil {
		log.Printf("error: %v\n", err)
		respWriter.WriteHeader(401)
		return
	}

	success := RequestSuccess{Token: accessToken}
	retVal, err := json.Marshal(success)
	if err != nil {
		log.Printf("Error encoding parameters: %s", err)
		respWriter.WriteHeader(401)
		return
	}

	respWriter.WriteHeader(200)
	respWriter.Write(retVal)
}

func (cfg *ApiConfig) handlerRevoke(respWriter http.ResponseWriter, req *http.Request) {
	req.Header.Set("Content-Type", "application/json")
	refreshToken, err := auth.GetBearerToken(req.Header)

	if err != nil {
		log.Printf("error getting auth token: %v\n", err)
		respWriter.WriteHeader(401)
		return
	}

	revoked, err := cfg.dbQueries.RevokeToken(req.Context(), refreshToken)
	if err != nil {
		log.Printf("error revoking token: %v\n", err)
		respWriter.WriteHeader(401)
		return
	}

	fmt.Printf("After revoke: %v\n", revoked.RevokedAt)

	respWriter.WriteHeader(204)
}

func (cfg *ApiConfig) handlerUpdateUsersInfo(respWriter http.ResponseWriter, req *http.Request) {
	type RequestParameters struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	type RequestSuccess struct {
		Id          string `json:"id"`
		CreatedAt   string `json:"created_at"`
		UpdatedAt   string `json:"updated_at"`
		Email       string `json:"email"`
		IsChirpyRed bool   `json:"is_chirpy_red"`
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
		accessToken, err := auth.GetBearerToken(req.Header)
		if err != nil {
			retVal := getRequestError("error: no access token", "Error encoding parameters.")
			respWriter.WriteHeader(401)
			respWriter.Write(retVal)
			return
		}

		jwtUserId, err := auth.ValidateJWT(accessToken, cfg.secret)
		if err != nil {
			retVal := getRequestError("error: access token not valid", "Error encoding parameters.")
			respWriter.WriteHeader(401)
			respWriter.Write(retVal)
			return
		}

		existingUser, err := cfg.dbQueries.GetUserById(req.Context(), jwtUserId)
		if err != nil {
			retVal := getRequestError("error: couldn't get user with id.", "Error encoding parameters.")
			respWriter.WriteHeader(401)
			respWriter.Write(retVal)
			return
		}

		if params.Password == "" {
			retVal := getRequestError("error: no password provided", "Error encoding parameters.")
			respWriter.WriteHeader(401)
			respWriter.Write(retVal)
			return
		}

		hashedPassword, err := auth.HashPassword(params.Password)
		if err != nil {
			retVal := getRequestError("error: couldn't create user by email.", "Error encoding parameters.")
			respWriter.WriteHeader(401)
			respWriter.Write(retVal)
			return
		}

		updatedUser, err := cfg.dbQueries.UpdateUsersEmailAndPassword(req.Context(), database.UpdateUsersEmailAndPasswordParams{ID: existingUser.ID, Email: params.Email, HashedPassword: hashedPassword})
		if err != nil {
			retVal := getRequestError("error: couldn't update user with info provided.", "Error encoding parameters.")
			respWriter.WriteHeader(401)
			respWriter.Write(retVal)
			return
		}

		success := RequestSuccess{Id: updatedUser.ID.String(), CreatedAt: updatedUser.CreatedAt.String(), UpdatedAt: updatedUser.UpdatedAt.String(), Email: updatedUser.Email, IsChirpyRed: updatedUser.IsChirpyRed}
		retVal, err := json.Marshal(success)
		if err != nil {
			log.Printf("Error encoding parameters: %s", err)
		}

		respWriter.WriteHeader(200)
		respWriter.Write(retVal)
		return
	}
}

func (cfg *ApiConfig) handlerWebhooks(respWriter http.ResponseWriter, req *http.Request) {
	type RequestDataParameter struct {
		UserID string `json:"user_id"`
	}

	type RequestParameters struct {
		Event string               `json:"event"`
		Data  RequestDataParameter `json:"data"`
	}

	req.Header.Set("Content-Type", "application/json")

	apiKey, err := auth.GetAPIKey(req.Header)
	if err != nil {
		log.Printf("error: no api key")
		respWriter.WriteHeader(401)
		return
	}

	log.Printf("a - %s\n", apiKey)
	log.Printf("p - %s\n", cfg.polkaKey)

	if apiKey != cfg.polkaKey {
		log.Printf("error: api key mismatch")
		respWriter.WriteHeader(401)
		return
	}

	decoder := json.NewDecoder(req.Body)
	params := RequestParameters{}
	err = decoder.Decode(&params)
	if err != nil {
		retVal := getRequestError(err.Error(), "Error encoding parameters.")
		respWriter.WriteHeader(500)
		respWriter.Write(retVal)
		return
	}

	// Only care about the user being upgraded, so return.
	if params.Event != "user.upgraded" {
		respWriter.WriteHeader(204)
		return
	}

	id, err := uuid.Parse(params.Data.UserID)
	if err != nil {
		log.Printf("Couldn't parse UUID: %s", err)
		respWriter.WriteHeader(404)
		return
	}

	_, err = cfg.dbQueries.UpgradeUserToChirpyRed(req.Context(), id)
	if err != nil {
		log.Printf("user with id not found: %v", err)
		respWriter.WriteHeader(404)
		return
	}

	// No errors returned early, so write the success header.
	respWriter.WriteHeader(204)
}
