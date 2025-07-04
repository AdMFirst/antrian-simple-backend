package main
import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"
	"os"

	"github.com/joho/godotenv"
	"github.com/golang-jwt/jwt/v5"
	"github.com/redis/go-redis/v9"
)


var err = godotenv.Load()

// State version for long polling
var stateVersion int64
var stateCache []byte

var jwtKey = []byte(os.Getenv("JWT_KEY")) // Replace this with a secure key in production

// Redis client
var redisClient *redis.Client
var ctx = context.Background()

// Roles
const (
	RoleAdmin   = "admin"
	RoleCounter = "counter"
)

// Counter model
type Counter struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Count    int    `json:"count"`
}

// JWT claims
type Claims struct {
	Username string `json:"username"`
	Role     string `json:"role"`
	jwt.RegisteredClaims
}

// Initialize Redis client
func initRedis() {
    redisURL := os.Getenv("MY_REDIS_URL")
    if redisURL == "" {
        log.Fatal("MY_REDIS_URL must be set in .env")
    }

    opts, err := redis.ParseURL(redisURL)
    if err != nil {
        log.Fatalf("Failed to parse MY_REDIS_URL: %v", err)
    }

    redisClient = redis.NewClient(opts)

    if _, err := redisClient.Ping(ctx).Result(); err != nil {
        log.Fatalf("Failed to connect to Redis: %v", err)
    }

    adminKey := "counter:admin"
    exists, err := redisClient.Exists(ctx, adminKey).Result()
    if err != nil {
        log.Fatalf("Failed to check admin existence: %v", err)
    }
    if exists == 0 {
        adminPassword := os.Getenv("ADMIN_PASSWORD")
        if adminPassword == "" {
            log.Fatal("ADMIN_PASSWORD must be set in .env")
        }
        admin := Counter{Username: "admin", Password: adminPassword}
        adminJSON, err := json.Marshal(admin)
        if err != nil {
            log.Fatalf("Failed to marshal admin: %v", err)
        }
        if err := redisClient.Set(ctx, adminKey, adminJSON, 0).Err(); err != nil {
            log.Fatalf("Failed to set admin: %v", err)
        }
    }

	updateState()
}

// ===== CORS Middleware =====
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Set CORS headers
		w.Header().Set("Access-Control-Allow-Origin", os.Getenv("NEXT_FRONT_END_URL"))
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		w.Header().Set("Access-Control-Allow-Credentials", "true")

		// Handle preflight (OPTIONS) requests
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		// Call the next handler
		next.ServeHTTP(w, r)
	})
}

// ===== JWT Middleware =====
func authMiddleware(next http.HandlerFunc, requiredRole string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("auth_token")
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		tokenStr := cookie.Value
		claims := &Claims{}
		token, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})

		if err != nil || !token.Valid || claims.Role != requiredRole {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Add user info to headers for later use
		r.Header.Set("X-User", claims.Username)
		r.Header.Set("X-Role", claims.Role)

		next(w, r)
	}
}

// ===== Handlers =====
func loginHandler(w http.ResponseWriter, r *http.Request) {
    var creds struct {
        Username string `json:"username"`
        Password string `json:"password"`
    }

    if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
        log.Printf("Failed to decode login request: %v", err)
        http.Error(w, "Invalid request format", http.StatusBadRequest)
        return
    }

    if creds.Username == "" || creds.Password == "" {
        log.Printf("Empty username or password in login request")
        http.Error(w, "Username and password are required", http.StatusBadRequest)
        return
    }

    if redisClient == nil {
        log.Println("Redis client is not initialized")
        http.Error(w, "Server error: database not initialized", http.StatusInternalServerError)
        return
    }

    userJSON, err := redisClient.Get(ctx, fmt.Sprintf("counter:%s", creds.Username)).Result()
    if err == redis.Nil {
        log.Printf("User %s not found in Redis", creds.Username)
        http.Error(w, "Unauthorized: invalid username or password", http.StatusUnauthorized)
        return
    } else if err != nil {
        log.Printf("Redis error fetching user %s: %v", creds.Username, err)
        http.Error(w, "Server error", http.StatusInternalServerError)
        return
    }

    var user Counter
    if err := json.Unmarshal([]byte(userJSON), &user); err != nil {
        log.Printf("Error unmarshaling user %s: %v", creds.Username, err)
        http.Error(w, "Server error", http.StatusInternalServerError)
        return
    }

    if user.Password != creds.Password {
        log.Printf("Password mismatch for user %s", creds.Username)
        http.Error(w, "Unauthorized: invalid username or password", http.StatusUnauthorized)
        return
    }

    role := RoleCounter
    if creds.Username == "admin" {
        role = RoleAdmin
    }

    exp := time.Now().Add(24 * time.Hour)
    claims := &Claims{
        Username: creds.Username,
        Role:     role,
        RegisteredClaims: jwt.RegisteredClaims{
            ExpiresAt: jwt.NewNumericDate(exp),
        },
    }
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    signed, err := token.SignedString(jwtKey)
    if err != nil {
        log.Printf("Error signing JWT for user %s: %v", creds.Username, err)
        http.Error(w, "Server error", http.StatusInternalServerError)
        return
    }

    http.SetCookie(w, &http.Cookie{
        Name:     "auth_token",
        Value:    signed,
        Path:     "/",
        HttpOnly: true,
        SameSite: http.SameSiteLaxMode,
    })
	http.SetCookie(w, &http.Cookie{
        Name:     "auth_token",
        Value:    signed,
        Path:     "/",
        HttpOnly: true,
        SameSite: http.SameSiteNoneMode,
		Secure: true,
    })

    json.NewEncoder(w).Encode(map[string]string{"message": "login success", "role": claims.Role})
}

func createCounter(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		http.Error(w, "Invalid JSON format", http.StatusBadRequest)
		return
	}

	if input.Username == "" || input.Password == "" {
		http.Error(w, "Username and password are required", http.StatusBadRequest)
		return
	}

	// Check if counter exists
	key := fmt.Sprintf("counter:%s", input.Username)
	exists, _ := redisClient.Exists(ctx, key).Result()
	if exists > 0 {
		http.Error(w, "Counter already exists", http.StatusBadRequest)
		return
	}

	// Store new counter
	newCounter := Counter{Username: input.Username, Password: input.Password}
	counterJSON, _ := json.Marshal(newCounter)
	if err := redisClient.Set(ctx, key, counterJSON, 0).Err(); err != nil {
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	updateState()
	json.NewEncoder(w).Encode(map[string]string{"message": "Counter created"})
}

func deleteCounter(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")
	if username == "" || username == "admin" {
		http.Error(w, "Invalid username", http.StatusBadRequest)
		return
	}

	key := fmt.Sprintf("counter:%s", username)
	if _, err := redisClient.Del(ctx, key).Result(); err != nil {
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	updateState()
	json.NewEncoder(w).Encode(map[string]string{"message": "Counter deleted"})
}

func updateCounter(w http.ResponseWriter, r *http.Request) {
	var input struct {
		OldUsername string `json:"old_username"`
		NewUsername string `json:"new_username"`
		Password    string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		http.Error(w, "Invalid JSON format", http.StatusBadRequest)
		return
	}

	if input.OldUsername == "" || input.NewUsername == "" || input.Password == "" {
		http.Error(w, "Old username, new username, and password are required", http.StatusBadRequest)
		return
	}

	if input.OldUsername == "admin" {
		http.Error(w, "Cannot modify admin account", http.StatusForbidden)
		return
	}

	oldKey := fmt.Sprintf("counter:%s", input.OldUsername)
	newKey := fmt.Sprintf("counter:%s", input.NewUsername)

	// Fetch existing counter
	userJSON, err := redisClient.Get(ctx, oldKey).Result()
	if err == redis.Nil {
		http.Error(w, "Counter not found", http.StatusNotFound)
		return
	} else if err != nil {
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	var counter Counter
	if err := json.Unmarshal([]byte(userJSON), &counter); err != nil {
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	// Check for new username conflict
	if input.NewUsername != input.OldUsername {
		exists, _ := redisClient.Exists(ctx, newKey).Result()
		if exists > 0 {
			http.Error(w, "New username already exists", http.StatusBadRequest)
			return
		}
	}

	// Update counter
	updatedCounter := Counter{
		Username: input.NewUsername,
		Password: input.Password,
		Count:    counter.Count,
	}
	updatedJSON, _ := json.Marshal(updatedCounter)

	// Use a transaction to ensure atomicity
	pipe := redisClient.TxPipeline()
	if input.NewUsername != input.OldUsername {
		pipe.Del(ctx, oldKey)
	}
	pipe.Set(ctx, newKey, updatedJSON, 0)
	if _, err := pipe.Exec(ctx); err != nil {
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	updateState()
	json.NewEncoder(w).Encode(map[string]string{"message": "Counter updated"})
}

func listCounters(w http.ResponseWriter, r *http.Request) {
	// Get all keys matching "counter:*"
	keys, err := redisClient.Keys(ctx, "counter:*").Result()
	if err != nil {
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	counters := make(map[string]*Counter)
	for _, key := range keys {
		userJSON, err := redisClient.Get(ctx, key).Result()
		if err != nil {
			continue
		}
		var counter Counter
		if err := json.Unmarshal([]byte(userJSON), &counter); err != nil {
			continue
		}
		username := counter.Username
		counters[username] = &counter
	}

	json.NewEncoder(w).Encode(counters)
}

func incrementCounter(w http.ResponseWriter, r *http.Request) {
	user := r.Header.Get("X-User")
	key := fmt.Sprintf("counter:%s", user)

	userJSON, err := redisClient.Get(ctx, key).Result()
	if err == redis.Nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	} else if err != nil {
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	var counter Counter
	if err := json.Unmarshal([]byte(userJSON), &counter); err != nil {
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	var input struct {
		Count int `json:"count"`
	}

	if err := json.NewDecoder(r.Body).Decode(&input); err != nil || input.Count < 0 {
		http.Error(w, "Invalid count input", http.StatusBadRequest)
		return
	}

	counter.Count = input.Count
	updatedJSON, _ := json.Marshal(counter)
	if err := redisClient.Set(ctx, key, updatedJSON, 0).Err(); err != nil {
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	updateState()
	json.NewEncoder(w).Encode(map[string]int{"count": counter.Count})
}


// ===== Long Polling Handler =====
func updateState() {
    log.Println("updateState: Starting state update")
    stateVersion = time.Now().UnixNano()
    keys, err := redisClient.Keys(ctx, "counter:*").Result()
    if err != nil {
        log.Printf("updateState: Error fetching keys from Redis: %v", err)
    }
    log.Printf("updateState: Retrieved keys: %v", keys)
    counters := make(map[string]*Counter)
    for _, key := range keys {
        userJSON, err := redisClient.Get(ctx, key).Result()
        if err != nil {
            log.Printf("updateState: Error fetching key %s: %v", key, err)
            continue
        }
        var counter Counter
        if err := json.Unmarshal([]byte(userJSON), &counter); err != nil {
            log.Printf("updateState: Error unmarshaling JSON for key %s: %v", key, err)
            continue
        }
        counters[counter.Username] = &counter
    }
    state, err := json.Marshal(counters)
    if err != nil {
        log.Printf("updateState: Error marshaling counters to JSON: %v", err)
    }
    stateCache = state
    log.Printf("updateState: Updated stateCache with %d counters", len(counters))
}

func pollHandler(w http.ResponseWriter, r *http.Request) {
    versionQuery := r.URL.Query().Get("version")
    log.Printf("pollHandler: Received request with version: %s", versionQuery)
    lastVersion, err := time.Parse(time.RFC3339Nano, versionQuery)
    if err != nil {
        log.Printf("pollHandler: Error parsing version '%s': %v, defaulting to zero time", versionQuery, err)
        lastVersion = time.Time{}
    }
    timeout := time.After(30 * time.Second)

    for {
        select {
        case <-timeout:
            log.Println("pollHandler: Timeout reached")
            w.Header().Set("Content-Type", "application/json")
            var counters map[string]*Counter
            log.Printf("pollHandler: stateCache size: %d bytes", len(stateCache))
            if len(stateCache) > 0 {
                if err := json.Unmarshal(stateCache, &counters); err != nil {
                    log.Printf("pollHandler: Error unmarshaling stateCache: %v", err)
                    http.Error(w, "Server error", http.StatusInternalServerError)
                    return
                }
            } else {
                counters = make(map[string]*Counter)
                log.Println("pollHandler: stateCache is empty, returning empty counters")
            }
            log.Printf("pollHandler: Sending response with %d counters", len(counters))
            json.NewEncoder(w).Encode(map[string]interface{}{
                "version": time.Unix(0, stateVersion).Format(time.RFC3339Nano),
                "state":   counters,
            })
            return
        default:
            currentTime := time.Unix(0, stateVersion)
            if lastVersion.Before(currentTime) {
                log.Printf("pollHandler: State changed, lastVersion=%v, currentTime=%v", lastVersion, currentTime)
                w.Header().Set("Content-Type", "application/json")
                var counters map[string]*Counter
                log.Printf("pollHandler: stateCache size: %d bytes", len(stateCache))
                if len(stateCache) > 0 {
                    if err := json.Unmarshal(stateCache, &counters); err != nil {
                        log.Printf("pollHandler: Error unmarshaling stateCache: %v", err)
                        http.Error(w, "Server error", http.StatusInternalServerError)
                        return
                    }
                } else {
                    counters = make(map[string]*Counter)
                    log.Println("pollHandler: stateCache is empty, returning empty counters")
                }
                log.Printf("pollHandler: Sending response with %d counters", len(counters))
                json.NewEncoder(w).Encode(map[string]interface{}{
                    "version": currentTime.Format(time.RFC3339Nano),
                    "state":   counters,
                })
                return
            }
            time.Sleep(100 * time.Millisecond)
        }
    }
}


// ===== MAIN =====
func main() {
	
	initRedis()
	mux := http.NewServeMux()

	// Public
	mux.HandleFunc("/api/login", loginHandler)
	mux.HandleFunc("/api/poll", pollHandler)

	// Admin
	mux.HandleFunc("/api/admin/create", authMiddleware(createCounter, RoleAdmin))
	mux.HandleFunc("/api/admin/delete", authMiddleware(deleteCounter, RoleAdmin))
	mux.HandleFunc("/api/admin/list", authMiddleware(listCounters, RoleAdmin))
	mux.HandleFunc("/api/admin/update", authMiddleware(updateCounter, RoleAdmin))

	// Counter
	mux.HandleFunc("/api/counter/increment", authMiddleware(incrementCounter, RoleCounter))


	fmt.Println("Server running on http://localhost:4000")
	log.Fatal(http.ListenAndServe(":4000", corsMiddleware(mux)))
}
