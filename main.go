package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"
	"os"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/websocket"
)

const ORIGIN = os.Getenv("NEXT_FRONT_END_URL")
const JWT_KEY = os.Getenv("NEXT_JWT_KEY")


var jwtKey = []byte(JWT_KEY) 
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

// In-memory counter store
var counters = map[string]*Counter{
	"admin": {Username: "admin", Password: "admin123"},
}

// ===== CORS Middleware =====
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Set CORS headers
		w.Header().Set("Access-Control-Allow-Origin", ORIGIN)
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
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	user, ok := counters[creds.Username]
	if !ok || user.Password != creds.Password {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
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
	signed, _ := token.SignedString(jwtKey)

	http.SetCookie(w, &http.Cookie{
		Name:     "auth_token",
		Value:    signed,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteNoneMode,
		Secure: true,
		
	})
	broadcastState()
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

	if _, exists := counters[input.Username]; exists {
		http.Error(w, "Counter already exists", http.StatusBadRequest)
		return
	}

	counters[input.Username] = &Counter{Username: input.Username, Password: input.Password}
	broadcastState()
	json.NewEncoder(w).Encode(map[string]string{"message": "Counter created"})
}


func deleteCounter(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")
	if username == "" || username == "admin" {
		http.Error(w, "Invalid username", http.StatusBadRequest)
		return
	}
	delete(counters, username)
	broadcastState()
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

	// Validate input
	if input.OldUsername == "" || input.NewUsername == "" || input.Password == "" {
		http.Error(w, "Old username, new username, and password are required", http.StatusBadRequest)
		return
	}

	// Prevent admin account modification
	if input.OldUsername == "admin" {
		http.Error(w, "Cannot modify admin account", http.StatusForbidden)
		return
	}

	// Check if old username exists
	counter, exists := counters[input.OldUsername]
	if !exists {
		http.Error(w, "Counter not found", http.StatusNotFound)
		return
	}

	// If new username is different and already exists, prevent duplication
	if input.NewUsername != input.OldUsername {
		if _, exists := counters[input.NewUsername]; exists {
			http.Error(w, "New username already exists", http.StatusBadRequest)
			return
		}
		// Update username by removing old entry and creating new one
		delete(counters, input.OldUsername)
		counters[input.NewUsername] = &Counter{
			Username: input.NewUsername,
			Password: input.Password,
			Count:    counter.Count, // Preserve the count
		}
	} else {
		// If usernames are the same, only update password
		counter.Password = input.Password
	}

	broadcastState()
	json.NewEncoder(w).Encode(map[string]string{"message": "Counter updated"})
}

func listCounters(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(counters)
}

func incrementCounter(w http.ResponseWriter, r *http.Request) {
	user := r.Header.Get("X-User")
	counter, ok := counters[user]
	if !ok {
		http.Error(w, "User not found", http.StatusNotFound)
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
	broadcastState()
	json.NewEncoder(w).Encode(map[string]int{"count": counter.Count})
}

func resetCounter(w http.ResponseWriter, r *http.Request) {
	user := r.Header.Get("X-User")
	counter, ok := counters[user]
	if !ok {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}
	counter.Count = 0
	json.NewEncoder(w).Encode(map[string]int{"count": counter.Count})
	broadcastState()
}

// ===== WebSocket Broadcasting =====

type Client chan []byte

var (
	clients   = make(map[Client]bool)
	broadcast = make(chan []byte)
	upgrader  = websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool { return true },
	}
)

func wsHandler(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	client := make(Client)
	clients[client] = true

	go func() {
		for msg := range client {
			conn.WriteMessage(websocket.TextMessage, msg)
		}
	}()

	defer func() {
		delete(clients, client)
		close(client)
		conn.Close()
	}()

	// Passive read loop (to detect disconnects)
	for {
		if _, _, err := conn.ReadMessage(); err != nil {
			break
		}
	}
}

func broadcaster() {
	for {
		msg := <-broadcast
		for c := range clients {
			select {
			case c <- msg:
			default:
				close(c)
				delete(clients, c)
			}
		}
	}
}

func broadcastState() {
	state, _ := json.Marshal(counters)
	broadcast <- state
}

// ===== MAIN =====
func main() {
	mux := http.NewServeMux()

	// Public
	mux.HandleFunc("/api/login", loginHandler)
	mux.HandleFunc("/ws/counters", wsHandler)

	// Admin
	mux.HandleFunc("/api/admin/create", authMiddleware(createCounter, RoleAdmin))
	mux.HandleFunc("/api/admin/delete", authMiddleware(deleteCounter, RoleAdmin))
	mux.HandleFunc("/api/admin/list", authMiddleware(listCounters, RoleAdmin))
	mux.HandleFunc("/api/admin/update", authMiddleware(updateCounter, RoleAdmin))

	// Counter
	mux.HandleFunc("/api/counter/increment", authMiddleware(incrementCounter, RoleCounter))
	mux.HandleFunc("/api/counter/reset", authMiddleware(resetCounter, RoleCounter))

	// Start WebSocket broadcaster
	go broadcaster()

	fmt.Println("Server running on http://localhost:4000")
	log.Fatal(http.ListenAndServe(":4000", corsMiddleware(mux)))
}
