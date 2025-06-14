Understood\! I'll update the backend README to reflect that the **`PORT`** environment variable isn't explicitly set and defaults to **`4000`**. I'll remove it from the `.env` example to maintain clarity about its default behavior.

Here's the revised backend README:

# Antrian Simple: Real-time Queue Management (Backend)

This repository houses the Go backend application for **Antrian Simple**, a real-time queue management and display system. This application provides the core logic for managing counter statuses, user authentication, and serving real-time updates to the frontend via **long polling**, prioritizing less computational burden on the server. All data, including counter states and user information, is persisted in **Redis**.

-----

## Features

  - **Counter Management API:** RESTful API endpoints for creating, reading, updating, and deleting counter configurations. All counter data is stored and managed in **Redis**.
  - **User Authentication & Authorization:** Secure login and role-based access control for administrators and counter users. User session data and roles are managed using **Redis**.
  - **Real-time Updates via Long Polling:** Efficiently pushes real-time queue status updates to connected frontend clients, ideal for high-frequency, low-latency requirements while minimizing server overhead. Updates are sourced directly from **Redis**.
  - **Redis Integration:** Utilizes **Redis** as the primary data store for all application data, ensuring fast read/write operations for real-time responsiveness.
  - **Seamless Integration:** Designed to work with the **Antrian Simple Next.js Frontend**.

-----

## Prerequisites

Before running this backend application, ensure you have the following installed:

  - **Go**: `v1.20` or higher
  - **Redis**: A running Redis instance for data storage.
  - **Antrian Simple Next.js Frontend**: While this is the backend, it's designed to be used with the frontend for a complete system.

-----

## Installation

Follow these steps to set up and run the backend application locally:

1.  **Clone the repository:**

    ```bash
    git clone https://github.com/AdMFirst/antrian-simple-backend.git
    cd antrian-simple-backend
    ```

2.  **Install dependencies:**

    ```bash
    go mod tidy
    ```

3.  **Configure Environment Variables:**
    Create a `.env` file in the root of the project and add the following:

    ```
    NEXT_FRONT_END_URL=https://localhost:3000
    JWT_KEY=secret-word
    ADMIN_PASSWORD=
    MY_REDIS_URL=redis://default:password@localhost:6379
    ```

      - **`NEXT_FRONT_END_URL`**: The URL of your Next.js frontend application. This is useful for CORS or other frontend-backend interactions.
      - **`JWT_KEY`**: A strong, secret key used for signing JWT tokens. **Generate a complex, random string for production.**
      - **`ADMIN_PASSWORD`**: The default password for the initial admin user. This should be set in production for security.
      - **`MY_REDIS_URL`**: The connection string for your Redis instance (e.g., `redis://default:password@localhost:6379`).

    **Note:** Ensure your Redis instance is running and accessible with the provided configuration. The backend will run on **port 4000** by default.

4.  **Run the application:**

    ```bash
    go run main.go
    ```

    The backend server will typically be accessible at `http://localhost:4000`.

-----

## API Documentation

The backend exposes RESTful API endpoints for various functionalities.

### Public Endpoints

  - **`POST /api/login`**: Authenticate a user. Requires `username` and `password` in the request body. Returns a JWT token upon successful authentication.
  - **`GET /api/poll`**: This is the **long polling** endpoint for real-time updates. The frontend will make repeated requests to this endpoint to receive the latest queue numbers for all counters. The backend holds the request open until new data is available or a timeout occurs, then sends the response.

### Admin Endpoints (Admin Role Required)

These endpoints require a valid JWT token with an "Admin" role in the `Authorization` header.

  - **`POST /api/admin/create`**: Create a new counter.
  - **`POST /api/admin/delete`**: Delete an existing counter.
  - **`GET /api/admin/list`**: Retrieve a list of all counters.
  - **`POST /api/admin/update`**: Update an existing counter's details.

### Counter Endpoints (Counter Role Required)

These endpoints require a valid JWT token with a "Counter" role in the `Authorization` header.

  - **`POST /api/counter/increment`**: Increment the current queue number for the authenticated counter.

-----

## Developer Documentation

### Key Technologies

  - **Go**: The primary language for the backend, chosen for its performance, concurrency features, and low computational overhead.
  - **`net/http` package**: Used for building the HTTP server and handling requests.
  - **`github.com/joho/godotenv`**: For loading environment variables from a `.env` file.
  - **`github.com/golang-jwt/jwt/v5`**: For handling JSON Web Tokens for authentication and authorization.
  - **`github.com/redis/go-redis/v9`**: The official Go client for Redis, used for all data persistence and retrieval.

### Data Model (in Redis)

Data is stored in Redis using various data structures:

  - **Counters**: Each counter might be stored as a Hash, where the hash key is the counter ID and fields represent properties like `name` and `current_number`. A Set or Sorted Set could also maintain a list of active counter IDs.
  - **Users**: User data (username, hashed password, role) could be stored as Hashes, with a unique user ID as the hash key.
  - **Real-time Updates**: A Pub/Sub channel or a simple key-value pair could be used to signal updates, triggering the long polling responses.

### Long Polling Implementation

The `/api/poll` endpoint is designed to support **long polling**. When a client requests this endpoint:

1.  The server checks for new queue updates from Redis.
2.  If new updates are available, it immediately sends the data and closes the connection.
3.  If no new updates are available, the server holds the connection open for a predefined period (e.g., up to 50 seconds) or until an update occurs in Redis.
4.  Once new data is available or the timeout is reached, the server sends the response.
5.  The client, upon receiving a response, immediately makes a new request to continue receiving updates.
    This approach reduces continuous connection overhead compared to WebSockets, making it suitable for scenarios where computational burden is a key concern.

-----

## Dependencies

This project relies on the following key Go modules, managed via `go.mod`:

  - `github.com/joho/godotenv`: For loading environment variables.
  - `github.com/golang-jwt/jwt/v5`: For JWT handling.
  - `github.com/redis/go-redis/v9`: Redis client for Go.
  - `golang.org/x/crypto/bcrypt`: For password hashing.
  - *And standard Go libraries like `net/http`, `encoding/json`, etc.*

-----

## Notes

  - The backend handles all data persistence in Redis, business logic, and exposes the API endpoints for the frontend.
  - Error handling and logging are crucial for robust production deployments.
  - The `JWT_KEY` should be kept highly confidential and ideally loaded from a secure environment variable in production.
  - For initial setup, you might need to manually populate some admin users (using the `ADMIN_PASSWORD` for the default admin) and counters directly in Redis or provide an initialization script.

-----

## License

This project is licensed under GNU General Public License v3.0. - see the LICENSE.md file for more details.

