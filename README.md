## Testing the Application

### 1. Start the Server

```bash
node server.js

```

### 2. Authenticate and Receive a Token

Send a POST request to `/login` (using Postman, cURL, etc.):

```bash
curl -X POST http://localhost:3000/login \
  -H "Content-Type: application/json" \
  -d '{"username": "testuser", "password": "mypassword"}'

```

You should receive a JSON response containing the token.

### 3. Access the Protected Route

Use the token to access the protected route. For example, using cURL:

```bash
curl http://localhost:3000/protected \
  -H "Authorization: Bearer YOUR_JWT_TOKEN_HERE"

```

Replace `YOUR_JWT_TOKEN_HERE` with the token received from the login endpoint.
