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


Below is an example of how you can implement a token refresh mechanism using JWTs in an ExpressJS application. This example shows how to generate both an access token (with a short expiry) and a refresh token (with a longer expiry), how to validate the refresh token to generate a new access token, and how to optionally handle logout.

### Step-by-Step Explanation

1. **Login Endpoint:**  
   When a user logs in (after successful authentication), you issue both an access token and a refresh token. The access token typically has a short expiry (e.g., 15 minutes), while the refresh token may not have an expiry or have a longer one.

2. **Storing Refresh Tokens:**  
   In this simple example, refresh tokens are stored in an in-memory array. In a production app, consider storing them in a database or a secure store so you can revoke them if needed.

3. **Token Refresh Endpoint:**  
   This endpoint accepts a refresh token. It verifies the token using the refresh token secret and, if valid, issues a new access token.

4. **Logout Endpoint:**  
   This endpoint invalidates a refresh token by removing it from the store.

### Code Example

```javascript
const express = require('express');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');

const app = express();
app.use(bodyParser.json());

// Secrets for signing tokens (store these securely in your environment)
const ACCESS_TOKEN_SECRET = 'youraccesstokensecret';
const REFRESH_TOKEN_SECRET = 'yourrefreshtokensecret';

// In-memory store for refresh tokens (for demo purposes)
let refreshTokens = [];

// Login endpoint: Authenticate the user and generate tokens
app.post('/login', (req, res) => {
  // Replace this with your actual authentication logic
  const { username, password } = req.body;
  if (username !== 'user' || password !== 'password') {
    return res.status(401).json({ message: 'Username or password incorrect' });
  }
  
  const user = { name: username };

  // Create an access token that expires in 15 minutes
  const accessToken = jwt.sign(user, ACCESS_TOKEN_SECRET, { expiresIn: '15m' });
  // Create a refresh token (you may choose an expiry for this as well)
  const refreshToken = jwt.sign(user, REFRESH_TOKEN_SECRET);
  
  // Save refresh token so we can revoke it later if needed
  refreshTokens.push(refreshToken);
  
  res.json({ accessToken, refreshToken });
});

// Token refresh endpoint: Validate the refresh token and issue a new access token
app.post('/token', (req, res) => {
  const { token } = req.body;
  if (!token) return res.sendStatus(401);
  if (!refreshTokens.includes(token)) return res.sendStatus(403); // Forbidden if token not recognized

  jwt.verify(token, REFRESH_TOKEN_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    
    // Optionally, you can exclude refresh token specific fields here
    const { name } = user;
    const newAccessToken = jwt.sign({ name }, ACCESS_TOKEN_SECRET, { expiresIn: '15m' });
    res.json({ accessToken: newAccessToken });
  });
});

// Logout endpoint: Remove the refresh token from the store
app.post('/logout', (req, res) => {
  const { token } = req.body;
  refreshTokens = refreshTokens.filter(t => t !== token);
  res.sendStatus(204);
});

// Middleware to authenticate access token for protected routes
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  // Token is usually sent as "Bearer <token>"
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.sendStatus(401);

  jwt.verify(token, ACCESS_TOKEN_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

// Protected route example
app.get('/protected', authenticateToken, (req, res) => {
  res.json({ message: `Hello ${req.user.name}, you have accessed a protected route!` });
});

app.listen(4000, () => {
  console.log('Server running on port 4000');
});
```

### How It Works

- **/login:**  
  Validates user credentials (here, a simple check is used for demonstration). It then issues an access token (valid for 15 minutes) and a refresh token, storing the latter.

- **/token:**  
  Checks if the refresh token is provided and is valid. If so, it issues a new access token. This lets the user continue their session without having to log in again.

- **/logout:**  
  Removes the refresh token from the store, effectively revoking it.

- **authenticateToken Middleware:**  
  Protects routes by verifying the provided access token.

This pattern allows you to keep your access tokens short-lived (improving security) while still providing a way for the client to get a new access token using the refresh token.

Feel free to customize this code to suit your application's security requirements and persistence strategies.
