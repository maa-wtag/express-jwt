const express = require("express");
const jwt = require("jsonwebtoken");
const bodyParser = require("body-parser");

const app = express();
app.use(bodyParser.json());

// Secrets for signing tokens (store these securely in your environment)
const ACCESS_TOKEN_SECRET = "youraccesstokensecret";
const REFRESH_TOKEN_SECRET = "yourrefreshtokensecret";

// In-memory store for refresh tokens (for demo purposes)
let refreshTokens = [];

// Login endpoint: Authenticate the user and generate tokens
app.post("/login", (req, res) => {
  // Replace this with your actual authentication logic
  const { username, password } = req.body;
  if (username !== "user" || password !== "password") {
    return res.status(401).json({ message: "Username or password incorrect" });
  }

  const user = { name: username };

  // Create an access token that expires in 15 minutes
  const accessToken = jwt.sign(user, ACCESS_TOKEN_SECRET, { expiresIn: "15m" });
  // Create a refresh token (you may choose an expiry for this as well)
  const refreshToken = jwt.sign(user, REFRESH_TOKEN_SECRET);

  // Save refresh token so we can revoke it later if needed
  refreshTokens.push(refreshToken);

  res.json({ accessToken, refreshToken });
});

// Token refresh endpoint: Validate the refresh token and issue a new access token
app.post("/token", (req, res) => {
  const { token } = req.body;
  if (!token) return res.sendStatus(401);
  if (!refreshTokens.includes(token)) return res.sendStatus(403); // Forbidden if token not recognized

  jwt.verify(token, REFRESH_TOKEN_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);

    // Optionally, you can exclude refresh token specific fields here
    const { name } = user;
    const newAccessToken = jwt.sign({ name }, ACCESS_TOKEN_SECRET, {
      expiresIn: "15m",
    });
    res.json({ accessToken: newAccessToken });
  });
});

// Logout endpoint: Remove the refresh token from the store
app.post("/logout", (req, res) => {
  const { token } = req.body;
  refreshTokens = refreshTokens.filter((t) => t !== token);
  res.sendStatus(204);
});

// Middleware to authenticate access token for protected routes
function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  // Token is usually sent as "Bearer <token>"
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) return res.sendStatus(401);

  jwt.verify(token, ACCESS_TOKEN_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

// Protected route example
app.get("/protected", authenticateToken, (req, res) => {
  res.json({
    message: `Hello ${req.user.name}, you have accessed a protected route!`,
  });
});

app.listen(4000, () => {
  console.log("Server running on port 4000");
});
