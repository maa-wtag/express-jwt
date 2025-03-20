// server.js

const express = require("express");
const jwt = require("jsonwebtoken");
const app = express();
const port = 3000;

// Use environment variables to store secrets in production
const JWT_SECRET = "your_jwt_secret"; // Replace with a secure secret key

// Middleware to parse JSON bodies
app.use(express.json());

// Dummy user data for demonstration purposes
// In a real-world scenario, validate against a database with hashed passwords.
const user = {
  id: 1,
  username: "testuser",
  password: "mypassword",
};

/**
 * POST /login
 * This endpoint authenticates a user and returns a JWT on success.
 */
app.post("/login", (req, res) => {
  const { username, password } = req.body;

  // Basic authentication check
  if (username === user.username && password === user.password) {
    // User is authenticated, generate a JWT
    const payload = { id: user.id, username: user.username };
    const token = jwt.sign(payload, JWT_SECRET, { expiresIn: "1h" });

    return res.json({
      message: "Authentication successful!",
      token,
    });
  }

  // If credentials are invalid, send an unauthorized response
  return res.status(401).json({ message: "Invalid username or password" });
});

/**
 * Middleware to authenticate and authorize requests using JWT.
 */
const authenticateToken = (req, res, next) => {
  // The token is expected to be sent in the Authorization header as: "Bearer <token>"
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({ message: "Token required" });
  }

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(403).json({ message: "Invalid or expired token" });
    }
    // Token is valid; attach decoded payload to request
    req.user = decoded;
    next();
  });
};

/**
 * Protected route example.
 * This route can only be accessed with a valid JWT.
 */
app.get("/protected", authenticateToken, (req, res) => {
  res.json({
    message: "This is a protected route.",
    user: req.user, // Information from the JWT payload
  });
});

// Middleware to verify the JWT
// const authenticateJWT = (req, res, next) => {
//   const authHeader = req.headers.authorization;

//   if (authHeader) {
//     const token = authHeader.split(' '); // Bearer <token>

//     jwt.verify(token, secretKey, (err, user) => {
//       if (err) {
//         return res.sendStatus(403); // 403 Forbidden (invalid token)
//       }

//       req.user = user; // Add the user data to the request object
//       next(); // Proceed to the next middleware or route handler
//     });
//   } else {
//     res.sendStatus(401); // 401 Unauthorized (no token)
//   }
// };

// // Example protected route
// app.get('/profile', authenticateJWT, (req, res) => {
//   res.json({ message: 'Protected route accessed!', user: req.user }); // Access user data from req.user
// });

// Example using fetch API:
// fetch("/profile", {
//   headers: {
//     Authorization: `Bearer ${localStorage.getItem("token")}`, // Get token from storage
//   },
// })
//   .then((response) => {
//     /*... */
//   })
//   .catch((error) => {
//     /*... */
//   });

// Basic home route
app.get("/", (req, res) => {
  res.send("Welcome to the Express JWT Authentication example!");
});

app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});
