const express = require("express");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const app = express();

app.use(express.json());

// Secret key for JWT
const JWT_SECRET = process.env.JWT_SECRET || "your-secret-key";

const mongoose = require("mongoose");

const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, enum: ["user", "admin"], default: "user" },
});

// Hash password before saving
userSchema.pre("save", async function (next) {
  if (this.isModified("password")) {
    this.password = await bcrypt.hash(this.password, 12);
  }
  next();
});

const User = mongoose.model("User", userSchema);

const auth = async (req, res, next) => {
  try {
    const token = req.header("Authorization").replace("Bearer ", "");
    const decoded = jwt.verify(token, JWT_SECRET);

    const user = await User.findById(decoded.id);
    if (!user) {
      throw new Error();
    }

    req.user = user;
    req.token = token;
    next();
  } catch (error) {
    res.status(401).json({
      status: "error",
      message: "Please authenticate",
    });
  }
};

const authorize = (...roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({
        status: "error",
        message: "Not authorized to access this resource",
      });
    }
    next();
  };
};

// Register new user
app.post("/auth/register", async (req, res) => {
  try {
    const { email, password } = req.body;

    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({
        status: "error",
        message: "Email already registered",
      });
    }

    // Create new user
    const user = await User.create({
      email,
      password,
    });

    // Generate token
    const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: "24h" });

    res.status(201).json({
      status: "success",
      data: {
        user: {
          id: user._id,
          email: user.email,
          role: user.role,
        },
        token,
      },
    });
  } catch (error) {
    res.status(500).json({
      status: "error",
      message: error.message,
    });
  }
});

// Login user
app.post("/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    // Find user
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({
        status: "error",
        message: "Invalid credentials",
      });
    }

    // Check password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({
        status: "error",
        message: "Invalid credentials",
      });
    }

    // Generate token
    const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: "24h" });

    res.json({
      status: "success",
      data: {
        user: {
          id: user._id,
          email: user.email,
          role: user.role,
        },
        token,
      },
    });
  } catch (error) {
    res.status(500).json({
      status: "error",
      message: error.message,
    });
  }
});

// Logout (optional - client-side token removal)
app.post("/auth/logout", auth, (req, res) => {
  res.json({
    status: "success",
    message: "Logged out successfully",
  });
});

// Protected route - all authenticated users
app.get("/profile", auth, async (req, res) => {
  res.json({
    status: "success",
    data: {
      user: {
        id: req.user._id,
        email: req.user.email,
        role: req.user.role,
      },
    },
  });
});

// Admin-only route
app.get("/admin/dashboard", auth, authorize("admin"), async (req, res) => {
  // Admin dashboard data
  res.json({
    status: "success",
    data: {
      // Admin specific data
    },
  });
});

// Request password reset
app.post("/auth/forgot-password", async (req, res) => {
  try {
    const { email } = req.body;
    const user = await User.findOne({ email });

    if (!user) {
      return res.status(404).json({
        status: "error",
        message: "User not found",
      });
    }

    // Generate reset token
    const resetToken = jwt.sign({ id: user._id }, JWT_SECRET, {
      expiresIn: "1h",
    });

    // In a real application, send this token via email
    res.json({
      status: "success",
      message: "Password reset token sent to email",
      resetToken, // In production, don't send this in response
    });
  } catch (error) {
    res.status(500).json({
      status: "error",
      message: error.message,
    });
  }
});

// Reset password
app.post("/auth/reset-password", async (req, res) => {
  try {
    const { token, newPassword } = req.body;

    // Verify token
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.id);

    if (!user) {
      return res.status(404).json({
        status: "error",
        message: "Invalid or expired reset token",
      });
    }

    // Update password
    user.password = newPassword;
    await user.save();

    res.json({
      status: "success",
      message: "Password reset successful",
    });
  } catch (error) {
    res.status(500).json({
      status: "error",
      message: error.message,
    });
  }
});

// Refresh token
app.post("/auth/refresh-token", async (req, res) => {
  try {
    const { token } = req.body;

    // Verify existing token
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.id);

    if (!user) {
      throw new Error();
    }

    // Generate new token
    const newToken = jwt.sign({ id: user._id }, JWT_SECRET, {
      expiresIn: "24h",
    });

    res.json({
      status: "success",
      data: { token: newToken },
    });
  } catch (error) {
    res.status(401).json({
      status: "error",
      message: "Invalid token",
    });
  }
});
