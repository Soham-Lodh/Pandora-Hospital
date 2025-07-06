// ====================== IMPORTS ======================
import express from "express";              // Express framework for server setup and routing
import pg from "pg";                        // PostgreSQL client
import bcrypt from "bcryptjs";              // For hashing passwords
import jwt from "jsonwebtoken";             // For creating/verifying JWT tokens
import transporter from "./nodemailer.js";  // Custom Nodemailer transporter module
import cors from "cors";                    // For handling CORS
import "dotenv/config";                     // Loads environment variables
import cookieParser from "cookie-parser";   // Parses cookies from incoming requests

// ====================== DB SETUP ======================
const db = new pg.Client({
  user: process.env.DB_USER,
  host: "localhost",
  database: process.env.DATABASE,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT
});
db.connect();

// ====================== EXPRESS APP SETUP ======================
const app = express();
const port = process.env.PORT;

// Set up allowed origins for CORS
const allowedOrigins=["http://localhost:5173"];

// Middlewares
app.use(express.json());                     // To parse JSON request bodies
app.use(cors({ origin: allowedOrigins, credentials: true })); // Allow frontend requests with cookies
app.use(cookieParser());                     // To access cookies

// ====================== AUTH CONTROLLERS ======================

// ---------- REGISTER ----------
const register = async (req, res) => {
  const { name, email, password } = req.body;

  // Validate input
  if (!name || !email || !password) {
    return res.json({ success: false, message: "Please fill all the fields" });
  }

  try {
    // Check if user already exists
    const existingUser = await db.query("SELECT * FROM patients WHERE email=$1", [email]);
    if (existingUser.rows.length > 0) {
      return res.json({ success: false, message: "User already exists" });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 15);

    // Save user to DB
    const result = await db.query(
      "INSERT INTO patients (name, email, password) VALUES ($1, $2, $3) RETURNING *",
      [name, email, hashedPassword]
    );
    const newUser = result.rows[0];

    // Create JWT token
    const token = jwt.sign({ id: newUser.id }, process.env.JWT_SECRET, { expiresIn: "7d" });

    // Store token in cookie
    res.cookie("token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
      maxAge: 7 * 24 * 60 * 60 * 1000
    });

    // Send welcome email
    const mailOptions = {
      from: process.env.SENDER_EMAIL,
      to: email,
      subject: "Welcome to Our App",
      text: `Hello ${name},\n\nThank you for registering on our app. We are excited to have you on board!\n\nBest regards,\nPandora Hospital`
    };
    transporter.sendMail(mailOptions);

    return res.json({ success: true, message: "User registered successfully" });
  } catch (err) {
    return res.json({ success: false, message: "Something went wrong during registration" });
  }
};

// ---------- LOGIN ----------
const login = async (req, res) => {
  const { email, password } = req.body;

  // Validate input
  if (!email || !password) {
    return res.json({ success: false, message: "Please fill all the fields" });
  }

  try {
    // Find user
    const result = await db.query("SELECT * FROM patients WHERE email=$1", [email]);
    const user = result.rows[0];

    if (!user) {
      return res.json({ success: false, message: "User does not exist" });
    }

    // Compare passwords
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.json({ success: false, message: "Invalid credentials" });
    }

    // Issue JWT token
    const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET, { expiresIn: "7d" });

    // Store token in cookie
    res.cookie("token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: process.env.NODE_ENV === "production" ? "none" : "lax",
      maxAge: 7 * 24 * 60 * 60 * 1000
    });

    return res.json({ success: true, message: "Login successful" });
  } catch (err) {
    return res.json({ success: false, message: "Something went wrong during login" });
  }
};

// ---------- LOGOUT ----------
const logout = async (req, res) => {
  try {
    // Clear token cookie
    res.clearCookie("token", {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: process.env.NODE_ENV === "production" ? "none" : "strict"
    });

    return res.json({ success: true, message: "Logged out successfully" });
  } catch (err) {
    return res.json({ success: false, message: "Something went wrong during logout" });
  }
};

// ---------- SEND VERIFY OTP ----------
const sendVerifyOtp = async (req, res) => {
  try {
    const userId = req.userId;

    // Get user
    const result = await db.query("SELECT * FROM patients WHERE id=$1", [userId]);
    const user = result.rows[0];

    if (!user) return res.json({ success: false, message: "User not found" });
    if (user.is_account_verified) return res.json({ success: false, message: "Account already verified" });

    // Generate OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // valid for 10 min

    // Store OTP in DB
    await db.query("UPDATE patients SET otp=$1, otp_expires_at=$2 WHERE id=$3", [otp, expiresAt, userId]);

    // Send OTP email
    const mailOptions = {
      from: process.env.SENDER_EMAIL,
      to: user.email,
      subject: "Verify Your Account",
      text: `Your verification OTP is ${otp}. It is valid for 10 minutes.`
    };
    transporter.sendMail(mailOptions);

    return res.json({ success: true, message: "OTP sent successfully" });
  } catch (err) {
    return res.json({ success: false, message: "Something went wrong while sending OTP" });
  }
};

// ---------- VERIFY OTP ----------
const verifyOtp = async (req, res) => {
  try {
    const { otp } = req.body;
    const userId = req.userId;

    // Check required fields
    if (!userId || !otp) {
      return res.json({ success: false, message: "Please fill all the fields" });
    }

    // Get user
    const result = await db.query("SELECT * FROM patients WHERE id=$1", [userId]);
    const user = result.rows[0];

    if (!user) return res.json({ success: false, message: "User not found" });
    if (user.is_account_verified) return res.json({ success: false, message: "Account already verified" });
    if (user.otp !== otp) return res.json({ success: false, message: "Invalid OTP" });

    // Check expiry
    const now = new Date();
    if (user.otp_expires_at && now > new Date(user.otp_expires_at)) {
      return res.json({ success: false, message: "OTP has expired" });
    }

    // Mark as verified
    await db.query("UPDATE patients SET is_account_verified=true, otp=NULL, otp_expires_at=NULL WHERE id=$1", [userId]);

    return res.json({ success: true, message: "Account verified successfully" });
  } catch (err) {
    return res.json({ success: false, message: "Something went wrong during OTP verification" });
  }
};

// ---------- CHECK AUTH ----------
const isAuthenticated = async (req, res) => {
  try {
    return res.json({
      success: true,
      message: "User is authenticated",
      userId: req.userId
    });
  } catch (err) {
    return res.json({ success: false, message: "Something went wrong" });
  }
};

// ====================== JWT AUTH MIDDLEWARE ======================
const userAuth = async (req, res, next) => {
  const { token } = req.cookies;

  if (!token) return res.json({ success: false, message: "Unauthorized" });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    if (decoded.id) {
      req.userId = decoded.id;
      next();
    } else {
      return res.json({ success: false, message: "Unauthorized" });
    }
  } catch (err) {
    return res.json({ success: false, message: "Invalid or expired token" });
  }
};

// ====================== ROUTES ======================
const authRouter = express.Router();
authRouter.post("/register", register);
authRouter.post("/login", login);
authRouter.post("/logout", logout);
authRouter.post("/send-verify-otp", userAuth, sendVerifyOtp);
authRouter.post("/verify-otp", userAuth, verifyOtp);
authRouter.get("/is-auth", userAuth, isAuthenticated);

// Use the auth router under /api/auth
app.use("/api/auth", authRouter);

// ====================== START SERVER ======================
app.listen(port, () => {
  console.log(`🚀 Server running at http://localhost:${port}`);
});
