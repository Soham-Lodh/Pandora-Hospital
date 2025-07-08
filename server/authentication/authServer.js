// ====================== IMPORTS ======================
import express from "express";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import transporter from "./../mail/nodemailer.js";
import "dotenv/config";
import cookieParser from "cookie-parser";
import db from "./../database/dataBase.js";

// ====================== CONTROLLERS ======================

// ---------- REGISTER ----------
const register = async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password)
    return res.json({ success: false, message: "Please fill all the fields" });

  try {
    // Check if user already exists
    const userExists = await db.query("SELECT * FROM patients WHERE email = $1", [email]);
    if (userExists.rows.length)
      return res.json({ success: false, message: "User already exists" });

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 15);

    // Insert user into database
    const result = await db.query(
      "INSERT INTO patients (name, email, password) VALUES ($1, $2, $3) RETURNING *",
      [name, email, hashedPassword]
    );

    const newUser = result.rows[0];

    // Generate JWT token
    const token = jwt.sign({ id: newUser.patient_id }, process.env.JWT_SECRET, {
      expiresIn: "7d",
    });

    // Set cookie
    res.cookie("token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    });

    // Send welcome email
    await transporter.sendMail({
      from: process.env.SENDER_EMAIL,
      to: email,
      subject: "Welcome to Our App",
      text: `Hello ${name},\n\nThanks for registering on our app!\n\nRegards,\nPandora Hospital`,
    });

    res.json({ success: true, message: "User registered successfully" });
  } catch (err) {
    console.error("❌ Registration error:", err);
    res.json({ success: false, message: "Something went wrong during registration" });
  }
};

// ---------- LOGIN ----------
const login = async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password)
    return res.json({ success: false, message: "Please fill all the fields" });

  try {
    const result = await db.query("SELECT * FROM patients WHERE email = $1", [email]);
    const user = result.rows[0];

    if (!user) return res.json({ success: false, message: "User does not exist" });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.json({ success: false, message: "Invalid credentials" });

    const token = jwt.sign({ id: user.patient_id }, process.env.JWT_SECRET, {
      expiresIn: "7d",
    });

    res.cookie("token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: process.env.NODE_ENV === "production" ? "none" : "lax",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    res.json({ success: true, message: "Login successful" });
  } catch (err) {
    console.error("❌ Login error:", err);
    res.json({ success: false, message: "Something went wrong during login" });
  }
};

// ---------- LOGOUT ----------
const logout = (req, res) => {
  try {
    res.clearCookie("token", {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
    });
    res.json({ success: true, message: "Logged out successfully" });
  } catch (err) {
    console.error("❌ Logout error:", err);
    res.json({ success: false, message: "Something went wrong during logout" });
  }
};

// ---------- SEND OTP ----------
const sendVerifyOtp = async (req, res) => {
  const userId = req.userId;

  try {
    const result = await db.query("SELECT * FROM patients WHERE patient_id = $1", [userId]);
    const user = result.rows[0];

    if (!user) return res.json({ success: false, message: "User not found" });
    if (user.is_account_verified)
      return res.json({ success: false, message: "Account already verified" });

    // Generate 6-digit OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 min from now

    // Store OTP and expiry
    await db.query(
      "UPDATE patients SET otp = $1, otp_expires_at = $2 WHERE patient_id = $3",
      [otp, expiresAt, userId]
    );

    // Send OTP via email
    await transporter.sendMail({
      from: process.env.SENDER_EMAIL,
      to: user.email,
      subject: "Verify Your Account",
      text: `Your verification OTP is ${otp}. It is valid for 10 minutes.`,
    });

    res.json({ success: true, message: "OTP sent successfully" });
  } catch (err) {
    console.error("❌ Send OTP error:", err);
    res.json({ success: false, message: "Something went wrong while sending OTP" });
  }
};

// ---------- VERIFY OTP ----------
const verifyOtp = async (req, res) => {
  const { otp } = req.body;
  const userId = req.userId;

  if (!otp || !userId)
    return res.json({ success: false, message: "Please fill all the fields" });

  try {
    const result = await db.query("SELECT * FROM patients WHERE patient_id = $1", [userId]);
    const user = result.rows[0];

    if (!user) return res.json({ success: false, message: "User not found" });
    if (user.is_account_verified)
      return res.json({ success: false, message: "Account already verified" });

    if (user.otp !== otp) return res.json({ success: false, message: "Invalid OTP" });

    if (user.otp_expires_at && new Date() > new Date(user.otp_expires_at))
      return res.json({ success: false, message: "OTP has expired" });

    // Mark account as verified
    await db.query(
      "UPDATE patients SET is_account_verified = true, otp = NULL, otp_expires_at = NULL WHERE patient_id = $1",
      [userId]
    );

    res.json({ success: true, message: "Account verified successfully" });
  } catch (err) {
    console.error("❌ OTP verification error:", err);
    res.json({ success: false, message: "Something went wrong during OTP verification" });
  }
};

// ---------- CHECK AUTH ----------
const isAuthenticated = (req, res) => {
  res.json({ success: true, message: "User is authenticated", userId: req.userId });
};

// ====================== MIDDLEWARE ======================
const userAuth = (req, res, next) => {
  const { token } = req.cookies;
  if (!token) return res.json({ success: false, message: "Unauthorized" });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = decoded.id;
    next();
  } catch (err) {
    console.error("❌ Auth middleware error:", err);
    res.json({ success: false, message: "Invalid or expired token" });
  }
};

// ====================== ROUTER ======================
const authRouter = express.Router();

// Public Routes
authRouter.post("/register", register);
authRouter.post("/login", login);
authRouter.post("/logout", logout);

// Protected Routes
authRouter.post("/send-verify-otp", userAuth, sendVerifyOtp);
authRouter.post("/verify-otp", userAuth, verifyOtp);
authRouter.get("/is-auth", userAuth, isAuthenticated);

export default authRouter;
