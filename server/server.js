// ================== IMPORTS ==================
import express from "express";
import authRouter from "./authentication/authServer.js"; // Auth route module
import docRouter from "./doctors/docInfo.js";           // Doctor route module
import cors from "cors";
import "dotenv/config";                                 // Load .env variables
import cookieParser from "cookie-parser";

// ================== INITIALIZE APP AND CONFIG ==================
const app = express();
const port = process.env.PORT || 5000; // Default to 5000 if not set in .env

// ================== CORS CONFIG ==================
// Only allow frontend running at this origin
const allowedOrigins = ["http://localhost:5173"];

app.use(cors({
  origin: allowedOrigins,  // allow requests from this origin
  credentials: true        // allow cookies and auth headers
}));

// ================== MIDDLEWARE ==================
app.use(express.json());     // Parses incoming JSON requests
app.use(cookieParser());     // Parses cookies from request headers

// ================== ROUTES ==================

// Base route to test server status
app.get("/", (req, res) => {
  res.send("Welcome to the MERN Server!");
});

// Auth-related routes (register, login, logout, etc.)
app.use("/api/auth", authRouter);

// Doctor-related routes (get all doctors, search doctors, etc.)
app.use("/api/doc", docRouter);

// ================== START SERVER ==================
app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
