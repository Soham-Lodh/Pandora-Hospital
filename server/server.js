import express from "express";
import authRouter from "./authentication/authServer.js"; // Ensure ".js" is added if using ES modules
import cors from "cors";
import "dotenv/config";
import cookieParser from "cookie-parser";

// ================== INITIALIZE APP AND CONFIG ==================
const app = express();
const port = process.env.PORT || 5000;

// ================== CORS CONFIG ==================
const allowedOrigins = ["http://localhost:5173"];

app.use(cors({
  origin: allowedOrigins,
  credentials: true
}));

// ================== MIDDLEWARE ==================
app.use(express.json());           // Parse JSON bodies
app.use(cookieParser());           // Read cookies

// ================== ROUTES ==================
app.get("/", (req, res) => {
  res.send("Welcome to the MERN Server!");
});

app.use("/api/auth", authRouter);  // Auth routes

// ================== START SERVER ==================
app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
