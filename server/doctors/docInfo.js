// Import the database connection and Express
import db from "./../database/dataBase.js";
import express from "express";

// Route handler to fetch all doctors
const allInfo = async (req, res) => {
    try {
        // Query all doctor records from the 'doctors' table
        const result = await db.query("SELECT * FROM doctors");

        // Extract rows (array of doctor objects)
        const data = result.rows;

        // Return the data as a JSON response
        return res.json(data);
    } catch (err) {
        // Log and return internal server error if query fails
        console.error("Error in allInfo:", err);
        return res.status(500).json({ error: "Internal server error" });
    }
};

// Route handler to fetch doctors by name or specialty
const someInfo = async (req, res) => {
    try {
        // Destructure input from request body
        const { input } = req.body;

        // Handle missing input
        if (!input) {
            return res.status(400).json({ error: "Missing search input" });
        }

        // Query doctors table where name or specialty partially matches the input (case-insensitive)
        const result = await db.query(
            "SELECT * FROM doctors WHERE name ILIKE $1 OR specialty ILIKE $1",
            [`%${input}%`] // Add wildcards for partial match
        );

        // Extract matching rows
        const data = result.rows;

        // Return the filtered data
        return res.json(data);
    } catch (err) {
        // Log and return internal server error if query fails
        console.error("Error in someInfo:", err);
        return res.status(500).json({ error: "Internal server error" });
    }
};

// Create a router instance
const docRouter = express.Router();

// Route to get all doctors
docRouter.get("/doc-info", allInfo);

// Route to get doctors by name or specialty (requires POST with 'input' in body)
docRouter.post("/specific-doc-info", someInfo);

// Export the router
export default docRouter;
