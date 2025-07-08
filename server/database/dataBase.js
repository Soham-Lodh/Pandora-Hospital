import pkg from "pg";
import "dotenv/config";


const { Pool } = pkg;

const db = new Pool({
  user: process.env.DB_USER,
  host: "localhost",
  database: process.env.DATABASE,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT,
});

export default db;
