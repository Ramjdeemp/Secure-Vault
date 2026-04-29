const mysql = require('mysql2/promise');
require('dotenv').config();

const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD || '', // Fallback for empty password
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

pool.getConnection()
  .then(conn => {
    console.log("✅ MySQL Database connected successfully.");
    conn.release();
  })
  .catch(err => {
    console.error("❌ Database connection failed.");
    console.error("Error:", err.message);
  });

module.exports = pool;