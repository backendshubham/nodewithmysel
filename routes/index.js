var express = require("express");
const jwt = require("jsonwebtoken");
var router = express.Router();
const connection = require("./../database/connection");
const { hashPassword, comparePassword } = require("./../helper/hashPassword");

/* GET home page. */
router.get("/", function (req, res, next) {
  res.render("index", { title: "Express" });
});

/* GET home page. */
router.post("/signup", async function (req, res, next) {
  try {
    // Validate required fields
    const requiredFields = ["name", "phone", "email", "password"];
    for (const field of requiredFields) {
      if (!req.body[field]) {
        return res
          .status(400)
          .json({ error: `Missing required field: ${field}` });
      }
    }

    const userData = {
      name: req.body.name,
      phone: req.body.phone,
      email: req.body.email,
      password: await hashPassword(req.body.password),
    };

    // Insert data into the users table
    const insertQuery =
      "INSERT INTO users (name, phone, email, password) VALUES (?, ?, ?, ?)";

    connection.query(
      insertQuery,
      [userData.name, userData.phone, userData.email, userData.password],
      (error, results, fields) => {
        if (error) {
          res.status(500).json({ error: "Internal Server Error" });
          return;
        }

        const token = jwt.sign(
          {
            data: { id: results.insertId, email: req.body.email },
          },
          "aaaabbbbcccc",
          { expiresIn: "1h" }
        );

        console.log("Data inserted successfully. Insert ID:", results.insertId);
        res
          .status(201)
          .json({ message: "User registered successfully", token });
      }
    );
  } catch (err) {
    res.status(500).json({ error: "Internal Server Error" });
  }
});


// Login route
router.post('/login', async function(req, res, next) {
  try {
    // Validate required fields
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    // Retrieve user from the database
    const selectQuery = 'SELECT id, email, password FROM users WHERE email = ?';
    connection.query(selectQuery, [email], async (error, results, fields) => {
      if (error) {
        console.error('Error retrieving user data:', error);
        return res.status(500).json({ error: 'Internal Server Error' });
      }

      if (results.length === 0) {
        return res.status(401).json({ error: 'Invalid credentials' });
      }

      const user = results[0];

      // Compare passwords
      const passwordMatch = await comparePassword(password, user.password);

      if (!passwordMatch) {
        return res.status(401).json({ error: 'Invalid credentials' });
      }

      const token = jwt.sign(
        {
          data: { id: user.id, email: user.email },
        },
        'aaaabbbbcccc',
        { expiresIn: '1h' }
      );

      res.status(200).json({ message: 'Login successful', token });
    });
  } catch (err) {
    res.status(500).json({ message: 'Internal Server Error' });
  }
});

module.exports = router;
