
const express = require("express");
const mongoose = require("mongoose");
const dotenv = require("dotenv");
const bcrypt = require("bcryptjs");
const path = require("path");

const User = require("./models/User");

dotenv.config();

const app = express();

// Allow server to read JSON and form information
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serve your HTML files from the public folder
app.use(express.static(path.join(__dirname, "public")));

// Create account route
app.post("/api/register", async (req, res) => {
    try {
        const { fullName, email, password } = req.body;

        // Check that all fields are filled in
        if (!fullName || !email || !password) {
            return res.status(400).json({
                message: "Please fill in all fields."
            });
        }

        // Validate email
        const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

        if (!emailPattern.test(email)) {
            return res.status(400).json({
                message: "Please enter a valid email."
            });
        }

        // Validate password
        if (password.length < 6) {
            return res.status(400).json({
                message: "Password must be at least 6 characters."
            });
        }

        // Check whether email already exists
        const existingUser = await User.findOne({
            email: email.toLowerCase().trim()
        });

        if (existingUser) {
            return res.status(409).json({
                message: "An account with this email already exists."
            });
        }

        // Hash password before saving
        const hashedPassword = await bcrypt.hash(password, 12);

        // Create new user
        const newUser = new User({
            fullName,
            email: email.toLowerCase().trim(),
            password: hashedPassword
        });

        // Save account to MongoDB
        await newUser.save();

        res.status(201).json({
            message: "Account created successfully!"
        });

    } catch (error) {
        console.error(error);

        res.status(500).json({
            message: "Server error creating account."
        });
    }
});

// Sign in route
app.post("/api/login", async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({
                message: "Please enter your email and password."
            });
        }

        // Find user by email
        const user = await User.findOne({
            email: email.toLowerCase().trim()
        });

        if (!user) {
            return res.status(401).json({
                message: "Invalid email or password."
            });
        }

        // Compare entered password with stored hash
        const passwordMatch = await bcrypt.compare(
            password,
            user.password
        );

        if (!passwordMatch) {
            return res.status(401).json({
                message: "Invalid email or password."
            });
        }

        res.json({
            message: "Login successful!",
            redirect: "/dashboard.html"
        });

    } catch (error) {
        console.error(error);

        res.status(500).json({
            message: "Server error signing in."
        });
    }
});

// Connect to MongoDB and start server
mongoose.connect(process.env.MONGO_URI)
    .then(() => {
        console.log("Connected to MongoDB!");

        const PORT = process.env.PORT || 3000;

        app.listen(PORT, () => {
            console.log(`Server running at http://localhost:${PORT}`);
        });
    })
    .catch(error => {
        console.error("MongoDB connection failed:", error);
    });
