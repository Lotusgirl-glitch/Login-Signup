const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const UserModel = require("../Models/User");


const signup = async (req, res) => {
    try {
        console.log("➡️ Signup request received:", req.body);

        const { name, email, password } = req.body;

        const user = await UserModel.findOne({ email });
        console.log("🔍 Checking if user exists...");

        if (user) {
            console.log("⚠️ User already exists");
            return res.status(409)
                .json({ message: 'User already exists', success: false });
        }

        console.log("✅ Creating new user...");
        const userModel = new UserModel({ name, email, password });

        userModel.password = await bcrypt.hash(password, 10);
        console.log("🔐 Password hashed");

        await userModel.save();
        console.log("💾 User saved to database");

        res.status(201).json({
            message: "Signup successful",
            success: true
        });

    } catch (err) {
        console.error("🔥 Signup error:", err);
        res.status(500).json({
            message: "Internal server error",
            success: false
        });
    }
};



const login = async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await UserModel.findOne({ email });
        const errorMsg = 'Auth failed email or password is wrong';
        if (!user) {
            return res.status(403)
                .json({ message: errorMsg, success: false });
        }
        const isPassEqual = await bcrypt.compare(password, user.password);
        if (!isPassEqual) {
            return res.status(403)
                .json({ message: errorMsg, success: false });
        }
        const jwtToken = jwt.sign(
            { email: user.email, _id: user._id },
            process.env.JWT_SECRET,
            { expiresIn: '24h' }
        )

        res.status(200)
            .json({
                message: "Login Success",
                success: true,
                jwtToken,
                email,
                name: user.name
            })
    } catch (err) {
        res.status(500)
            .json({
                message: "Internal server errror",
                success: false
            })
    }
}

module.exports = {
    signup,
    login
}