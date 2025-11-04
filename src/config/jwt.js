const jwt = require("jsonwebtoken");

const SECRET_KEY = process.env.JWT_SECRET || "your_secret_key";
const EXPIRES_IN = process.env.JWT_EXPIRES_IN || "2h"; // access token mặc định 2h

// Tạo token (access hoặc refresh)
const generateToken = (payload, expiresIn = EXPIRES_IN) => {
  return jwt.sign(payload, SECRET_KEY, { expiresIn });
};

// Giải mã token
const verifyToken = (token) => {
  try {
    return jwt.verify(token, SECRET_KEY);
  } catch (error) {
    return null;
  }
};

module.exports = { generateToken, verifyToken };
