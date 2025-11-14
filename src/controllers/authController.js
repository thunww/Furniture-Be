const User = require("../models/user");
const {
  registerUser,
  loginUser,
  forgotPassword,
  resetPassword,
  refreshAccessToken,
} = require("../services/authService");
const { verifyToken } = require("../config/jwt");
require("dotenv").config();

const getCookieOptions = (maxAge) => ({
  httpOnly: true,
  secure: false,
  sameSite: "Lax",
  path: "/",
  maxAge: maxAge,
});

const handleregisterUser = async (req, res) => {
  try {
    const { username, email, password } = req.body;
    const result = await registerUser(username, email, password);
    return res.status(201).json({
      message:
        "User registration successful. Please check your email for verification.",
      user: {
        user_id: result.user_id,
        username: result.username,
        email: result.email,
        role: result.role,
      },
    });
  } catch (error) {
    return res.status(400).json({ message: error.message });
  }
};

const handleLoginUser = async (req, res) => {
  try {
    const { email, password, rememberMe } = req.body;
    const { accessToken, refreshToken, user } = await loginUser(
      email,
      password,
      rememberMe
    );

    res.cookie(
      "accessToken",
      accessToken,
      getCookieOptions(2 * 60 * 60 * 1000)
    );
    res.cookie(
      "refreshToken",
      refreshToken,
      getCookieOptions(
        rememberMe ? 30 * 24 * 60 * 60 * 1000 : 7 * 24 * 60 * 60 * 1000
      )
    );

    res.json({
      message: "Login successful",
      user,
    });
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
};

const handleRefreshToken = async (req, res) => {
  try {
    const refreshToken = req.cookies.refreshToken;
    if (!refreshToken) {
      return res.status(401).json({ message: "Missing refresh token" });
    }

    const newAccessToken = await refreshAccessToken(refreshToken);
    res.cookie(
      "accessToken",
      newAccessToken,
      getCookieOptions(2 * 60 * 60 * 1000)
    );
    return res
      .status(200)
      .json({ message: "Access token refreshed successfully" });
  } catch (error) {
    res.clearCookie("accessToken", getCookieOptions(0));
    res.clearCookie("refreshToken", getCookieOptions(0));
    return res.status(403).json({ message: error.message });
  }
};

const verifyEmail = async (req, res) => {
  const { token } = req.query;
  if (!token) return res.status(400).json({ message: "Token is required" });

  try {
    const decoded = verifyToken(token);
    const user = await User.findOne({ where: { user_id: decoded.user_id } });
    if (!user) return res.status(400).json({ message: "User not found" });

    user.is_verified = true;
    await user.save();
    return res.redirect(`${process.env.CLIENT_URL}/login`);
  } catch (error) {
    return res.status(400).json({ message: "Invalid or expired token" });
  }
};

const handleForgotPassword = async (req, res) => {
  try {
    const { email } = req.body;
    const result = await forgotPassword(email);
    return res.status(200).json(result);
  } catch (error) {
    if (error.message === "No user found with this email") {
      return res.status(404).json({ message: error.message });
    }
    return res.status(500).json({
      message: "Failed to send reset password email, please try again later",
    });
  }
};

const handleResetPassword = async (req, res) => {
  try {
    const { token, newPassword } = req.body;
    const resultMessage = await resetPassword(token, newPassword);
    return res.status(200).json({ message: resultMessage });
  } catch (error) {
    if (error.name === "TokenExpiredError")
      return res.status(400).json({ message: "Reset token has expired" });
    if (error.message === "Reset token is required")
      return res.status(400).json({ message: "Reset token is required" });
    if (error.message === "User not found")
      return res.status(404).json({ message: "User not found" });
    return res.status(500).json({ message: "Internal server error" });
  }
};

const handleLogout = async (req, res) => {
  res.clearCookie("accessToken", getCookieOptions(0));
  res.clearCookie("refreshToken", getCookieOptions(0));
  return res.status(200).json({ message: "Logout successful" });
};

const handleGetProfile = async (req, res) => {
  try {
    const token = req.cookies.accessToken;
    if (!token) return res.status(401).json({ message: "Unauthorized" });

    const decoded = verifyToken(token);
    if (!decoded)
      return res.status(401).json({ message: "Invalid or expired token" });

    const user = await User.findOne({ where: { user_id: decoded.user_id } });
    if (!user) return res.status(404).json({ message: "User not found" });

    res.status(200).json({
      user: {
        user_id: user.user_id,
        username: user.username,
        email: user.email,
        roles: decoded.roles || [],
      },
    });
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
};

module.exports = {
  handleregisterUser,
  handleLoginUser,
  verifyEmail,
  handleForgotPassword,
  handleResetPassword,
  handleLogout,
  handleRefreshToken,
  handleGetProfile,
};
