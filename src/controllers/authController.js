const User = require("../models/user");
const {
  registerUser,
  loginUser,
  refreshAccessToken,
  logoutUser,
  forgotPassword,
  resetPassword,
} = require("../services/authService");
const { verifyToken } = require("../config/jwt");
require("dotenv").config();

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
    return res.status(400).json({
      message: error.message,
    });
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

    // Thời gian sống của cookie tùy thuộc vào rememberMe
    const accessTokenMaxAge = rememberMe
      ? 7 * 24 * 60 * 60 * 1000
      : 2 * 60 * 60 * 1000; // 7 ngày hoặc 2 giờ
    const refreshTokenMaxAge = rememberMe
      ? 30 * 24 * 60 * 60 * 1000
      : 7 * 24 * 60 * 60 * 1000; // 30 ngày hoặc 7 ngày

    // Set access token cookie
    res.cookie("accessToken", accessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: process.env.NODE_ENV === "production" ? "None" : "lax",
      maxAge: accessTokenMaxAge,
      path: "/",
    });

    // Set refresh token cookie
    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: process.env.NODE_ENV === "production" ? "None" : "lax",
      maxAge: refreshTokenMaxAge,
      path: "/",
    });

    res.json({
      message: "Login successful",
      user,
    });
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
};

// Controller để refresh access token
const handleRefreshToken = async (req, res) => {
  try {
    const refreshToken = req.cookies?.refreshToken;

    console.log(
      "Refresh token from cookie:",
      refreshToken ? "exists" : "missing"
    );

    if (!refreshToken) {
      return res.status(401).json({
        message: "Refresh token not found",
        needLogin: true,
      });
    }

    const { accessToken, user } = await refreshAccessToken(refreshToken);

    // Set access token mới vào cookie
    res.cookie("accessToken", accessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: process.env.NODE_ENV === "production" ? "None" : "lax",
      maxAge: 2 * 60 * 60 * 1000, // 2 giờ
      path: "/",
    });

    res.json({
      message: "Token refreshed successfully",
      user,
    });
  } catch (error) {
    console.error("Refresh token error:", error.message);

    // Nếu refresh token không hợp lệ, xóa cả 2 cookies
    res.clearCookie("accessToken", {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: process.env.NODE_ENV === "production" ? "None" : "lax",
      path: "/",
    });

    res.clearCookie("refreshToken", {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: process.env.NODE_ENV === "production" ? "None" : "lax",
      path: "/",
    });

    return res.status(401).json({
      message: error.message,
      needLogin: true,
    });
  }
};

const verifyEmail = async (req, res) => {
  const { token } = req.query;
  if (!token) {
    return res.status(400).json({ message: "Token is required" });
  }

  try {
    const decoded = verifyToken(token);

    const user = await User.findOne({ where: { user_id: decoded.user_id } });
    if (!user) {
      return res.status(400).json({ message: "User not found" });
    }

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
    console.error("Error in forgotPassword:", error);
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
    console.error("Error in resetPassword:", error);

    if (error.name === "TokenExpiredError") {
      return res.status(400).json({ message: "Reset token has expired" });
    }
    if (error.message === "Reset token is required") {
      return res.status(400).json({ message: "Reset token is required" });
    }
    if (error.message === "User not found") {
      return res.status(404).json({ message: "User not found" });
    }

    return res.status(500).json({ message: "Internal server error" });
  }
};

const handleLogout = async (req, res) => {
  try {
    const userId = req.user?.id;

    if (userId) {
      // Xóa refresh token khỏi database
      await logoutUser(userId);
    }

    // Xóa cả 2 cookies
    res.clearCookie("accessToken", {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: process.env.NODE_ENV === "production" ? "None" : "lax",
      path: "/",
    });

    res.clearCookie("refreshToken", {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: process.env.NODE_ENV === "production" ? "None" : "lax",
      path: "/",
    });

    return res.status(200).json({
      message: "Logout successful",
    });
  } catch (error) {
    console.error("Logout error:", error);
    return res.status(500).json({
      message: "Logout failed",
    });
  }
};

module.exports = {
  handleregisterUser,
  handleLoginUser,
  handleRefreshToken,
  verifyEmail,
  handleForgotPassword,
  handleResetPassword,
  handleLogout,
};
