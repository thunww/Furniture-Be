const User = require("../models/user");
const {
  registerUser,
  loginUser,
  loginWithGoogle, // ← THÊM
  refreshAccessToken,
  logoutUser,
  forgotPassword,
  resetPassword,
  getUserProfile,
} = require("../services/authService");
const { verifyToken } = require("../config/jwt");
require("dotenv").config();

const cookieOptions = {
  httpOnly: true,
  secure: process.env.NODE_ENV === "production",
  sameSite: process.env.NODE_ENV === "production" ? "None" : "Lax",
  path: "/",
};

// ========================== REGISTER ==========================
const handleregisterUser = async (req, res) => {
  try {
    const { username, email, password } = req.body;

    const result = await registerUser(username, email, password);

    return res.status(201).json({
      message: result.message || "User registration successful.",
      user: result.user || null,
    });
  } catch (error) {
    console.error(" Lỗi đăng ký:", error.message);
    return res.status(400).json({
      message: error.message || "Đăng ký thất bại, vui lòng thử lại.",
    });
  }
};

// ========================== LOGIN ==========================
const handleLoginUser = async (req, res) => {
  try {
    const { email, password, rememberMe, captchaToken } = req.body;

    const { accessToken, refreshToken, user } = await loginUser(
      email,
      password,
      rememberMe,
      captchaToken
    );

    const accessTokenMaxAge = rememberMe
      ? 7 * 24 * 60 * 60 * 1000
      : 2 * 60 * 60 * 1000;
    const refreshTokenMaxAge = rememberMe
      ? 30 * 24 * 60 * 60 * 1000
      : 7 * 24 * 60 * 60 * 1000;

    res.cookie("accessToken", accessToken, {
      ...cookieOptions,
      maxAge: accessTokenMaxAge,
    });

    res.cookie("refreshToken", refreshToken, {
      ...cookieOptions,
      maxAge: refreshTokenMaxAge,
    });

    res.json({
      message: "Login successful",
      user,
    });
  } catch (error) {
    console.error("Login error:", error.message);

    // Xác định status code
    const statusCode = error.isLocked ? 423 : 401; // 423 = Locked

    return res.status(statusCode).json({
      message: error.message,
      needCaptcha: error.needCaptcha || false,
      isLocked: error.isLocked || false,
      attempts: error.attempts || 0,
    });
  }
};

// ========================== GOOGLE LOGIN ==========================
const handleGoogleLogin = async (req, res) => {
  try {
    const { googleToken } = req.body;

    if (!googleToken) {
      return res.status(400).json({
        message: "Google token is required",
      });
    }

    const { accessToken, refreshToken, user } = await loginWithGoogle(
      googleToken
    );

    // Set cookies với thời gian dài hơn cho Google login
    res.cookie("accessToken", accessToken, {
      ...cookieOptions,
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 ngày
    });

    res.cookie("refreshToken", refreshToken, {
      ...cookieOptions,
      maxAge: 30 * 24 * 60 * 60 * 1000, // 30 ngày
    });

    return res.status(200).json({
      message: "Google login successful",
      user,
    });
  } catch (error) {
    console.error("Google login error:", error.message);
    return res.status(401).json({
      message: error.message,
    });
  }
};

// ========================== REFRESH TOKEN ==========================
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

    const {
      accessToken,
      refreshToken: newRefresh,
      user,
    } = await refreshAccessToken(refreshToken);

    res.cookie("accessToken", accessToken, {
      ...cookieOptions,
      maxAge: 2 * 60 * 60 * 1000,
    });

    res.cookie("refreshToken", newRefresh, {
      ...cookieOptions,
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    res.json({
      message: "Token refreshed successfully",
      user,
    });
  } catch (error) {
    console.error("Refresh token error:", error.message);

    res.clearCookie("accessToken", cookieOptions);
    res.clearCookie("refreshToken", cookieOptions);

    return res.status(401).json({
      message: error.message,
      needLogin: true,
    });
  }
};

// ========================== VERIFY EMAIL ==========================
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

// ========================== FORGOT PASSWORD ==========================
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

// ========================== RESET PASSWORD ==========================
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

// ========================== LOGOUT ==========================
const handleLogout = async (req, res) => {
  try {
    const userId = req.user?.id || req.user?.user_id;

    if (userId) {
      await logoutUser(userId);
    }

    res.clearCookie("accessToken", cookieOptions);
    res.clearCookie("refreshToken", cookieOptions);

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

// ========================== GET PROFILE ==========================
const handleGetProfile = async (req, res) => {
  try {
    const accessToken = req.cookies?.accessToken;
    if (!accessToken) {
      return res.status(401).json({ message: "Unauthorized - No token" });
    }

    const profile = await getUserProfile(accessToken);

    return res.status(200).json({
      message: "Profile retrieved successfully",
      user: profile,
    });
  } catch (error) {
    console.error("Get profile error:", error.message);
    return res.status(401).json({
      message: error.message || "Failed to get profile",
    });
  }
};

module.exports = {
  handleregisterUser,
  handleLoginUser,
  handleGoogleLogin,
  handleRefreshToken,
  verifyEmail,
  handleForgotPassword,
  handleResetPassword,
  handleLogout,
  handleGetProfile,
};
