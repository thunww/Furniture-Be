const express = require("express");
const router = express.Router();
const authMiddleware = require("../middleware/authMiddleware");
const {
  handleregisterUser,
  handleLoginUser,
  handleRefreshToken,
  verifyEmail,
  handleForgotPassword,
  handleResetPassword,
  handleLogout,
} = require("../controllers/authController");

// Public routes
router.post("/register", handleregisterUser);
router.post("/login", handleLoginUser);
router.get("/verify-email", verifyEmail);
router.post("/forgot-password", handleForgotPassword);
router.post("/reset-password", handleResetPassword);

// Route để refresh token (không cần authMiddleware)
router.post("/refresh-token", handleRefreshToken);

// Protected routes
router.post("/logout", authMiddleware, handleLogout);

module.exports = router;
