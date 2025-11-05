const express = require("express");
const {
  handleLoginUser,
  handleregisterUser,
  verifyEmail,
  handleForgotPassword,
  handleResetPassword,
  handleLogout,
  handleRefreshToken,
  handleGetProfile,
} = require("../controllers/authController");

const router = express.Router();

// ---------- ROUTES ----------
router.post("/register", handleregisterUser);
router.post("/login", handleLoginUser);
router.get("/verify-email", verifyEmail);
router.post("/forgot-password", handleForgotPassword);
router.post("/reset-password", handleResetPassword);
router.post("/logout", handleLogout);

// ✅ Thêm route refresh token
router.post("/refresh", handleRefreshToken);
router.get("/profile", handleGetProfile);

module.exports = router;
