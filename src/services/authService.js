const User = require("../models/user");
const Role = require("../models/role");
const UserRole = require("../models/userrole");
const { hashPassword, comparePassword } = require("../utils/hashPassword");
const { generateToken, verifyToken } = require("../config/jwt");
const {
  sendVerificationEmail,
  sendResetPasswordEmail,
} = require("../utils/sendEmail");

// ========================== REGISTER ==========================
const registerUser = async (username, email, password) => {
  if (!username || !email || !password) throw new Error("Missing information");

  const existingUser = await User.findOne({ where: { email } });
  if (existingUser) throw new Error("Email already in use");

  const hashedPassword = await hashPassword(password);
  const newUser = await User.create({
    username,
    email,
    password: hashedPassword,
  });

  const customerRole = await Role.findOne({ where: { role_name: "customer" } });
  await UserRole.create({
    user_id: newUser.user_id,
    role_id: customerRole.role_id,
  });

  const verificationToken = generateToken({
    user_id: newUser.user_id,
    email: newUser.email,
    role: customerRole.role_name,
  });

  try {
    await sendVerificationEmail(newUser.email, verificationToken);
  } catch (error) {
    console.log("Error sending verification email:", error.message);
  }

  return {
    user_id: newUser.user_id,
    username: newUser.username,
    email: newUser.email,
    role: customerRole.role_name,
  };
};

// ========================== LOGIN ==========================
const loginUser = async (email, password, rememberMe = false) => {
  const user = await User.findOne({ where: { email } });
  if (!user) throw new Error("Email does not exist!");

  const isMatch = await comparePassword(password, user.password);
  if (!isMatch) throw new Error("Incorrect password!");

  if (user.status === "banned") throw new Error("User account banned");
  if (!user.is_verified) throw new Error("Please verify your email first!");

  const userRoles = await UserRole.findAll({
    where: { user_id: user.user_id },
  });
  if (!userRoles.length) throw new Error("User has no assigned role!");

  const roleIds = userRoles.map((ur) => ur.role_id);
  const roles = await Role.findAll({ where: { role_id: roleIds } });
  const roleNames = roles.map((role) => role.role_name);

  const accessTokenExpiry = rememberMe ? "7d" : "2h";
  const refreshTokenExpiry = rememberMe ? "30d" : "7d";

  const accessToken = generateToken(
    { user_id: user.user_id, email: user.email, roles: roleNames },
    accessTokenExpiry
  );

  const refreshToken = generateToken(
    { user_id: user.user_id, type: "refresh" },
    refreshTokenExpiry
  );

  await user.update({ refresh_token: refreshToken });

  return {
    message: "Login successful",
    accessToken,
    refreshToken,
    user: {
      user_id: user.user_id,
      email: user.email,
      username: user.username,
      roles: roleNames,
      status: user.status,
    },
  };
};

// ========================== REFRESH TOKEN ==========================
const refreshAccessToken = async (refreshToken) => {
  if (!refreshToken) throw new Error("Refresh token is required");

  // ✅ Giải mã refresh token
  const decoded = verifyToken(refreshToken);
  if (!decoded || decoded.type !== "refresh")
    throw new Error("Invalid refresh token");

  // ✅ Không cần so sánh token, chỉ cần user tồn tại
  const user = await User.findOne({ where: { user_id: decoded.user_id } });
  if (!user) throw new Error("User not found");
  if (user.status === "banned") throw new Error("User account banned");

  // ✅ Lấy roles
  const userRoles = await UserRole.findAll({
    where: { user_id: user.user_id },
  });
  const roleIds = userRoles.map((ur) => ur.role_id);
  const roles = await Role.findAll({ where: { role_id: roleIds } });
  const roleNames = roles.map((role) => role.role_name);

  // ✅ Tạo access token mới
  const newAccessToken = generateToken(
    { user_id: user.user_id, email: user.email, roles: roleNames },
    "2h"
  );

  // ✅ (Tuỳ chọn) rotate refresh token — nhưng KHÔNG ép so sánh DB
  const newRefreshToken = generateToken(
    { user_id: user.user_id, type: "refresh" },
    "7d"
  );
  await user.update({ refresh_token: newRefreshToken });

  return {
    accessToken: newAccessToken,
    refreshToken: newRefreshToken,
    user: {
      user_id: user.user_id,
      email: user.email,
      username: user.username,
      roles: roleNames,
    },
  };
};

// ========================== LOGOUT ==========================
const logoutUser = async (userId) => {
  const user = await User.findOne({ where: { user_id: userId } });
  if (!user) throw new Error("User not found");
  await user.update({ refresh_token: null });
  return { message: "Logout successful" };
};

// ========================== FORGOT PASSWORD ==========================
const forgotPassword = async (email) => {
  const user = await User.findOne({ where: { email } });
  if (!user) throw new Error("No user found with this email");

  const resetToken = generateToken({ userId: user.user_id }, "1h");
  await sendResetPasswordEmail(email, resetToken);

  return { message: "Password reset email has been sent" };
};

// ========================== RESET PASSWORD ==========================
const resetPassword = async (token, newPassword) => {
  if (!token) throw new Error("Reset token is required");

  const decoded = verifyToken(token);
  const userId = decoded.userId;

  const user = await User.findOne({ where: { user_id: userId } });
  if (!user) throw new Error("User not found");

  const hashedPassword = await hashPassword(newPassword);
  user.password = hashedPassword;
  await user.save();

  return "Password has been successfully changed";
};
const getUserProfile = async (accessToken) => {
  if (!accessToken) throw new Error("Access token missing");

  const decoded = verifyToken(accessToken);
  if (!decoded || !decoded.user_id) throw new Error("Invalid or expired token");

  const user = await User.findOne({
    where: { user_id: decoded.user_id },
    attributes: ["user_id", "username", "email", "status", "is_verified"],
  });

  if (!user) throw new Error("User not found");

  const userRoles = await UserRole.findAll({
    where: { user_id: user.user_id },
  });

  const roleIds = userRoles.map((ur) => ur.role_id);
  const roles = await Role.findAll({ where: { role_id: roleIds } });
  const roleNames = roles.map((r) => r.role_name);

  return {
    user_id: user.user_id,
    username: user.username,
    email: user.email,
    status: user.status,
    is_verified: user.is_verified,
    roles: roleNames,
  };
};

module.exports = {
  registerUser,
  loginUser,
  refreshAccessToken,
  logoutUser,
  forgotPassword,
  resetPassword,
  getUserProfile,
};
