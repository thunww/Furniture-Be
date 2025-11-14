const User = require("../models/user");
const Role = require("../models/role");
const UserRole = require("../models/userrole");
const { hashPassword, comparePassword } = require("../utils/hashPassword");
const { generateToken, verifyToken } = require("../config/jwt");
const {
  sendVerificationEmail,
  sendResetPasswordEmail,
} = require("../utils/sendEmail");

const registerUser = async (username, email, password) => {
  if (!username || !email || !password) {
    throw new Error("Missing information");
  }
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
    console.log("Verification email sent successfully.");
  } catch (error) {
    console.log("Error sending verification email: ", error.message);
  }

  return {
    user_id: newUser.user_id,
    username: newUser.username,
    email: newUser.email,
    role: customerRole.role_name,
  };
};

const loginUser = async (email, password, rememberMe = false) => {
  const user = await User.findOne({ where: { email } });

  // Luôn trả lỗi chung nếu email không tồn tại hoặc mật khẩu sai
  if (!user) throw new Error("Email hoặc mật khẩu không chính xác");

  const isMatch = await comparePassword(password, user.password);
  if (!isMatch) throw new Error("Email hoặc mật khẩu không chính xác");

  // Cấm login nếu bị khóa hoặc chưa xác minh
  if (user.status === "banned") throw new Error("Tài khoản đã bị khóa");
  if (!user.is_verified)
    throw new Error("Vui lòng xác minh email trước khi đăng nhập");

  // Lấy roles
  const userRoles = await UserRole.findAll({
    where: { user_id: user.user_id },
  });
  const roleIds = userRoles.map((ur) => ur.role_id);
  const roles = await Role.findAll({ where: { role_id: roleIds } });
  const roleNames = roles.map((r) => r.role_name);

  // Tạo Access Token (2h)
  const accessToken = generateToken(
    { user_id: user.user_id, email: user.email, roles: roleNames },
    "2h"
  );

  // Tạo Refresh Token (7 hoặc 30 ngày)
  const refreshExpiresIn = rememberMe ? "30d" : "7d";
  const refreshToken = generateToken(
    { user_id: user.user_id, email: user.email },
    refreshExpiresIn
  );

  return {
    message: "Đăng nhập thành công",
    accessToken,
    refreshToken,
    user: {
      user_id: user.user_id,
      email: user.email,
      roles: roleNames,
    },
  };
};

// ✅ Làm mới token
const refreshAccessToken = async (refreshToken) => {
  const decoded = verifyToken(refreshToken);
  if (!decoded) throw new Error("Invalid or expired refresh token");

  // Tạo token mới
  const newAccessToken = generateToken(
    {
      user_id: decoded.user_id,
      email: decoded.email,
    },
    "2h"
  );

  return newAccessToken;
};

const forgotPassword = async (email) => {
  const user = await User.findOne({ where: { email } });
  if (!user) {
    throw new Error("No user found with this email");
  }

  const resetToken = generateToken({ userId: user.user_id }, "1h");

  await sendResetPasswordEmail(email, resetToken);

  return { message: "Password reset email has been sent" };
};

const resetPassword = async (token, newPassword) => {
  if (!token) {
    throw new Error("Reset token is required");
  }

  const decoded = verifyToken(token);
  const userId = decoded.userId;

  const user = await User.findOne({ where: { user_id: userId } });
  if (!user) {
    throw new Error("User not found");
  }

  const hashedPassword = await hashPassword(newPassword);
  user.password = hashedPassword;
  await user.save();

  return "Password has been successfully changed";
};

module.exports = {
  registerUser,
  loginUser,
  forgotPassword,
  resetPassword,
  refreshAccessToken,
};
