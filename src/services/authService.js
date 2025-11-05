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
  if (!user) {
    throw new Error("Email does not exist!");
  }

  const isMatch = await comparePassword(password, user.password);
  if (!isMatch) {
    throw new Error("Incorrect password!");
  }

  if (user.status === "banned") {
    throw new Error("User account banned");
  }

  if (!user.is_verified) {
    throw new Error("Please verify your email first!");
  }

  const userRoles = await UserRole.findAll({
    where: { user_id: user.user_id },
  });

  if (userRoles.length === 0) {
    throw new Error("User has no assigned role!");
  }

  const roleIds = userRoles.map((ur) => ur.role_id);
  const roles = await Role.findAll({ where: { role_id: roleIds } });
  const roleNames = roles.map((role) => role.role_name);

  // Tạo access token (thời gian ngắn)
  const accessTokenExpiry = rememberMe ? "7d" : "2h";
  const accessToken = generateToken(
    {
      user_id: user.user_id,
      email: user.email,
      roles: roleNames,
    },
    accessTokenExpiry
  );

  // Tạo refresh token (thời gian dài hơn)
  const refreshTokenExpiry = rememberMe ? "30d" : "7d";
  const refreshToken = generateToken(
    {
      user_id: user.user_id,
      type: "refresh",
    },
    refreshTokenExpiry
  );

  // Lưu refresh token vào database
  await user.update({
    refresh_token: refreshToken,
  });

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

// Service để refresh access token
const refreshAccessToken = async (refreshToken) => {
  if (!refreshToken) {
    throw new Error("Refresh token is required");
  }

  // Verify refresh token
  const decoded = verifyToken(refreshToken);
  if (!decoded || decoded.type !== "refresh") {
    throw new Error("Invalid refresh token");
  }

  // Tìm user và kiểm tra refresh token trong DB
  const user = await User.findOne({
    where: {
      user_id: decoded.user_id,
      refresh_token: refreshToken,
    },
  });

  if (!user) {
    throw new Error("Invalid refresh token or user not found");
  }

  if (user.status === "banned") {
    throw new Error("User account banned");
  }

  // Lấy roles của user
  const userRoles = await UserRole.findAll({
    where: { user_id: user.user_id },
  });

  const roleIds = userRoles.map((ur) => ur.role_id);
  const roles = await Role.findAll({ where: { role_id: roleIds } });
  const roleNames = roles.map((role) => role.role_name);

  // Tạo access token mới
  const newAccessToken = generateToken(
    {
      user_id: user.user_id,
      email: user.email,
      roles: roleNames,
    },
    "2h"
  );

  return {
    accessToken: newAccessToken,
    user: {
      user_id: user.user_id,
      email: user.email,
      username: user.username,
      roles: roleNames,
    },
  };
};

// Service để logout (xóa refresh token)
const logoutUser = async (userId) => {
  const user = await User.findOne({ where: { user_id: userId } });

  if (!user) {
    throw new Error("User not found");
  }

  // Xóa refresh token khỏi database
  await user.update({
    refresh_token: null,
  });

  return { message: "Logout successful" };
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
  refreshAccessToken,
  logoutUser,
  forgotPassword,
  resetPassword,
};
