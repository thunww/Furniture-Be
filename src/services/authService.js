const User = require("../models/user");
const Role = require("../models/role");
const UserRole = require("../models/userrole");
const { hashPassword, comparePassword } = require("../utils/hashPassword");
const { generateToken, verifyToken } = require("../config/jwt");
const {
  sendVerificationEmail,
  sendResetPasswordEmail,
} = require("../utils/sendEmail");
const { verifyCaptcha } = require("../utils/captchaHelper");

// ========================== CONFIG ==========================
const MAX_LOGIN_ATTEMPTS = 5;
const LOCK_TIME = 15 * 60 * 1000; // 15 phút
const ATTEMPT_WINDOW = 5 * 60 * 1000; // reset nếu cách >5 phút
const CAPTCHA_THRESHOLD = 3;

// ========================== REGISTER ==========================
const registerUser = async (username, email, password) => {
  if (!username || !email || !password)
    throw new Error("Thiếu thông tin đăng ký");

  const existingUser = await User.findOne({ where: { email } });
  if (existingUser) {
    // Không tiết lộ email đã tồn tại
    return {
      message:
        "Nếu địa chỉ email này chưa được đăng ký, bạn sẽ nhận được email xác minh trong vài phút.",
    };
  }

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
    message: "Nếu địa chỉ email hợp lệ, bạn sẽ nhận được email xác minh sớm.",
  };
};

// ========================== LOGIN ==========================
const loginUser = async (
  email,
  password,
  rememberMe = false,
  captchaToken = null
) => {
  const user = await User.findOne({ where: { email } });

  // Delay cố tình để chống timing attack
  await new Promise((r) => setTimeout(r, 500 + Math.random() * 300));

  if (!user) {
    console.warn(`[WARN] Login failed - email not found: ${email}`);
    throw new Error("Thông tin đăng nhập không hợp lệ.");
  }

  // Kiểm tra tài khoản bị khóa
  if (user.locked_until && new Date() < new Date(user.locked_until)) {
    const remainingTime = Math.ceil(
      (new Date(user.locked_until) - new Date()) / 1000 / 60
    );
    const error = new Error(
      `Tài khoản tạm khóa do đăng nhập sai quá nhiều lần. Vui lòng thử lại sau ${remainingTime} phút.`
    );
    error.isLocked = true;
    throw error;
  }

  // Reset nếu hết hạn khóa
  if (user.locked_until && new Date() >= new Date(user.locked_until)) {
    await user.update({
      login_attempts: 0,
      locked_until: null,
      last_failed_login: null,
    });
  }

  // Bắt buộc CAPTCHA nếu sai >=3 lần
  if (user.login_attempts >= CAPTCHA_THRESHOLD) {
    if (!captchaToken) {
      const error = new Error("Vui lòng xác minh CAPTCHA để tiếp tục.");
      error.needCaptcha = true;
      error.attempts = user.login_attempts;
      throw error;
    }

    const captchaValid = await verifyCaptcha(captchaToken);
    if (!captchaValid) {
      const error = new Error(
        "CAPTCHA không hợp lệ hoặc đã hết hạn. Vui lòng thử lại."
      );
      error.needCaptcha = true;
      error.attempts = user.login_attempts;
      throw error;
    }
  }

  const isMatch = await comparePassword(password, user.password);
  if (!isMatch) {
    const newAttempts = user.login_attempts + 1;
    const now = new Date();
    const timeSinceLastFail = user.last_failed_login
      ? now - new Date(user.last_failed_login)
      : ATTEMPT_WINDOW + 1;
    const attemptsToSave = timeSinceLastFail > ATTEMPT_WINDOW ? 1 : newAttempts;

    if (attemptsToSave >= MAX_LOGIN_ATTEMPTS) {
      const lockUntil = new Date(now.getTime() + LOCK_TIME);
      await user.update({
        login_attempts: attemptsToSave,
        locked_until: lockUntil,
        last_failed_login: now,
      });
      const error = new Error(
        `Bạn đã đăng nhập sai ${MAX_LOGIN_ATTEMPTS} lần. Tài khoản tạm khóa 15 phút.`
      );
      error.isLocked = true;
      throw error;
    }

    await user.update({
      login_attempts: attemptsToSave,
      last_failed_login: now,
    });

    console.warn(`[WARN] Wrong password for user: ${email}`);
    throw new Error("Thông tin đăng nhập không hợp lệ.");
  }

  if (user.status === "banned")
    throw new Error("Tài khoản bị khóa. Vui lòng liên hệ hỗ trợ.");
  if (!user.is_verified)
    throw new Error("Vui lòng xác minh email trước khi đăng nhập.");

  await user.update({
    login_attempts: 0,
    locked_until: null,
    last_failed_login: null,
  });

  // Lấy roles
  const userRoles = await UserRole.findAll({
    where: { user_id: user.user_id },
  });
  if (!userRoles.length) throw new Error("User has no assigned role!");

  const roleIds = userRoles.map((ur) => ur.role_id);
  const roles = await Role.findAll({ where: { role_id: roleIds } });
  const roleNames = roles.map((r) => r.role_name);

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
    message: "Đăng nhập thành công.",
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

// ========================== FORGOT PASSWORD ==========================
const forgotPassword = async (email) => {
  const user = await User.findOne({ where: { email } });

  // Delay để đồng bộ phản hồi
  await new Promise((r) => setTimeout(r, 400 + Math.random() * 300));

  if (!user) {
    console.warn(
      `[INFO] Password reset requested for non-existent email: ${email}`
    );
    return {
      message:
        "Nếu email tồn tại trong hệ thống, bạn sẽ nhận được hướng dẫn đặt lại mật khẩu.",
    };
  }

  const resetToken = generateToken({ userId: user.user_id }, "1h");
  await sendResetPasswordEmail(email, resetToken);

  return {
    message:
      "Nếu email tồn tại trong hệ thống, bạn sẽ nhận được hướng dẫn đặt lại mật khẩu.",
  };
};

// ========================== RESET PASSWORD ==========================
const resetPassword = async (token, newPassword) => {
  if (!token) throw new Error("Thiếu token đặt lại mật khẩu.");

  const decoded = verifyToken(token);
  const userId = decoded.userId;
  const user = await User.findOne({ where: { user_id: userId } });
  if (!user) throw new Error("Không tìm thấy tài khoản.");

  const hashedPassword = await hashPassword(newPassword);
  user.password = hashedPassword;
  await user.save();

  return "Mật khẩu đã được thay đổi thành công.";
};

// ========================== REFRESH TOKEN, LOGOUT, PROFILE ==========================
const refreshAccessToken = async (refreshToken) => {
  if (!refreshToken) throw new Error("Refresh token is required");

  const decoded = verifyToken(refreshToken);
  if (!decoded || decoded.type !== "refresh")
    throw new Error("Invalid refresh token");

  const user = await User.findOne({ where: { user_id: decoded.user_id } });
  if (!user) throw new Error("User not found");
  if (user.status === "banned") throw new Error("User account banned");

  const userRoles = await UserRole.findAll({
    where: { user_id: user.user_id },
  });
  const roleIds = userRoles.map((ur) => ur.role_id);
  const roles = await Role.findAll({ where: { role_id: roleIds } });
  const roleNames = roles.map((role) => role.role_name);

  const newAccessToken = generateToken(
    { user_id: user.user_id, email: user.email, roles: roleNames },
    "2h"
  );
  const newRefreshToken = generateToken(
    { user_id: user.user_id, type: "refresh" },
    "7d"
  );

  await user.update({ refresh_token: newRefreshToken });
  return { accessToken: newAccessToken, refreshToken: newRefreshToken };
};

const logoutUser = async (userId) => {
  const user = await User.findOne({ where: { user_id: userId } });
  if (!user) throw new Error("User not found");
  await user.update({ refresh_token: null });
  return { message: "Logout successful" };
};

const getUserProfile = async (accessToken) => {
  const decoded = verifyToken(accessToken);
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
