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
const { OAuth2Client } = require("google-auth-library");
const { Op } = require("sequelize");

// ========================== CONFIG ==========================
const MAX_LOGIN_ATTEMPTS = 5;
const LOCK_TIME = 15 * 60 * 1000; // 15 phút
const ATTEMPT_WINDOW = 5 * 60 * 1000; // reset nếu cách >5 phút
const CAPTCHA_THRESHOLD = 3;

const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

// ========================== REGISTER ==========================
const registerUser = async (username, email, password) => {
  if (!username || !email || !password)
    throw new Error("Thiếu thông tin đăng ký");

  // 🔍 Kiểm tra email đã tồn tại chưa
  const existingUser = await User.findOne({ where: { email } });

  if (existingUser) {
    //  Nếu tài khoản Google → báo rõ
    if (existingUser.auth_provider === "google") {
      throw new Error(
        "Email này đã được đăng ký bằng tài khoản Google. Vui lòng đăng nhập bằng Google."
      );
    }

    //  Nếu là local → không tiết lộ chi tiết (ẩn thông tin)
    return {
      message:
        "Nếu địa chỉ email này chưa được đăng ký, bạn sẽ nhận được email xác minh trong vài phút.",
    };
  }

  //  Hash password
  const hashedPassword = await hashPassword(password);

  //  Tạo user mới
  const newUser = await User.create({
    username,
    email,
    password: hashedPassword,
    auth_provider: "local",
    is_verified: false,
    status: "active",
  });

  //  Gán role mặc định = customer
  const customerRole = await Role.findOne({ where: { role_name: "customer" } });
  if (customerRole) {
    await UserRole.create({
      user_id: newUser.user_id,
      role_id: customerRole.role_id,
    });
  }

  //  Gửi email xác minh
  const verificationToken = generateToken({
    user_id: newUser.user_id,
    email: newUser.email,
    role: customerRole.role_name,
  });

  try {
    await sendVerificationEmail(newUser.email, verificationToken);
  } catch (error) {
    console.error(" Lỗi gửi email xác minh:", error.message);
  }

  //  Trả kết quả cho controller
  return {
    message:
      "Đăng ký thành công! Vui lòng kiểm tra email để xác minh tài khoản.",
    user: {
      user_id: newUser.user_id,
      username: newUser.username,
      email: newUser.email,
      role: customerRole.role_name,
    },
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

  // ← KIỂM TRA XEM USER ĐĂNG KÝ BẰNG GOOGLE
  if (user.auth_provider === "google" && !user.password) {
    throw new Error(
      "Tài khoản này đăng ký bằng Google. Vui lòng sử dụng 'Đăng nhập với Google'."
    );
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

// ========================== GOOGLE LOGIN ==========================

const loginWithGoogle = async (googleToken) => {
  try {
    // 1. Verify Google token
    const ticket = await client.verifyIdToken({
      idToken: googleToken,
      audience: process.env.GOOGLE_CLIENT_ID,
    });

    const payload = ticket.getPayload();
    const { email, name, picture, sub: googleId, email_verified } = payload;

    if (!email_verified) {
      throw new Error("Email chưa được xác thực bởi Google.");
    }

    // 2. Tìm user theo google_id TRƯỚC
    let user = await User.findOne({
      where: { google_id: googleId },
    });

    // 3. Nếu chưa có user với google_id → Kiểm tra email
    if (!user) {
      // Kiểm tra xem email đã tồn tại chưa
      const existingUser = await User.findOne({
        where: { email: email },
      });

      // ← NẾU EMAIL ĐÃ TỒN TẠI VÀ KHÔNG PHẢI GOOGLE → TỪCHỐI
      if (existingUser && existingUser.auth_provider === "local") {
        throw new Error(
          `Email ${email} đã được đăng ký bằng tài khoản thông thường. Vui lòng đăng nhập bằng email và mật khẩu.`
        );
      }

      // Nếu email chưa tồn tại → Tạo mới
      user = await User.create({
        username: name || email.split("@")[0],
        email: email,
        google_id: googleId,
        auth_provider: "google",
        profile_picture: picture,
        is_verified: true,
        status: "active",
        password: null,
      });

      // Gán role customer mặc định
      const customerRole = await Role.findOne({
        where: { role_name: "customer" },
      });
      if (customerRole) {
        await UserRole.create({
          user_id: user.user_id,
          role_id: customerRole.role_id,
        });
      }

      console.log(`[INFO] New user registered via Google: ${email}`);
    }

    // 4. Kiểm tra tài khoản bị banned
    if (user.status === "banned") {
      throw new Error("Tài khoản bị khóa. Vui lòng liên hệ hỗ trợ.");
    }

    // 5. Lấy roles
    const userRoles = await UserRole.findAll({
      where: { user_id: user.user_id },
    });
    const roleIds = userRoles.map((ur) => ur.role_id);
    const roles = await Role.findAll({ where: { role_id: roleIds } });
    const roleNames = roles.map((r) => r.role_name);

    // 6. Tạo tokens
    const accessToken = generateToken(
      { user_id: user.user_id, email: user.email, roles: roleNames },
      "7d"
    );

    const refreshToken = generateToken(
      { user_id: user.user_id, type: "refresh" },
      "30d"
    );

    await user.update({ refresh_token: refreshToken });

    return {
      message: "Đăng nhập Google thành công.",
      accessToken,
      refreshToken,
      user: {
        user_id: user.user_id,
        email: user.email,
        username: user.username,
        profile_picture: user.profile_picture,
        roles: roleNames,
        status: user.status,
        auth_provider: user.auth_provider,
      },
    };
  } catch (error) {
    console.error("[ERROR] Google login failed:", error.message);
    throw new Error(error.message || "Xác thực Google thất bại");
  }
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
  loginWithGoogle,
  refreshAccessToken,
  logoutUser,
  forgotPassword,
  resetPassword,
  getUserProfile,
};
