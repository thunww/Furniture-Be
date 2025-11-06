const jwt = require("jsonwebtoken");
require("dotenv").config();

const authMiddleware = (req, res, next) => {
  try {
    // 1️⃣ Lấy token từ cookie hoặc header
    const token =
      req.cookies?.accessToken ||
      (req.headers.authorization?.startsWith("Bearer ")
        ? req.headers.authorization.split(" ")[1]
        : null);

    if (!token) {
      return res.status(401).json({
        message: "Unauthorized - No token provided",
        needLogin: true,
      });
    }

    // 2️⃣ Xác thực token
    let decoded;
    try {
      decoded = jwt.verify(token, process.env.JWT_SECRET);
    } catch (err) {
      // Token hết hạn hoặc sai khóa → báo FE gọi refresh
      if (err.name === "TokenExpiredError") {
        return res.status(401).json({
          message: "Access token expired",
          needRefresh: true,
        });
      }
      return res.status(401).json({
        message: "Invalid token",
        needLogin: true,
      });
    }

    // 3️⃣ Chuẩn hóa dữ liệu user — cho phép dùng cả id & user_id
    req.user = {
      ...decoded,
      id: decoded.id || decoded.user_id,
      user_id: decoded.user_id || decoded.id,
      email: decoded.email,
      roles: decoded.roles || [],
    };

    next();
  } catch (error) {
    console.error("authMiddleware error:", error.message);
    return res.status(500).json({
      message: "Internal authentication error",
    });
  }
};

module.exports = authMiddleware;
