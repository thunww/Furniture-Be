const { verifyToken } = require("../config/jwt");

const authMiddleware = (req, res, next) => {
  try {
    // Đọc token từ cookie
    const token = req.cookies?.accessToken;

    if (!token) {
      return res.status(401).json({
        message: "Unauthorized - No token provided",
        needLogin: true,
      });
    }

    const decoded = verifyToken(token);

    if (!decoded) {
      return res.status(401).json({
        message: "Invalid or expired token",
        needRefresh: true,
      });
    }

    // Chuẩn hóa ID người dùng
    req.user = {
      id: decoded.user_id || decoded.id,
      email: decoded.email,
      roles: decoded.roles || [],
    };

    next();
  } catch (error) {
    console.error("authMiddleware error:", error.message);
    return res.status(401).json({
      message: "Invalid token",
      needRefresh: true,
    });
  }
};

module.exports = authMiddleware;
