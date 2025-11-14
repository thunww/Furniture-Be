const express = require("express");
const morgan = require("morgan");
const helmet = require("helmet");
const compression = require("compression");
const cookieParser = require("cookie-parser");
const http = require("http");

// Config imports
const { sequelize } = require("./models");
const configCORS = require("./config/cors");
// require("./config/passport"); // ← XÓA DÒNG NÀY (không cần passport cho Google OAuth)

// Routes imports
const authRoutes = require("./routes/authRoutes");
const productRoutes = require("./routes/productRoutes");
const vendorRoutes = require("./routes/vendorRoutes");
const usersRoutes = require("./routes/usersRoutes");
const orderRoutes = require("./routes/orderRoutes");
const cartRoutes = require("./routes/cartRoutes");
const wishlistRoutes = require("./routes/wishlistRoutes");
const reviewRoutes = require("./routes/reviewRoutes");
const paymentRoutes = require("./routes/paymentRoutes");
const notificationRoutes = require("./routes/notificationRoutes");
const addressRoutes = require("./routes/addressRoutes");
const shopRoutes = require("./routes/shopRoutes");
const couponRoutes = require("./routes/couponRoutes");
const chatRoutes = require("./routes/chatRoutes");
const categoryRoutes = require("./routes/categoryRoutes");
const shipperRoutes = require("./routes/shipperRoutes");

// Middleware & Utils
const { handleUploadError } = require("./middleware/upload");
const { setupSocketServer } = require("./websocket/chatSocket");

const app = express();

// SECURITY & PERFORMANCE MIDDLEWARE
app.use(helmet());
app.use(compression());

// CORS phải đứng trước các middleware khác
configCORS(app);

// COOKIE & JSON PARSING
app.use(cookieParser());
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true, limit: "10mb" }));

// LOGGING (chỉ dev mode)
if (process.env.NODE_ENV === "development") {
  app.use(morgan("dev"));
}

// PASSPORT AUTHENTICATION
// app.use(passport.initialize()); // ← XÓA HOẶC COMMENT DÒNG NÀY (không cần passport)

// STATIC FILES
app.use("/uploads", express.static("uploads"));

// API ROUTES
const API_PREFIX = "/api/v1";

app.use(`${API_PREFIX}/auth`, authRoutes);
app.use(`${API_PREFIX}/`, usersRoutes);
app.use(`${API_PREFIX}/products`, productRoutes);
app.use(`${API_PREFIX}/cart`, cartRoutes);
app.use(`${API_PREFIX}/wishlist`, wishlistRoutes);
app.use(`${API_PREFIX}/reviews`, reviewRoutes);
app.use(`${API_PREFIX}/payments`, paymentRoutes);
app.use(`${API_PREFIX}/notifications`, notificationRoutes);
app.use(`${API_PREFIX}/addresses`, addressRoutes);
app.use(`${API_PREFIX}/orders`, orderRoutes);
app.use(`${API_PREFIX}/coupons`, couponRoutes);
app.use(`${API_PREFIX}/categories`, categoryRoutes);
app.use(`${API_PREFIX}/chat`, chatRoutes);
app.use(`${API_PREFIX}/shops`, shopRoutes);
app.use(`${API_PREFIX}/vendor`, vendorRoutes);
app.use(`${API_PREFIX}/shippers`, shipperRoutes);
app.use(`${API_PREFIX}/admin`, usersRoutes);

// ERROR HANDLING

// Upload error handling
app.use(handleUploadError);

// 404 Handler
app.use((req, res, next) => {
  res.status(404).json({
    success: false,
    message: "Route not found",
    path: req.originalUrl,
  });
});

// Global Error Handler
app.use((err, req, res, next) => {
  console.error("Error:", err);

  // Mongoose/Sequelize validation errors
  if (err.name === "SequelizeValidationError") {
    return res.status(400).json({
      success: false,
      message: "Validation error",
      errors: err.errors.map((e) => e.message),
    });
  }

  // JWT errors
  if (err.name === "JsonWebTokenError") {
    return res.status(401).json({
      success: false,
      message: "Invalid token",
    });
  }

  if (err.name === "TokenExpiredError") {
    return res.status(401).json({
      success: false,
      message: "Token expired",
    });
  }

  // Default error
  res.status(err.status || 500).json({
    success: false,
    message: err.message || "Internal Server Error",
    ...(process.env.NODE_ENV === "development" && { stack: err.stack }),
  });
});

// DATABASE CONNECTION
const connectDB = async () => {
  try {
    await sequelize.authenticate();
    console.log("Kết nối database thành công.");

    // Sync models (chỉ dev, KHÔNG dùng production)
    if (process.env.NODE_ENV === "development") {
      await sequelize.sync({ alter: false });
      console.log("Database synced.");
    }
  } catch (err) {
    console.error("Không thể kết nối database:", err);
    process.exit(1);
  }
};

// SERVER STARTUP
const PORT = process.env.PORT || 3000;
const server = http.createServer(app);

// Setup WebSocket
setupSocketServer(server);

// Start server
const startServer = async () => {
  await connectDB();

  server.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
    console.log(`Environment: ${process.env.NODE_ENV || "development"}`);
    console.log(`API: http://localhost:${PORT}/api/v1`);
  });
};

startServer();

// GRACEFUL SHUTDOWN
process.on("SIGTERM", () => {
  console.log("SIGTERM received, closing server...");
  server.close(async () => {
    await sequelize.close();
    console.log("Server closed.");
    process.exit(0);
  });
});

module.exports = app;
