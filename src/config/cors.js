const cors = require("cors");
require("dotenv").config();

const configCORS = (app) => {
  const allowedOrigins = [
    "http://localhost:5173",
    "http://localhost:3000",
    process.env.CLIENT_URL,
  ].filter(Boolean);

  const corsOptions = {
    origin: allowedOrigins,
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  };

  app.use(cors(corsOptions));
  app.options("*", cors(corsOptions)); // ✅ Chrome cần preflight OPTIONS
};

module.exports = configCORS;
