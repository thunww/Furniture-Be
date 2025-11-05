const cors = require("cors");
require("dotenv").config();

const configCORS = (app) => {
  const corsOptions = {
    origin: process.env.CLIENT_URL || "http://localhost:5173",
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
    exposedHeaders: ["Set-Cookie"],
    optionsSuccessStatus: 200,
  };

  app.options("*", cors(corsOptions));
  app.use(cors(corsOptions));
};

module.exports = configCORS;
