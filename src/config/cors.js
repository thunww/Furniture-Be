const cors = require("cors");
require("dotenv").config();

const configCORS = (app) => {
  //them de pentest tren burpsuite
  const allowedOrigins = [
    process.env.CLIENT_URL,
    "http://localhost:5173",
    "https://2330ca8c13d9.ngrok-free.app", // test thay đổi khi có tên miền rồi 
  ].filter(Boolean); // bỏ bớt thằng undefined/null

  const corsOptions = {
    origin: allowedOrigins,
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
