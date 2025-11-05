const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const User = require("../models/user");
const { generateToken } = require("./jwt");

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: process.env.GOOGLE_CALLBACK_URL,
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        // Lấy email và ảnh đại diện từ profile
        const email = profile.emails[0].value;
        const picture = profile.photos?.[0]?.value || null;

        // Kiểm tra user đã tồn tại chưa
        let user = await User.findOne({ where: { email } });

        // Nếu chưa có thì tạo mới
        if (!user) {
          user = await User.create({
            username: profile.displayName,
            email: email,
            is_verified: true,
            status: "active",
            profile_picture: picture,
          });
        }

        // Tạo JWT token
        const token = generateToken(
          { user_id: user.user_id, email: user.email },
          "2h"
        );

        // Trả về user + token cho route callback
        return done(null, { user, token });
      } catch (error) {
        console.error("Google OAuth Error:", error);
        done(error, null);
      }
    }
  )
);

module.exports = passport;
