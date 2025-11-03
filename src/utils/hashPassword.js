const bcrypt = require("bcrypt");

/**
 * Hàm băm mật khẩu với bycrypt
 * @param {string} password - mật khẩu gốc
 * @returns {Promise<string>} - chuỗi băm 
 */
const hashPassword = async(password) => {
  const saltRounds = 10;
  const hashedPassword= await bcrypt.hash(password, saltRounds);
  return hashedPassword;
};

/**
 * Hàm so sánh mật khẩu (dạng đơn giản - không có salt)
 * @param {string} password - mật khẩu người dùng nhập
 * @param {string} hashedPassword - mật khẩu đã băm lưu trong DB
 * @returns {Promise<boolean>} - kết quả so sánh
 */
const comparePassword = async (password, hashedPassword) => {
  const isMatch = await bcrypt.compare(password, hashedPassword);
  return isMatch;
};

module.exports = {
  hashPassword,
  comparePassword,
};
