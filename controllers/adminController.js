const adminModel = require("../models/admin-model");
const bcrypt = require('bcrypt');
const { genrateToken} = require("../utils/genrateTokenAdmin");

module.exports.loginUser = async function (req, res) {
  try {  
    let { email, password } = req.body;
    const admin = await adminModel.findOne({ Email: email });

    if (!admin) {
      return res.json({ success: false, message: 'Invalid credentials' });
    }

    let isMatch = await bcrypt.compare(password, admin.Password);

    if (!isMatch) {
      return res.json({ success: false, message: 'Invalid credentials' });
    }

    const token = genrateToken(admin);
    res.cookie("token", token, {
      httpOnly: true,        // For security, make sure the cookie is not accessible via JavaScript
      secure: true,          // Only send the cookie over HTTPS
      sameSite: 'None',      // Allows cross-origin cookies
      
    });
    return res.json({ success: true, message: 'Login successful' });

  } catch (e) {
    console.log(e);
    return res.status(500).send("Server Error");
  }
};
