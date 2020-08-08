const { Router } = require("express");
const bcrypt = require("bcryptjs");
const { check, validationResult } = require("express-validator");
const jwt = require("jsonwebtoken");
const config = require("config");
const User = require("../models/User");

const router = Router();

// /api/auth/register
router.post(
  "/register",
  [
    check("email", "Email is wrong").isEmail(),
    check("password", "Minimal length shoud be 6").isLength({ min: 6 }),
  ],
  async (req, res) => {
    try {
      console.log(req.body);
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res
          .status(400)
          .json({ errors: errors.array(), message: "The Data is wrong" });
      }
      const { email, password } = req.body;
      const candidate = await User.findOne({ email });
      if (candidate) {
        res.status(400).json({ message: " The User exist" });
      }
      const hashedPassword = await bcrypt.hash(password, 12);
      const user = new User({ email: email, password: hashedPassword });
      await user.save();
      res.status(201).json({ message: "User has been created" });
    } catch (e) {
      res.status(500).json({ message: "Somthing is wrong, try later" });
    }
  }
);

// /api/auth/login
router.post(
  "/login",
  [
    check("email", "Email is wrong").normalizeEmail().isEmail(),
    check("password", "Entrie Pass").exists(),
  ],
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res
          .status(400)
          .json({ errors: errors.array(), message: "The Data is wrong" });
      }
      const { email, password } = req.body;
      const user = await User.findOne({ email });
      if (!user) {
        return res.status(400).json({ message: "User dot't find" });
      }
      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) {
        return res.status(400).json({ message: "pass is wrong, try again" });
      }

      const token = jwt.sign({ userId: user.id }, config.get("jwtSecret"), {
        expiresIn: "1h",
      });
      res.json({ token, userId: user.id });
    } catch (e) {
      res.status(500).json({ message: "Somthing is wrong, try later" });
    }
  }
);

module.exports = router;
