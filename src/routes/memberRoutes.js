// src/routes/memberRoutes.js
const express = require("express");
const authMiddleware = require("../middlewares/authMiddleware.js");
const MemberController = require("../controllers/MemberController.js");

const router = express.Router();

router.get("/member/summary", authMiddleware, MemberController.getMemberSummary);
router.get("/member/plans", authMiddleware, MemberController.getMemberPlans);

module.exports = router;