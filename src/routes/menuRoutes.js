// src/routes/menuRoutes.js
const express = require("express");
const router = express.Router();

const authMiddleware = require("../middlewares/authMiddleware");
const MenuController = require("../controllers/MenuController");

router.get("/me", authMiddleware, MenuController.getMe);
router.get("/me/payments", authMiddleware, MenuController.getPayments);
router.get("/me/payment-cards", authMiddleware, MenuController.getPaymentCards);
router.get("/me/benefits", authMiddleware, MenuController.getBenefits);

module.exports = router;
