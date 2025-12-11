const express = require("express");
const router = express.Router();

const UsuarioController = require("../controllers/UsuarioController.js");

router.post("/login", UsuarioController.loginUsuario);

router.post("/confirmacao/enviar",  UsuarioController.reenviarCodigo);   
router.post("/confirmacao/validar", UsuarioController.confirmarCadastro); 

router.post("/auth/forgot/start",  UsuarioController.forgotStart);

router.post("/auth/forgot/verify", UsuarioController.forgotVerify);

router.post("/auth/forgot/reset",  UsuarioController.forgotReset);

module.exports = router;
