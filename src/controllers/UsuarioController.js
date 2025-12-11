// src/controllers/UsuarioController.js
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const db = require("../config/DB");
const {
  schemaLogin,
  isValidEmail,
  onlyDigits,
  validateCadastro,
} = require("../validators/usuarioValidator");
const { sendMail } = require("../utils/mailer");
const { sixDigitCode } = require("../utils/random");

const JWT_SECRET = process.env.JWT_SECRET || "dev_secret";

const CODE_TTL_MIN = 15;
const MAX_ATTEMPTS = 5;
const RESEND_COOLDOWN_SEC = 30;

/* Utils ------------------------------------------------------------------ */
function normalizeEmail(e) {
  return String(e || "").toLowerCase().replace(/\s+/g, "").trim();
}

async function findUserByEmailOrCpf(identificador) {
  const isEmail = /@/.test(String(identificador));
  const val = isEmail ? normalizeEmail(identificador) : onlyDigits(identificador);

  const sql = isEmail
    ? "SELECT * FROM usuarios WHERE email=$1 LIMIT 1"
    : "SELECT * FROM usuarios WHERE REPLACE(REPLACE(cpf,'.',''), '-', '')=$1 OR cpf=$1 LIMIT 1";

  const { rows } = await db.query(sql, [val]);
  return rows[0] || null;
}

/* E-mail helpers ---------------------------------------------------------- */
function emailCodigoTemplate({ titulo, codigo, ttlMin }) {
  return `
    <div style="font-family:system-ui,Segoe UI,Arial">
      <h2 style="margin:0 0 8px 0">${titulo}</h2>
      <p style="margin:0 0 8px 0">Seu código é:</p>
      <div style="font-size:28px;font-weight:800;letter-spacing:4px">${codigo}</div>
      <p style="margin:8px 0 0 0">Ele expira em <strong>${ttlMin}</strong> minutos.</p>
    </div>
  `;
}

// Cadastro: verificação de e-mail
async function enviarEmailCodigoVerificacao(email, codigo) {
  await sendMail({
    to: email,
    subject: "Savóia • Código de verificação de e-mail",
    html: emailCodigoTemplate({ titulo: "Savóia", codigo, ttlMin: CODE_TTL_MIN }),
  });
}

// Esqueci minha senha: recuperação
async function enviarEmailRecuperacaoSenha(email, codigo) {
  await sendMail({
    to: email,
    subject: "Savóia • Recuperação de senha",
    html: emailCodigoTemplate({ titulo: "Recuperação de senha", codigo, ttlMin: CODE_TTL_MIN }),
  });
}

/* ENVIAR / REENVIAR CÓDIGO (CADASTRO) ------------------------------------ */
async function enviarOuReenviarCodigo(req, res, next) {
  try {
    const email = normalizeEmail(req.body?.email);
    if (!isValidEmail(email)) return res.status(400).json({ erro: "E-mail inválido" });

    const veioPayload =
      req.body?.nome || req.body?.cpf || req.body?.senha || req.body?.numero;

    let payload = null;

    if (veioPayload) {
      const { ok, errors, cpf } = validateCadastro(req.body || {});
      if (!ok) return res.status(400).json({ erro: "Dados inválidos", detalhes: errors });

      const dup = await db.query(
        `SELECT
           EXISTS(SELECT 1 FROM usuarios WHERE email=$1) AS email,
           EXISTS(SELECT 1 FROM usuarios WHERE cpf=$2)   AS cpf`,
        [email, cpf]
      );
      const flags = dup.rows[0];

      if (flags.email || flags.cpf) {
        return res.status(409).json({
          erro:
            flags.email && flags.cpf
              ? "E-mail e CPF já cadastrados."
              : flags.email
              ? "Este E-mail já está vinculado à um usuário."
              : "Este CPF já está vinculado à um usuário.",
          campos: { email: flags.email, cpf: flags.cpf },
        });
      }

      const senhaHash = await bcrypt.hash(String(req.body.senha), 10);
      const nome = String(req.body.nome).trim();
      const numero = String(req.body.numero).trim();

      payload = { nome, cpf, email, numero, senha_hash: senhaHash };
    }

    // Anti-spam simples
    const tipo = "cadastro";
    const cooldown = await db.query(
      `SELECT 1
         FROM verificacoes_email
        WHERE email=$1 AND tipo=$2
          AND criado_em > (NOW() - make_interval(secs => $3))
        LIMIT 1`,
      [email, tipo, RESEND_COOLDOWN_SEC]
    );
    if (cooldown.rowCount) {
      return res
        .status(429)
        .json({ erro: "Aguarde alguns segundos antes de solicitar novo código." });
    }

    const codigo = sixDigitCode();
    const expira = new Date(Date.now() + CODE_TTL_MIN * 60 * 1000);

    await db.query("BEGIN");
    try {
      // Só cria/atualiza sessão quando há payload (primeiro envio do cadastro)
      if (payload) {
        await db.query("DELETE FROM sessoes_cadastro WHERE email=$1", [email]);
        await db.query(
          `INSERT INTO sessoes_cadastro (nome, cpf, email, senha_hash, numero, usado, criado_em, payload_json)
           VALUES ($1, $2, $3, $4, $5, false, NOW(), $6::jsonb)`,
          [
            payload.nome,
            payload.cpf,
            email,
            payload.senha_hash,
            payload.numero,
            JSON.stringify(payload),
          ]
        );
      }

      await db.query(
        `INSERT INTO verificacoes_email (id_usuario, email, tipo, codigo, expira_em, usado, tentativas, ip, user_agent, criado_em)
         VALUES (NULL, $1, $2, $3, $4, false, 0, $5, $6, NOW())`,
        [email, tipo, codigo, expira, req.ip || null, String(req.headers["user-agent"] || "") || null]
      );

      await db.query("COMMIT");
    } catch (e) {
      await db.query("ROLLBACK");
      throw e;
    }

    // Log bonito no console (cadastro)
    console.log(`[VERIFY] para=${email} | codigo=${codigo} | expira=${expira.toISOString()}`);

    try {
      await enviarEmailCodigoVerificacao(email, codigo);
      return res.json({ message: "Código enviado" });
    } catch {
      return res.json({ message: "Código gerado (dev / sem SMTP)." });
    }
  } catch (err) {
    next(err);
  }
}

/* CONFIRMAR CÓDIGO + CRIAR USUÁRIO --------------------------------------- */
async function confirmarCadastro(req, res, next) {
  try {
    const email = normalizeEmail(req.body?.email);
    const codigo = String(req.body?.codigo || "");

    if (!isValidEmail(email) || !/^\d{6}$/.test(codigo)) {
      return res.status(400).json({ erro: "Dados inválidos" });
    }

    const tipo = "cadastro";
    const { rows: verifs } = await db.query(
      `SELECT id, codigo, expira_em, usado, tentativas
         FROM verificacoes_email
        WHERE email=$1
          AND tipo=$2
          AND usado = false
          AND expira_em > NOW()
        ORDER BY criado_em DESC
        LIMIT 1`,
      [email, tipo]
    );
    const verif = verifs[0];

    if (!verif) {
      return res
        .status(410)
        .json({ erro: "Código não encontrado ou expirado. Reenvie o código." });
    }

    if (Number(verif.tentativas) >= MAX_ATTEMPTS) {
      return res.status(429).json({ erro: "Muitas tentativas. Reenvie um novo código." });
    }

    if (String(verif.codigo) !== codigo) {
      await db.query("UPDATE verificacoes_email SET tentativas = tentativas + 1 WHERE id=$1", [
        verif.id,
      ]);
      return res.status(400).json({ erro: "Código inválido." });
    }

    const { rows: sessRows } = await db.query(
      `SELECT *
         FROM sessoes_cadastro
        WHERE email=$1
        ORDER BY criado_em DESC
        LIMIT 1`,
      [email]
    );
    const sess = sessRows[0];
    if (!sess) {
      return res.status(410).json({ erro: "Sessão de cadastro expirada. Reenvie o código." });
    }

    const data = sess.payload_json || {
      nome: sess.nome,
      cpf: sess.cpf,
      email: sess.email,
      numero: sess.numero,
      senha_hash: sess.senha_hash,
    };

    await db.query("BEGIN");
    try {
      const ins = await db.query(
        `INSERT INTO usuarios
           (nome, cpf, email, senha_hash, numero, status, origem_cadastro, datacriacao, email_verificado, verificado_em)
         VALUES
           ($1,$2,$3,$4,$5,'PENDENTE_VERIFICACAO','APP', NOW(), true, NOW())
         ON CONFLICT (email) DO NOTHING
         RETURNING id_usuario, nome, email, status, email_verificado`,
        [data.nome, data.cpf, data.email, data.senha_hash, data.numero]
      );

      if (ins.rowCount === 0) {
        await db.query("ROLLBACK");
        return res.status(409).json({ erro: "Usuário já existe." });
      }

      await db.query("UPDATE verificacoes_email SET usado=true WHERE id=$1", [verif.id]);
      await db.query("UPDATE sessoes_cadastro SET usado=true WHERE email=$1", [email]);

      await db.query("COMMIT");

      const user = ins.rows[0];
      return res.json({
        message: "Cadastro concluído.",
        usuario: {
          id: user.id_usuario,
          nome: user.nome,
          email: user.email,
          status: user.status,
          email_verificado: user.email_verificado,
        },
      });
    } catch (e) {
      await db.query("ROLLBACK");
      if (e && e.code === "23505") {
        return res.status(409).json({ erro: "Usuário já existe." });
      }
      throw e;
    }
  } catch (err) {
    next(err);
  }
}

/* LEGADO ------------------------------------------------------------------ */
async function cadastrarUsuario(req, res) {
  try {
    const { ok, errors, cpf } = validateCadastro(req.body || {});
    if (!ok) return res.status(400).json({ erro: "Dados inválidos", detalhes: errors });

    const nome = String(req.body.nome).trim();
    const email = normalizeEmail(req.body.email);
    const senha = String(req.body.senha);
    const numero = String(req.body.numero).trim();

    const existe = await db.query(
      "SELECT 1 FROM usuarios WHERE cpf=$1 OR email=$2 LIMIT 1",
      [cpf, email]
    );
    if (existe.rowCount) {
      return res.status(409).json({ erro: "Usuário já cadastrado com este CPF ou e-mail." });
    }

    const senhaHash = await bcrypt.hash(senha, 10);
    await db.query(
      `INSERT INTO usuarios
         (nome, cpf, email, senha_hash, numero, status, origem_cadastro, datacriacao, email_verificado)
       VALUES
         ($1,$2,$3,$4,$5,'PENDENTE_VERIFICACAO','APP', NOW(), false)`,
      [nome, cpf, email, senhaHash, numero]
    );

    return res.status(201).json({ message: "Cadastro realizado (LEGADO)." });
  } catch (err) {
    console.error("❌ ERRO AO CADASTRAR (LEGADO):", err);
    res.status(500).json({ erro: "Erro interno do servidor." });
  }
}

/* Login ------------------------------------------------------------------- */
async function loginUsuario(req, res) {
  try {
    const { error } = schemaLogin.validate(req.body);
    if (error) return res.status(400).json({ erro: error.details[0].message });

    const { identificador, senha } = req.body;
    const usuario = await findUserByEmailOrCpf(identificador);
    if (!usuario) return res.status(404).json({ erro: "Usuário não encontrado." });

    const ok = await bcrypt.compare(String(senha), usuario.senha_hash);
    if (!ok) return res.status(401).json({ erro: "Senha incorreta." });

    if (!usuario.email_verificado) {
      return res.status(403).json({ erro: "E-mail não verificado." });
    }

    const token = jwt.sign(
      { id: usuario.id_usuario, nome: usuario.nome, email: usuario.email },
      JWT_SECRET,
      { expiresIn: "8h" }
    );

    return res.json({
      message: "Login efetuado com sucesso!",
      token,
      usuario: {
        id: usuario.id_usuario,
        nome: usuario.nome,
        email: usuario.email,
        status: usuario.status,
      },
    });
  } catch (err) {
    console.error("❌ ERRO AO EFETUAR LOGIN:", err);
    res.status(500).json({ erro: "Erro interno do servidor." });
  }
}

/* ESQUECI MINHA SENHA ----------------------------------------------------- */

// Inicia a recuperação: gera e registra o código
async function iniciarRecuperacaoSenha(req, res, next) {
  try {
    const normEmail = String(req.body?.email || "").toLowerCase().trim();
    if (!isValidEmail(normEmail)) return res.status(400).json({ erro: "E-mail inválido" });

    // precisa existir usuário
    const u = await db.query(
      `SELECT id_usuario
         FROM usuarios
        WHERE lower(regexp_replace(email, '\\s+', '', 'g')) = $1
        LIMIT 1`,
      [normEmail]
    );
    if (u.rowCount === 0) return res.status(404).json({ erro: "Usuário não encontrado." });
    const idUsuario = u.rows[0].id_usuario;

    // cooldown
    const tipo = "recuperacao";
    const cd = await db.query(
      `SELECT 1
         FROM verificacoes_email
        WHERE lower(regexp_replace(email, '\\s+', '', 'g')) = $1
          AND tipo=$2
          AND criado_em > (NOW() - make_interval(secs => $3))
        LIMIT 1`,
      [normEmail, tipo, RESEND_COOLDOWN_SEC]
    );
    if (cd.rowCount) {
      return res
        .status(429)
        .json({ erro: "Aguarde alguns segundos antes de solicitar novo código." });
    }

    const codigo = sixDigitCode();
    const expira = new Date(Date.now() + CODE_TTL_MIN * 60 * 1000);

    await db.query(
      `INSERT INTO verificacoes_email
         (id_usuario, email, tipo, codigo, expira_em, usado, tentativas, ip, user_agent, criado_em)
       VALUES
         ($1, $2, $3, $4, $5, false, 0, $6, $7, NOW())`,
      [
        idUsuario,
        normEmail,
        tipo,
        codigo,
        expira,
        req.ip || null,
        String(req.headers["user-agent"] || "") || null,
      ]
    );

    // Log bonito no console (recuperação)
    console.log(
      `[FORGOT] para=${normEmail} | codigo=${codigo} | expira=${expira.toISOString()}`
    );

    try {
      await enviarEmailRecuperacaoSenha(normEmail, codigo);
      return res.json({ message: "Código enviado.", sent: true });
    } catch {
      return res.json({ message: "Código gerado (dev / sem SMTP).", sent: false });
    }
  } catch (err) {
    next(err);
  }
}

// Valida o código e devolve um token curto para resetar a senha
// Valida o código e (agora) marca como usado, depois devolve um token curto
async function verificarCodigoRecuperacao(req, res, next) {
  try {
    const normEmail = normalizeEmail(req.body?.email);
    const codigo    = String(req.body?.codigo || "");

    if (!isValidEmail(normEmail) || !/^\d{6}$/.test(codigo)) {
      return res.status(400).json({ erro: "Dados inválidos" });
    }

    const tipo = "recuperacao";
    const { rows } = await db.query(
      `SELECT id, id_usuario, codigo, expira_em, usado, tentativas
         FROM verificacoes_email
        WHERE lower(regexp_replace(email, '\\s+', '', 'g')) = $1
          AND tipo = $2
          AND usado = false
          AND expira_em > NOW()
        ORDER BY criado_em DESC
        LIMIT 1`,
      [normEmail, tipo]
    );
    const verif = rows[0];

    if (!verif) {
      return res.status(410).json({ erro: "Código não encontrado ou expirado. Reenvie o código." });
    }

    if (Number(verif.tentativas) >= MAX_ATTEMPTS) {
      return res.status(429).json({ erro: "Muitas tentativas. Reenvie um novo código." });
    }

    if (String(verif.codigo) !== codigo) {
      await db.query("UPDATE verificacoes_email SET tentativas = tentativas + 1 WHERE id=$1", [verif.id]);
      return res.status(400).json({ erro: "Código inválido." });
    }

    await db.query("UPDATE verificacoes_email SET usado=true WHERE id=$1", [verif.id]);

    // Gera token curto para o /forgot/reset
    const token = jwt.sign(
      { kind: "pwdreset", email: normEmail, id_usuario: verif.id_usuario, verif_id: verif.id },
      JWT_SECRET,
      { expiresIn: "15m" }
    );

    return res.json({ message: "Código validado.", token });
  } catch (err) {
    next(err);
  }
}

// Aplica a nova senha usando o token de verificação
async function resetarSenha(req, res, next) {
  try {
    const token = String(req.body?.token || "");
    const nova = String(req.body?.nova_senha || "");
    if (nova.length < 6) return res.status(422).json({ erro: "Senha muito curta (mín. 6)." });

    let payload;
    try {
      payload = jwt.verify(token, JWT_SECRET);
    } catch {
      return res.status(401).json({ erro: "Token inválido ou expirado." });
    }
    if (payload?.kind !== "pwdreset" || !payload?.id_usuario) {
      return res.status(401).json({ erro: "Token inválido." });
    }

    const hash = await bcrypt.hash(nova, 10);
    await db.query("UPDATE usuarios SET senha_hash=$1 WHERE id_usuario=$2", [
      hash,
      payload.id_usuario,
    ]);

    return res.json({ message: "Senha atualizada!" });
  } catch (err) {
    next(err);
  }
}

module.exports = {
  reenviarCodigo: enviarOuReenviarCodigo,
  confirmarCodigo: confirmarCadastro,

  iniciarCadastro: enviarOuReenviarCodigo,
  confirmarCadastro,

  forgotStart: iniciarRecuperacaoSenha,
  forgotVerify: verificarCodigoRecuperacao,
  forgotReset: resetarSenha,

  cadastrarUsuario,
  loginUsuario,
};
