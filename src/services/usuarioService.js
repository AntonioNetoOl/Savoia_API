import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { query, withTx } from '../config/DB.js';
import { sendMail } from '../utils/mailer.js';
import { sixDigitCode } from '../utils/random.js';
import { onlyDigits } from '../validators/usuarioValidator.js';

const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret';

export async function findByEmailOrCpf(identificador) {
  const isEmail = /@/.test(String(identificador));
  const val = isEmail ? String(identificador).toLowerCase() : onlyDigits(identificador);
  const sql = isEmail
    ? 'SELECT * FROM usuarios WHERE LOWER(email)=LOWER($1) LIMIT 1'
    : 'SELECT * FROM usuarios WHERE REPLACE(cpf, \'.\', \'\') = $1 OR cpf = $1 LIMIT 1';
  const { rows } = await query(sql, [val]);
  return rows[0] || null;
}

export async function createUser({ nome, cpf, email, senha, numero }) {
  const exists = await query(
    'SELECT 1 FROM usuarios WHERE LOWER(email)=LOWER($1) OR cpf=$2 LIMIT 1',
    [String(email).toLowerCase(), cpf]
  );
  if (exists.rowCount) {
    const err = new Error('E-mail ou CPF já cadastrado');
    err.status = 409;
    throw err;
  }
  const hash = await bcrypt.hash(senha, 10);
  const { rows } = await query(
    `INSERT INTO usuarios (nome, cpf, email, senha_hash, numero, email_verificado)
     VALUES ($1,$2,$3,$4,$5,false)
     RETURNING id, nome, email, cpf, email_verificado`,
    [nome, cpf, String(email).toLowerCase(), hash, numero]
  );
  return rows[0];
}

export async function issueVerifyCode(userId, email) {
  const codigo = sixDigitCode();
  const expira = new Date(Date.now() + 15 * 60 * 1000); // 15min
  await withTx(async (c) => {
    await c.query(
      `INSERT INTO email_verifications (id, usuario_id, codigo, expira_em, usado)
       VALUES (gen_random_uuid(), $1, $2, $3, false)`,
      [userId, codigo, expira]
    );
  });
  await sendMail({
    to: email,
    subject: 'Savóia • Código de verificação',
    html: `
      <div style="font-family:system-ui,Segoe UI,Arial">
        <h2>Savóia</h2>
        <p>Seu código de verificação é:</p>
        <div style="font-size:28px;font-weight:800;letter-spacing:4px">${codigo}</div>
        <p>Ele expira em 15 minutos.</p>
      </div>
    `,
  });
  return true;
}

export async function confirmEmail(email, codigo) {
  const { rows } = await query(
    'SELECT id FROM usuarios WHERE LOWER(email)=LOWER($1) LIMIT 1',
    [String(email).toLowerCase()]
  );
  const user = rows[0];
  if (!user) {
    const e = new Error('Usuário não encontrado');
    e.status = 404;
    throw e;
  }
  const { rows: vRows } = await query(
    `SELECT id, expira_em, usado
       FROM email_verifications
      WHERE usuario_id=$1 AND codigo=$2
      ORDER BY criado_em DESC LIMIT 1`,
    [user.id, String(codigo)]
  );
  const ver = vRows[0];
  if (!ver || ver.usado || new Date(ver.expira_em) < new Date()) {
    const e = new Error('Código inválido ou expirado');
    e.status = 400;
    throw e;
  }

  await withTx(async (c) => {
    await c.query('UPDATE email_verifications SET usado=true WHERE id=$1', [ver.id]);
    await c.query('UPDATE usuarios SET email_verificado=true WHERE id=$1', [user.id]);
  });
  return true;
}

export async function login({ identificador, senha }) {
  const user = await findByEmailOrCpf(identificador);
  if (!user) {
    const e = new Error('Credenciais inválidas');
    e.status = 401;
    throw e;
  }
  const ok = await bcrypt.compare(senha, user.senha_hash);
  if (!ok) {
    const e = new Error('Credenciais inválidas');
    e.status = 401;
    throw e;
  }
  if (!user.email_verificado) {
    const e = new Error('E-mail ainda não verificado');
    e.status = 403;
    e.code = 'EMAIL_NOT_VERIFIED';
    throw e;
  }
  const token = jwt.sign({ sub: user.id, email: user.email }, JWT_SECRET, {
    expiresIn: '7d',
  });
  return {
    token,
    usuario: {
      id: user.id,
      nome: user.nome,
      email: user.email,
      status: 'ATIVO',
    },
  };
}
