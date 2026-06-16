// scripts/linkExistingUsersToLegacyMembers.js
require("dotenv").config();

const { pool, withTx } = require("../src/config/DB");
const { linkLegacyMemberForUserInTx, normalizeCpf } = require("../src/services/memberLegacyLinkService");

const shouldApply = process.argv.includes("--apply");
const limitArg = process.argv.find((arg) => arg.startsWith("--limit="));
const limit = limitArg ? Number(limitArg.split("=")[1]) : null;

function formatMode() {
  return shouldApply ? "APLICAÇÃO" : "SIMULAÇÃO";
}

async function findCandidates() {
  const params = [];
  const limitSql = Number.isFinite(limit) && limit > 0 ? `LIMIT ${Math.floor(limit)}` : "";

  const { rows } = await pool.query(
    `SELECT u.id_usuario,
            u.nome,
            u.email,
            u.cpf,
            sl.id_socio_legado,
            sl.numero_socio_legado,
            sl.id_usuario_vinculado
       FROM usuarios u
       JOIN socios_legado sl
         ON sl.cpf_normalizado = regexp_replace(COALESCE(u.cpf, ''), '[^0-9]', '', 'g')
       LEFT JOIN socios s
         ON s.id_usuario = u.id_usuario
      WHERE s.id_socio IS NULL
        AND regexp_replace(COALESCE(u.cpf, ''), '[^0-9]', '', 'g') ~ '^[0-9]{11}$'
        AND (sl.id_usuario_vinculado IS NULL OR sl.id_usuario_vinculado = u.id_usuario)
      ORDER BY u.id_usuario ASC
      ${limitSql}`,
    params
  );

  return rows;
}

async function run() {
  console.log(`🔎 Backfill de sócios legados — modo: ${formatMode()}`);

  if (!shouldApply) {
    console.log("ℹ️ Nenhuma alteração será gravada. Use --apply para aplicar.");
  }

  const candidates = await findCandidates();
  console.log(`📋 Candidatos encontrados: ${candidates.length}`);

  let linked = 0;
  let skipped = 0;
  let failed = 0;

  for (const candidate of candidates) {
    const cpf = normalizeCpf(candidate.cpf);
    const prefix = `usuario=${candidate.id_usuario} cpf=${cpf} socio_legado=${candidate.numero_socio_legado}`;

    if (!shouldApply) {
      console.log(`DRY-RUN ${prefix} → vincularia como legacy_import/inactive`);
      skipped += 1;
      continue;
    }

    try {
      const result = await withTx((client) =>
        linkLegacyMemberForUserInTx(client, {
          userId: candidate.id_usuario,
          cpf,
        })
      );

      if (result.linked) {
        linked += 1;
        console.log(`✅ ${prefix} → vinculado numero_socio=${result.memberNumber}`);
      } else {
        skipped += 1;
        console.log(`⚠️ ${prefix} → não vinculado reason=${result.reason}`);
      }
    } catch (error) {
      failed += 1;
      console.error(`❌ ${prefix} → erro: ${error.message}`);
    }
  }

  console.log("\nResumo:");
  console.log(`- vinculados: ${linked}`);
  console.log(`- ignorados/simulados: ${skipped}`);
  console.log(`- falhas: ${failed}`);

  if (!shouldApply) {
    console.log("\nPara aplicar de verdade, rode:");
    console.log("npm run members:link-legacy:apply");
  }
}

run()
  .catch((error) => {
    console.error("❌ Erro no backfill:", error);
    process.exitCode = 1;
  })
  .finally(async () => {
    await pool.end();
  });
