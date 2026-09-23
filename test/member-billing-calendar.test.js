const assert = require("node:assert/strict");
const { test } = require("node:test");
const calendar = require("../src/utils/memberBillingCalendar");

test("renovação rejeita datas inválidas, vencimento fora do ciclo e antecipação ainda não modelada", () => {
  const valid = { anchorDate: "2026-04-10", dueDate: "2026-05-10", paymentDate: "2026-05-15" };
  for (const invalid of [
    { anchorDate: "2026-02-30" }, { dueDate: "2026-02-30" }, { paymentDate: "2026-02-30" },
    { dueDate: "2026-05-11" }, { dueDate: "2026-04-10" }, { dueDate: "2026-03-10" },
    { paymentDate: "2026-05-09" },
  ]) assert.throws(() => calendar.getNextCycle({ ...valid, ...invalid }), RangeError);
});

test("pagamento a partir do oitavo dia inicia novo ciclo sem acumular meses em atraso", () => {
  for (const [paymentDate, nextDueDate] of [
    ["2026-05-18", "2026-06-18"],
    ["2026-05-20", "2026-06-20"],
    ["2026-12-31", "2027-01-31"],
    ["2028-01-31", "2028-02-29"],
  ]) {
    assert.deepEqual(calendar.getNextCycle({ anchorDate: "2026-04-10", dueDate: "2026-05-10", paymentDate }), {
      anchorDate: paymentDate, nextDueDate, restartsCycle: true,
    });
  }
  assert.deepEqual(calendar.getNextCycle({ anchorDate: "2026-01-31", dueDate: "2026-02-28", paymentDate: "2026-03-08" }), {
    anchorDate: "2026-03-08", nextDueDate: "2026-04-08", restartsCycle: true,
  });
});

test("pagamento no vencimento ou até o sétimo dia mantém o ciclo original", () => {
  for (const paymentDate of ["2026-05-10", "2026-05-11", "2026-05-15", "2026-05-17"]) {
    assert.deepEqual(calendar.getNextCycle({ anchorDate: "2026-04-10", dueDate: "2026-05-10", paymentDate }), {
      anchorDate: "2026-04-10", nextDueDate: "2026-06-10", restartsCycle: false,
    });
  }
  assert.deepEqual(calendar.getNextCycle({ anchorDate: "2026-01-31", dueDate: "2026-02-28", paymentDate: "2026-03-07" }), {
    anchorDate: "2026-01-31", nextDueDate: "2026-03-31", restartsCycle: false,
  });
});

test("lembretes vão do primeiro ao sétimo dia e inativação começa no oitavo", () => {
  assert.deepEqual(calendar.getGracePeriod("2026-05-10"), {
    firstReminderDate: "2026-05-11", lastReminderDate: "2026-05-17", inactiveDate: "2026-05-18",
  });
  assert.deepEqual(calendar.getGracePeriod("2026-12-28"), {
    firstReminderDate: "2026-12-29", lastReminderDate: "2027-01-04", inactiveDate: "2027-01-05",
  });
  assert.deepEqual(calendar.getGracePeriod("2028-02-25"), {
    firstReminderDate: "2028-02-26", lastReminderDate: "2028-03-03", inactiveDate: "2028-03-04",
  });
  assert.throws(() => calendar.getGracePeriod("2026-02-30"), RangeError);
  assert.throws(() => calendar.getGracePeriod("9999-12-31"), RangeError);
});

test("rejeita datas inexistentes, timestamps e deslocamentos mensais inválidos", () => {
  for (const value of ["2026-02-29", "2026-04-31", "2026-13-01", "2026-00-10", "2026-01-00", "0000-01-01", "2026-5-10", "2026-05-10T00:00:00Z", null, 42]) {
    assert.throws(() => calendar.getMonthlyDueDate(value, 1), RangeError);
  }
  for (const offset of [0, -1, 1.5, "1", NaN, Infinity, undefined, Number.MAX_SAFE_INTEGER]) {
    assert.throws(() => calendar.getMonthlyDueDate("2026-05-10", offset), RangeError);
  }
  assert.throws(() => calendar.getMonthlyDueDate("9999-12-31", 1), RangeError);
});

test("mensalidade vence no mesmo dia do mês seguinte, inclusive na virada do ano", () => {
  assert.equal(calendar.getMonthlyDueDate("2026-05-10", 1), "2026-06-10");
  assert.equal(calendar.getMonthlyDueDate("2026-12-10", 1), "2027-01-10");
});

test("meses curtos ajustam o vencimento sem perder o dia original", () => {
  for (const [anchor, offset, expected] of [
    ["2026-01-31", 1, "2026-02-28"],
    ["2026-01-31", 2, "2026-03-31"],
    ["2026-01-31", 3, "2026-04-30"],
    ["2026-01-30", 1, "2026-02-28"],
    ["2026-01-30", 2, "2026-03-30"],
    ["2028-01-29", 1, "2028-02-29"],
    ["2028-01-31", 1, "2028-02-29"],
    ["2028-02-29", 12, "2029-02-28"],
    ["2028-02-29", 13, "2029-03-29"],
    ["2099-01-31", 13, "2100-02-28"],
    ["1999-01-31", 13, "2000-02-29"],
  ]) assert.equal(calendar.getMonthlyDueDate(anchor, offset), expected);
});
