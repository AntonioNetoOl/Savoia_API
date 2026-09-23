function formatDate(date) {
  const value = date.toISOString();
  if (!/^(?!0000)\d{4}-/.test(value)) throw new RangeError("Data fora do intervalo 0001–9999.");
  return value.slice(0, 10);
}

function parseDate(value) {
  if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(value)) {
    throw new RangeError("Use uma data válida no formato AAAA-MM-DD.");
  }
  const date = new Date(`${value}T00:00:00.000Z`);
  if (formatDate(date) !== value) throw new RangeError("Data inexistente.");
  return date;
}

function getMonthlyDueDate(anchorDate, monthOffset) {
  const date = parseDate(anchorDate);
  if (!Number.isSafeInteger(monthOffset) || monthOffset < 1) {
    throw new RangeError("O deslocamento mensal deve ser um inteiro positivo.");
  }
  const originalDay = date.getUTCDate();
  date.setUTCMonth(date.getUTCMonth() + monthOffset, 1);
  const lastDay = new Date(date);
  lastDay.setUTCMonth(lastDay.getUTCMonth() + 1, 0);
  date.setUTCDate(Math.min(originalDay, lastDay.getUTCDate()));
  return formatDate(date);
}

function getGracePeriod(dueDate) {
  const due = parseDate(dueDate);
  const afterDays = (days) => {
    const date = new Date(due);
    date.setUTCDate(date.getUTCDate() + days);
    return formatDate(date);
  };
  return { firstReminderDate: afterDays(1), lastReminderDate: afterDays(7), inactiveDate: afterDays(8) };
}

function getNextCycle({ anchorDate, dueDate, paymentDate }) {
  const anchor = parseDate(anchorDate);
  const due = parseDate(dueDate);
  parseDate(paymentDate);
  const monthOffset = (due.getUTCFullYear() - anchor.getUTCFullYear()) * 12 + due.getUTCMonth() - anchor.getUTCMonth();
  if (getMonthlyDueDate(anchorDate, monthOffset) !== dueDate) {
    throw new RangeError("O vencimento não pertence ao ciclo informado.");
  }
  if (paymentDate < dueDate) throw new RangeError("Pagamento antecipado está fora do escopo deste cálculo.");
  if (paymentDate >= getGracePeriod(dueDate).inactiveDate) {
    return { anchorDate: paymentDate, nextDueDate: getMonthlyDueDate(paymentDate, 1), restartsCycle: true };
  }
  return { anchorDate, nextDueDate: getMonthlyDueDate(anchorDate, monthOffset + 1), restartsCycle: false };
}

module.exports = { getMonthlyDueDate, getGracePeriod, getNextCycle };
