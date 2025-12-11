// src/utils/random.js (CommonJS)
function sixDigitCode() {
  return String(Math.floor(100000 + Math.random() * 900000));
}
module.exports = { sixDigitCode };
