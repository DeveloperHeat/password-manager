const trainingPasswords = [
  "u$9Y!fC7qLp1",
  "r3E%vT6#xW2@",
  "X9*bD3#mK!7p",
  "zL4@q1W#8p$A",
  "aF2^gB5@tX3!",
  "P#8mL!r1q$E4",
  "eZ6@tY9#pW1%",
  "M!7vK#4a$Xp2",
  "nQ1$zR8@cT5^",
  "dB3^mL6!qX@9",
];

async function getVault() {
  return vaultData;
}

async function saveVault(data) {
  const encrypted = await encryptData(data, masterPassword);
  localStorage.setItem("vaultx", JSON.stringify(encrypted));
}

async function addPassword() {
  const site = document.getElementById("site").value;
  const username = document.getElementById("username").value;
  const password = document.getElementById("password").value;

  vaultData.push({ site, username, password });
  await saveVault(vaultData);
  await displayVault();
}

async function displayVault() {
  const list = document.getElementById("password-list");
  list.innerHTML = "";

  if (vaultData && vaultData.length > 0) {
    vaultData.forEach((entry) => {
      const li = document.createElement("li");
      li.textContent = `${entry.site} — ${entry.username} — ${entry.password}`;
      list.appendChild(li);
    });
  } else if (masterPassword) {
    list.innerHTML = "<p>No passwords stored yet.</p>";
  }
}

function isFakeRandom(pw) {
    const keyboardPatterns = ["qwerty", "asdf", "zxcv", "1234", "7890"];
    return keyboardPatterns.some(seq => pw.toLowerCase().includes(seq)) ||
           /[a-z]{3,}\d{2,}/.test(pw);
}


function isVariant(base, password) {
  const variations = ["", "123", "1234", "!", "@", "1!", "2024", "2025"];
  return variations.some((v) => password.toLowerCase() === base + v);
}

function isInDictionary(pw) {
  const lowerPw = pw.toLowerCase();

  for (const word of commonPasswords) {
    if (lowerPw === word || isVariant(word, pw)) return true;
  }

  for (const pattern of keyboardPatterns) {
    if (pattern.includes(lowerPw) || lowerPw.includes(pattern)) return true;
  }

  for (const name of nameVariations) {
    if (lowerPw.includes(name)) return true;
  }

  for (const year of yearRange) {
    if (lowerPw.endsWith(year)) return true;
  }

  return false;
}

function hasPredictablePattern(pw) {
  const patterns = [
    /^[A-Z][a-z]+\d{2,4}[\W_]?$/,
    /^[a-z]{4,}\d{2,4}$/,
    /^\w{3,6}\d{1,4}$/,
    /^.{1,3}123$/,
    /^password[\W\d]*$/i,
  ];

  return patterns.some((pattern) => pattern.test(pw));
}

function ruleBasedGuessable(pw) {
  const lowered = pw.toLowerCase();

  const commonRoots = [
    "password",
    "welcome",
    "letmein",
    "iloveyou",
    "admin",
    "vaultx",
  ];
  const suffixes = [
    "123",
    "1234",
    "12345",
    "2023",
    "2024",
    "2025",
    "!",
    "@",
    "1!",
  ];

  return commonRoots.some((root) => {
    return suffixes.some((suffix) => pw.toLowerCase() === root + suffix);
  });
}

function aiCrackable(pw) {
    const entropy = calculateEntropy(pw);
  
     // Consider as uncrackable if long, complex, and high entropy
  if (
    entropy >= 120 &&
    pw.length >= 20 &&
    /[a-z]/.test(pw) &&
    /[A-Z]/.test(pw) &&
    /\d/.test(pw) &&
    /[\W_]/.test(pw)
  ) {
    return false;
  }

    // Detect repeating character chunks (like DaaD, XxXx)
    if (/(..).*\1/.test(pw)) return true;

    // If symbols are grouped together, it's likely user-generated
    if (/[\W_]{2,}/.test(pw)) return true;

    // If it ends in a digit-symbol combo, simulate AI-crackable
    if (/\d{2,4}[\W_]+$/.test(pw)) return true;

    // Penalize passwords with capitalized chunks at ends or middle (human habit)
    if (/[A-Z]{2,}/.test(pw) || /^[A-Z]/.test(pw) || /[A-Z]$/.test(pw)) return true;

    // Final entropy fallback
    if (entropy < 100 && pw.length <= 16) return true;

    return false;
}




function generatePassword() {
  const length = Math.max(20, parseInt(document.getElementById("gen-length").value)); // minimum 20
  const includeSymbols = document.getElementById("gen-symbols").checked;
  const includeNumbers = document.getElementById("gen-numbers").checked;
  const includeUppercase = document.getElementById("gen-uppercase").checked;

  const lowercase = "abcdefghijklmnopqrstuvwxyz";
  const uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  const numbers = "0123456789";
  const symbols = "!@#$%^&*()_+[]{}|;:,.<>?";

  let charset = lowercase;
  if (includeUppercase) charset += uppercase;
  if (includeNumbers) charset += numbers;
  if (includeSymbols) charset += symbols;

  if (charset.length === 0) {
    alert("Please select at least one character set!");
    return;
  }

  // Ensure at least one char from each selected group
  const requiredChars = [];
  if (includeUppercase) requiredChars.push(randomChar(uppercase));
  if (includeNumbers) requiredChars.push(randomChar(numbers));
  if (includeSymbols) requiredChars.push(randomChar(symbols));
  requiredChars.push(randomChar(lowercase)); // always include lowercase

  let password = requiredChars.join("");

  while (password.length < length) {
    password += randomChar(charset);
  }

  // Shuffle to randomize positions
  password = shuffle(password);

  document.getElementById("generated-password").textContent = password;
  const pwInput = document.getElementById("password");
  if (pwInput) pwInput.value = password;
}

function randomChar(str) {
  const randomIndex = crypto.getRandomValues(new Uint32Array(1))[0] % str.length;
  return str.charAt(randomIndex);
}

function shuffle(str) {
  const arr = str.split("");
  for (let i = arr.length - 1; i > 0; i--) {
    const j = crypto.getRandomValues(new Uint32Array(1))[0] % (i + 1);
    [arr[i], arr[j]] = [arr[j], arr[i]];
  }
  return arr.join("");
}


const commonPasswords = [
  "password",
  "123456",
  "qwerty",
  "letmein",
  "admin",
  "vaultx",
  "iloveyou",
  "abc123",
  "login",
  "welcome",
  "111111",
  "000000",
  "guest",
  "user",
  "secret",
  "sunshine",
  "dragon",
  "freedom",
  "believe",
  "forever",
];

const keyboardPatterns = [
  "qwerty",
  "asdfghjkl",
  "zxcvbnm",
  "1234567890",
  "qazwsxedcrfv",
  "plokmijnuhbygvft",
  "mnbvcxzlkjhgfdsaqwertyuiop",
];

const yearRange = new Array(51)
  .fill(null)
  .map((_, i) => (new Date().getFullYear() - 50 + i).toString());

const nameVariations = [
  "john",
  "jane",
  "david",
  "sarah",
  "michael",
  "emily",
  "johnny",
  "janie",
  "dave",
  "sara",
  "mike",
  "em",
  "johny1",
  "jane2",
  "david3",
  "sarah4",
];

const specialChars = "!@#$%^&*()_+=-`~[]\\{}|;':\",./<>?";
const numbersChars = "0123456789";
const lowerCaseChars = "abcdefghijklmnopqrstuvwxyz";
const upperCaseChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

function calculateEntropy(password) {
  let charsetSize = 0;

  if (/[a-z]/.test(password)) charsetSize += 26;
  if (/[A-Z]/.test(password)) charsetSize += 26;
  if (/[0-9]/.test(password)) charsetSize += 10;
  if (/[^a-zA-Z0-9]/.test(password)) charsetSize += 32; // Punctuation/symbols

  if (charsetSize === 0) return 0;

  return password.length * Math.log2(charsetSize);
}

function estimateCrackTime(entropy) {
  const guessesPerSecond = 1e10; // 10 billion guesses/sec
  const totalGuesses = Math.pow(2, entropy);
  const seconds = totalGuesses / guessesPerSecond;

  if (seconds < 1) return "< 1 second";
  if (seconds < 60) return `${seconds.toFixed(2)} seconds`;
  const minutes = seconds / 60;
  if (minutes < 60) return `${minutes.toFixed(2)} minutes`;
  const hours = minutes / 60;
  if (hours < 24) return `${hours.toFixed(2)} hours`;
  const days = hours / 24;
  if (days < 365) return `${days.toFixed(2)} days`;
  const years = days / 365;
  return `${years.toFixed(2)} years`;
}

function entropyRating(entropy) {
  if (entropy < 28) return "Very Weak";
  if (entropy < 36) return "Weak";
  if (entropy < 60) return "Moderate";
  if (entropy < 128) return "Strong";
  return "Very Strong";
}

function testPassword() {
  const pw = document.getElementById("test-password").value;

  if (!pw) {
    document.getElementById("crack-result").textContent = "Enter a password.";
    return;
  }

  if (isInDictionary(pw)) {
    document.getElementById("crack-result").innerHTML =
      `This password is vulnerable to a **dictionary attack**.<br>` +
      `Estimated crack time: < 1 second<br>` +
      `Strength rating: Very Weak`;

    return;
  }

  if (hasPredictablePattern(pw)) {
    document.getElementById("crack-result").innerHTML =
      `Your password follows a **predictable pattern** attackers often exploit.<br>` +
      `Estimated crack time: < 5 seconds<br>` +
      `Strength rating: Weak`;
    return;
  }

  if (ruleBasedGuessable(pw)) {
    document.getElementById("crack-result").innerHTML =
      `This strong-looking password is **vulnerable to rule-based cracking**.<br>` +
      `Estimated crack time: < 10 seconds<br>` +
      `Strength rating: Weak (by AI rule-based analysis)`;
    return;
  }
  
  if (aiCrackable(pw)) {
    document.getElementById("crack-result").innerHTML =
        `This password is **crackable by AI models trained on leaked datasets**.<br>` +
        `Estimated crack time: < 2 minutes<br>` +
        `Strength rating: Moderate (AI attack mode)`;
    return;
  }
  
  if (aiCrackable(pw) || isFakeRandom(pw)) {
    showCracked("This password looks random, but is crackable using AI pattern recognition.", "3 hours", "Moderate");
  }



  const entropy = calculateEntropy(pw);
  const time = estimateCrackTime(entropy);
  const rating = entropyRating(entropy);

  document.getElementById("crack-result").innerHTML =
    `Entropy: ${entropy.toFixed(2)} bits<br>` +
    `Estimated crack time: ${time}<br>` +
    `Strength rating: ${rating}`;
}

window.onload = displayVault;
