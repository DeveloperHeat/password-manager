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
      // Changed '—' to '-' to fix previous syntax error
      li.textContent = `${entry.site} - ${entry.username} - ${entry.password}`;
      list.appendChild(li);
    });
  } else if (masterPassword) {
    list.innerHTML = "<p>No passwords stored yet.</p>";
  }
}

async function checkBreach() {
  const password = document.getElementById("breach-password").value;
  const hashBuffer = await crypto.subtle.digest(
    "SHA-1",
    new TextEncoder().encode(password)
  );
  const fullHash = Array.from(new Uint8Array(hashBuffer))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("")
    .toUpperCase();
  const prefix = fullHash.slice(0, 5);
  const suffix = fullHash.slice(5);

  const response = await fetch(
    `https://api.pwnedpasswords.com/range/${prefix}`
  );
  const text = await response.text();
  const found = text.includes(suffix);

  const result = document.getElementById("breach-result");
  if (found) {
    result.innerHTML = "This password has been found in previous breaches!";
    result.style.color = "red";
  } else {
    result.innerHTML = "This password has NOT been found in any known breach.";
    result.style.color = "green";
  }
}

function isFakeRandom(pw) {
  const keyboardPatterns = ["qwerty", "asdf", "zxcv", "1234", "7890"];
  return (
    keyboardPatterns.some((seq) => pw.toLowerCase().includes(seq)) ||
    /[a-z]{3,}\d{2,}/.test(pw)
  );
}

function isVariant(base, password) {
  const variations = ["", "123", "1234", "!", "@", "1!", "2024", "2025"];
  return variations.some((v) => password.toLowerCase() === base + v);
}

function isInDictionary(pw) {
  const lowerPw = pw.toLowerCase();

  for (const word of commonPasswords) {
    // Exact match or simple variant (word, word123, word!)
    if (lowerPw === word || isVariant(word, pw)) return true;

    // Check for dictionary word + 2 digits (e.g., "password21")
    if (new RegExp(`^${word}\\d{2}$`).test(lowerPw)) return true;

    // Check for dictionary word + 3 digits (e.g., "password123")
    if (new RegExp(`^${word}\\d{3}$`).test(lowerPw)) return true;

    // Check for dictionary word + symbol + digits (e.g., "password!21")
    if (new RegExp(`^${word}[\\W_]\\d{1,4}$`).test(lowerPw)) return true;

    // Check for common prefix + dictionary word (e.g., "mysecretpassword") - can be resource intensive for large dictionaries
    // For now, let's stick to common prefixes that users add
    const commonPrefixes = ["my", "your", "the", "super"];
    if (
      commonPrefixes.some((prefix) =>
        lowerPw.includes(prefix + word.toLowerCase())
      )
    )
      return true;

    // Check for dictionary word + year (e.g., "password2024")
    for (const year of yearRange) {
      if (lowerPw === word + year) return true;
    }
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

  // If already very long and high entropy, it's very likely strong.
  // We'll be more forgiving with patterns if it's over a certain threshold.
  if (entropy >= 100 && pw.length >= 20) {
    // For very strong passwords, only flag truly egregious patterns
    // like massive repeating characters (e.g., 'aaaaa')
    if (/(.)\1{3,}/.test(pw)) return true; // Four or more identical consecutive characters
    return false; // If long and high entropy, assume strong unless truly horrible repetition
  }

  // Original stricter checks for shorter or less complex passwords:

  // Detect repeating character chunks (like DaaD, XxXx)
  if (/(..).*\1/.test(pw)) return true;

  // If symbols are grouped together, it's likely user-generated (often predictable)
  if (/[\W_]{2,}/.test(pw) && !/(.)\1/.test(pw)) {
    // Ensure it's not just a repeated symbol like "!!!"
    return true;
  }

  // If it ends in a digit-symbol combo, simulate AI-crackable (common human pattern)
  if (/\d{2,4}[\W_]+$/.test(pw)) return true;

  // Penalize passwords with all-capitalized chunks without lowercase mix
  // e.g., "MYPASSWORD" not "MyPaSsWoRd"
  if (/[A-Z]{3,}/.test(pw) && !/[a-z]/.test(pw)) return true;

  // Removed overly broad substitution check as it was causing false positives on truly random strings.
  // These are better handled by `isInDictionary` with de-substitution logic if desired.

  // Detect simple alternating patterns (e.g., ababab, 1a2b3c)
  if (/(.).\1.\1/.test(pw) || /(\d)([a-zA-Z])\1\2/.test(pw)) return true;

  // Final entropy fallback for *very* short or low-entropy passwords
  if (entropy < 60 && pw.length <= 16) return true;

  return false;
}

function generatePassphrase() {
  const theme = document.getElementById("theme-selector").value;
  let parts = [];

  if (theme === "animals") {
    parts.push(randomFromArray(colors));
    parts.push(randomFromArray(animals));
    parts.push(randomFromArray(animals));
  } else if (theme === "nz") {
    parts.push(randomFromArray(nzThemes));
    parts.push(randomFromArray(nzNouns));
    parts.push(randomFromArray(nzThemes));
  } else if (theme === "custom") {
    if (customWords.length < 3) {
      showAlertDialog(
        "Please define at least three custom words for a strong passphrase!"
      );
      return;
    }
    parts.push(randomFromArray(customWords));
    parts.push(randomFromArray(customWords));
    parts.push(randomFromArray(customWords));
  }

  // Add more numbers and symbols for better entropy and to avoid being "fake random" by pattern
  parts.push(randomNumber(1000, 9999).toString()); // First number set (4 digits)
  parts.push(randomFromArray(symbols)); // First symbol

  // Add more parts to increase base length and diversity
  parts.push(randomFromArray(symbols)); // Second symbol
  parts.push(randomNumber(10, 99).toString()); // Second number set (2 digits)

  // Shuffle all parts to distribute numbers and symbols throughout
  parts = shuffleArray(parts);

  let passphrase = parts.join("");

  // Ensure minimum length is 25 characters for "Strong" or "Very Strong" rating
  // Also ensure it meets diverse character type requirements
  while (
    passphrase.length < 25 || // Increased minimum length
    !/[a-z]/.test(passphrase) ||
    !/[A-Z]/.test(passphrase) ||
    !/\d/.test(passphrase) ||
    !/[\W_]/.test(passphrase)
  ) {
    const missingType = [];
    if (!/[a-z]/.test(passphrase)) missingType.push(randomChar(lowerCaseChars));
    if (!/[A-Z]/.test(passphrase)) missingType.push(randomChar(upperCaseChars));
    if (!/\d/.test(passphrase)) missingType.push(randomChar(numbersChars));
    if (!/[\W_]/.test(passphrase)) missingType.push(randomChar(symbols));

    if (missingType.length > 0) {
      passphrase += randomFromArray(missingType);
    } else {
      // If all types are present but still too short, add a random character type
      const allChars = lowerCaseChars + upperCaseChars + numbersChars + symbols;
      passphrase += randomChar(allChars);
    }
  }

  // Introduce more random capitalization within the words, not just at the start
  passphrase = scrambleCase(passphrase);

  document.getElementById("generated-passphrase").textContent = passphrase;

  const pwInput = document.getElementById("password");
  if (pwInput) pwInput.value = passphrase;
}

// Word lists
const animals = ["Panda", "Tiger", "Lion", "Eagle", "Shark", "Wolf", "Falcon"];
const colors = ["Blue", "Red", "Green", "Yellow", "Purple", "Orange", "Silver"];
const nzThemes = ["Kiwi", "Tui", "Kauri", "Pohutukawa", "SilverFern"];
const nzNouns = ["Sunset", "Mountain", "River", "Forest", "Beach"];
let customWords = [
  "Alpha",
  "Bravo",
  "Charlie",
  "Delta",
  "Echo",
  "Foxtrot",
  "Whiskey",
  "Zulu",
  "Oxygen",
  "Jupiter",
  "Rainbow",
  "Thunder",
  "Galaxy",
  "Starlight",
  "Quantum",
  "Nebula",
  "Cyclone",
  "Blossom",
  "Paradox",
  "Vortex",
]; // editable - expanded for better examples

// Helpers
function randomFromArray(arr) {
  const index = crypto.getRandomValues(new Uint32Array(1))[0] % arr.length;
  return arr[index];
}

function randomNumber(min, max) {
  const rand = crypto.getRandomValues(new Uint32Array(1))[0];
  return min + (rand % (max - min + 1));
}

// Helper: Shuffle array
function shuffleArray(arr) {
  for (let i = arr.length - 1; i > 0; i--) {
    const j = crypto.getRandomValues(new Uint32Array(1))[0] % (i + 1);
    [arr[i], arr[j]] = [arr[j], arr[i]];
  }
  return arr;
}

// Helper: Random symbol
const symbols = "!@#$%^&*()_+[]{}|;:,.<>?";

function randomChar(str) {
  const randomIndex =
    crypto.getRandomValues(new Uint32Array(1))[0] % str.length;
  return str.charAt(randomIndex);
}

// New helper to scramble case within a string
function scrambleCase(str) {
  return str
    .split("")
    .map((char) => {
      // Only scramble case for letters
      if (/[a-zA-Z]/.test(char)) {
        return randomNumber(0, 1) === 0
          ? char.toLowerCase()
          : char.toUpperCase();
      }
      return char;
    })
    .join("");
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

const specialChars = "!@#$%^&*()_+=-`~[]\\{}|;:,.<>?";
const numbersChars = "0123456789";
const lowerCaseChars = "abcdefghijklmnopqrstuvwxyz";
const upperCaseChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

function calculateEntropy(password) {
  let charsetSize = 0;
  const uniqueChars = new Set();

  for (const char of password) {
    uniqueChars.add(char);
  }

  // Base character sets
  if (/[a-z]/.test(password)) charsetSize += 26;
  if (/[A-Z]/.test(password)) charsetSize += 26;
  if (/[0-9]/.test(password)) charsetSize += 10;
  if (/[\W_]/.test(password)) charsetSize += 32; // Punctuation/symbols

  charsetSize = Math.max(charsetSize, uniqueChars.size); // Ensure at least uniqueChars.size for single char passwords

  if (charsetSize === 0) return 0;

  let entropy = password.length * Math.log2(charsetSize);

  // Simple penalty for consecutive repeating characters (e.g., 'aaaa')
  for (let i = 0; i < password.length - 2; i++) {
    if (
      password[i] === password[i + 1] &&
      password[i + 1] === password[i + 2]
    ) {
      entropy -= 5; // Arbitrary penalty
    }
  }

  // Simple penalty for common sequential patterns (e.g., 'abcd', '1234')
  const sequentialPatterns = [
    "abc",
    "def",
    "ghi",
    "jkl",
    "mno",
    "pqr",
    "stu",
    "vwx",
    "yz",
    "123",
    "234",
    "345",
    "456",
    "567",
    "678",
    "789",
    "890",
    "qwer",
    "asdf",
    "zxcv",
  ];
  for (const pattern of sequentialPatterns) {
    if (password.toLowerCase().includes(pattern)) {
      entropy -= 10; // Arbitrary penalty
    }
  }

  return Math.max(0, entropy); // Entropy cannot be negative
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

function entropyRating(entropy, pw) {
  // Added pw parameter
  let rating = "";

  if (entropy < 28) rating = "Very Weak";
  else if (entropy < 36) rating = "Weak";
  else if (entropy < 60) rating = "Moderate";
  else if (entropy < 128) rating = "Strong";
  else rating = "Very Strong";

  // Additional checks for real-world "actual" strength based on character diversity
  const hasLower = /[a-z]/.test(pw);
  const hasUpper = /[A-Z]/.test(pw);
  const hasDigit = /\d/.test(pw);
  const hasSymbol = /[\W_]/.test(pw);

  const missingTypes = [];
  if (!hasLower) missingTypes.push("lowercase");
  if (!hasUpper) missingTypes.push("uppercase");
  if (!hasDigit) missingTypes.push("digits");
  if (!hasSymbol) missingTypes.push("symbols");

  // Downgrade logic based on missing character types
  if (missingTypes.length > 0) {
    if (
      pw.length < 20 &&
      (missingTypes.includes("digits") || missingTypes.includes("symbols"))
    ) {
      // If relatively short AND missing digits or symbols, significantly downgrade
      if (rating === "Very Strong") rating = "Strong";
      if (rating === "Strong") rating = "Moderate";
      if (rating === "Moderate") rating = "Weak";
    } else if (pw.length < 25 && missingTypes.length >= 1) {
      // If missing any type and not super long
      if (rating === "Very Strong") rating = "Strong";
      if (rating === "Strong") rating = "Moderate";
    }
    // For very long passwords, missing types might still be strong (e.g., a very long passphrase with only letters)
    // but we can ensure they don't hit "Very Strong" if missing crucial elements
    if (
      rating === "Very Strong" &&
      (missingTypes.includes("digits") || missingTypes.includes("symbols"))
    ) {
      rating = "Strong"; // Downgrade from Very Strong if missing digits/symbols, even if long
    }
  }

  return rating;
}

function showCracked(message, time, rating) {
  document.getElementById("crack-result").innerHTML =
    `${message}<br>` +
    `Estimated crack time: ${time}<br>` +
    `Strength rating: ${rating}`;
}

function testPassword() {
  const pw = document.getElementById("test-password").value;
  const crackResultElement = document.getElementById("crack-result");

  if (!pw) {
    crackResultElement.textContent = "Enter a password.";
    return;
  }

  // --- Dynamic Feedback Logic ---

  if (isInDictionary(pw)) {
    crackResultElement.innerHTML =
      `This password is vulnerable to a **dictionary attack**. It's a common word or a simple variation.<br>` +
      `Estimated crack time: < 1 second<br>` +
      `Strength rating: Very Weak`;
    return;
  }

  if (hasPredictablePattern(pw)) {
    crackResultElement.innerHTML =
      `Your password follows a **predictable pattern** attackers often exploit (e.g., common capitalization, appending digits).<br>` +
      `Estimated crack time: < 5 seconds<br>` +
      `Strength rating: Weak`;
    return;
  }

  if (ruleBasedGuessable(pw)) {
    crackResultElement.innerHTML =
      `This strong-looking password is **vulnerable to rule-based cracking** because it uses common roots with simple suffixes.<br>` +
      `Estimated crack time: < 10 seconds<br>` +
      `Strength rating: Weak (by AI rule-based analysis)`;
    return;
  }

  if (isFakeRandom(pw)) {
    crackResultElement.innerHTML =
      `This password looks random, but contains **keyboard patterns or simple alphanumeric sequences** that AI recognizes as "fake" random.<br>` +
      `Estimated crack time: < 3 hours<br>` +
      `Strength rating: Moderate (AI pattern recognition)`;
    return;
  }

  if (aiCrackable(pw)) {
    crackResultElement.innerHTML =
      `This password exhibits **patterns crackable by AI models trained on leaked datasets** (e.g., symbol grouping, predictable capitalization).<br>` +
      `Estimated crack time: < 2 minutes<br>` +
      `Strength rating: Moderate (AI attack mode)`;
    return;
  }

  // --- End Dynamic Feedback Logic ---

  const entropy = calculateEntropy(pw);
  const time = estimateCrackTime(entropy);
  const rating = entropyRating(entropy, pw); // Pass pw here

  crackResultElement.innerHTML =
    `Entropy: ${entropy.toFixed(2)} bits<br>` +
    `Estimated crack time: ${time}<br>` +
    `Strength rating: ${rating}`;

  // Adaptive Suggestions
  let suggestion = "";
  if (rating === "Very Weak" || rating === "Weak") {
    suggestion =
      "Consider adding more unique characters, mixing cases, and including symbols. Avoid common words and predictable patterns.";
  } else if (rating === "Moderate") {
    suggestion =
      "To reach 'Strong' or 'Very Strong', aim for a longer password (25+ characters) with a mix of uppercase, lowercase, numbers, and symbols, avoiding obvious patterns.";
  } else if (rating === "Strong") {
    suggestion =
      "Great! For even higher security, increase length and ensure maximum character set diversity.";
  }

  crackResultElement.innerHTML += `<br><b>Suggestion:</b> ${suggestion}`;
}

function updateCustomWords() {
  const input = document.getElementById("custom-words-input").value;
  customWords = input
    .split(",")
    .map((w) => w.trim())
    .filter((w) => w);
  showAlertDialog(`Custom words updated: ${customWords.join(", ")}`);
}

// Custom alert dialog function to replace window.alert
function showAlertDialog(message) {
  const dialogBox = document.createElement("div");
  dialogBox.style.cssText = `
    position: fixed;
    top: 50%;
    left: 50%;
    transform: translate(-50%, -50%);
    background-color: white;
    padding: 20px;
    border-radius: 8px;
    box-shadow: 0 4px 8px rgba(0, 0, 0, 0.2);
    z-index: 1000;
    text-align: center;
    font-family: 'Inter', sans-serif;
    color: #333;
    max-width: 80%;
    border: 1px solid #ccc;
  `;

  const messagePara = document.createElement("p");
  messagePara.textContent = message;
  messagePara.style.marginBottom = "15px";

  const okButton = document.createElement("button");
  okButton.textContent = "OK";
  okButton.style.cssText = `
    background-color: #4CAF50;
    color: white;
    padding: 10px 20px;
    border: none;
    border-radius: 5px;
    cursor: pointer;
    font-size: 16px;
  `;
  okButton.onclick = () => dialogBox.remove();

  dialogBox.appendChild(messagePara);
  dialogBox.appendChild(okButton);
  document.body.appendChild(dialogBox);
}

window.onload = displayVault;
