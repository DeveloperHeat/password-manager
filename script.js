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

// Global variables (already in index.html, but keep for clarity for features)
// let masterPassword = null; // Defined in index.html script
// let vaultData = []; // Defined in index.html script
// let editIndex = -1; // Defined in index.html script

async function getVault() {
  return vaultData;
}

async function saveVault(data) {
  const encrypted = await encryptData(data, masterPassword);
  localStorage.setItem("vaultx", JSON.stringify(encrypted));
}

async function addPassword() {
  const site = document.getElementById("site").value.trim();
  const username = document.getElementById("username").value.trim();
  const password = document.getElementById("password").value.trim();

  if (!site || !username || !password) {
    showAlertDialog("Please fill in all fields (Website, Username, Password).");
    return;
  }

  if (editIndex !== -1) {
    // Editing an existing credential
    vaultData[editIndex] = { site, username, password };
    editIndex = -1; // Reset edit index
    document.getElementById("add-edit-password-btn").textContent =
      "Add Credential";
    document.getElementById("cancel-edit-btn").style.display = "none";
    showAlertDialog("Credential updated successfully!");
  } else {
    // Adding a new credential
    vaultData.push({ site, username, password });
    showAlertDialog("Credential added successfully!");
  }

  document.getElementById("site").value = "";
  document.getElementById("username").value = "";
  document.getElementById("password").value = "";

  await saveVault(vaultData);
  await displayVault();
}

// New function for editing
function editPassword(index) {
  const enteredPassword = prompt(
    "Please enter your master password to edit this entry:"
  );

  // Check if the user clicked "Cancel" or left the field empty
  if (enteredPassword === null) {
    return;
  }

  // Verify the master password
  if (enteredPassword === masterPassword) {
    editIndex = index;
    const entry = vaultData[index];
    document.getElementById("site").value = entry.site;
    document.getElementById("username").value = entry.username;
    document.getElementById("password").value = entry.password;

    document.getElementById("add-edit-password-btn").textContent =
      "Save Changes";
    document.getElementById("cancel-edit-btn").style.display = "inline-block"; // Show cancel button
    window.scrollTo({ top: 0, behavior: "smooth" }); // Scroll to top for easier editing
  } else {
    showAlertDialog("Incorrect master password. Edit denied.");
  }
}

// New function to cancel editing
function cancelEdit() {
  editIndex = -1;
  document.getElementById("site").value = "";
  document.getElementById("username").value = "";
  document.getElementById("password").value = "";
  document.getElementById("add-edit-password-btn").textContent =
    "Add Credential";
  document.getElementById("cancel-edit-btn").style.display = "none";
}

async function displayVault() {
  const list = document.getElementById("password-list");
  list.innerHTML = "";

  const searchQuery = document
    .getElementById("search-vault")
    .value.toLowerCase();

  const filteredVault = vaultData.filter((entry) => {
    return (
      entry.site.toLowerCase().includes(searchQuery) ||
      entry.username.toLowerCase().includes(searchQuery)
    );
  });

  if (filteredVault && filteredVault.length > 0) {
    filteredVault.forEach((entry, index) => {
      const li = document.createElement("li");

      // Container for the credential text
      const textContainer = document.createElement("span");
      textContainer.textContent = `${entry.site} - ${entry.username} - ••••••••`;

      // Button container for reveal, copy, edit, and delete
      const buttonContainer = document.createElement("div");
      buttonContainer.style.display = "flex";
      buttonContainer.style.gap = "5px";
      buttonContainer.style.flexWrap = "wrap"; // Allow buttons to wrap

      // Reveal button
      const revealButton = document.createElement("button");
      revealButton.textContent = "Reveal";
      revealButton.className = "btn btn-secondary btn-small";
      revealButton.onclick = () => revealPassword(vaultData.indexOf(entry)); // Use original index for reveal/delete/edit

      // Copy Username button
      const copyUserButton = document.createElement("button");
      copyUserButton.textContent = "Copy User";
      copyUserButton.className = "btn btn-secondary btn-small";
      copyUserButton.onclick = () => copyUsernameToClipboard(index);

      // Copy Password button
      const copyPassButton = document.createElement("button");
      copyPassButton.textContent = "Copy Pass";
      copyPassButton.className = "btn btn-secondary btn-small";
      copyPassButton.onclick = () => copyToClipboard(index);

      // Edit button
      const editButton = document.createElement("button");
      editButton.textContent = "Edit";
      editButton.className = "btn btn-secondary btn-small";
      editButton.onclick = () => editPassword(vaultData.indexOf(entry)); // Use original index

      // Delete button
      const deleteButton = document.createElement("button");
      deleteButton.textContent = "Delete";
      deleteButton.className = "btn btn-danger btn-small";
      deleteButton.onclick = () => deletePassword(vaultData.indexOf(entry)); // Use original index

      buttonContainer.appendChild(revealButton);
      buttonContainer.appendChild(copyUserButton);
      buttonContainer.appendChild(copyPassButton);
      buttonContainer.appendChild(editButton);
      buttonContainer.appendChild(deleteButton);

      li.appendChild(textContainer);
      li.appendChild(buttonContainer);
      list.appendChild(li);
    });
  } else if (masterPassword) {
    list.innerHTML =
      "<p>No passwords stored yet or no results for your search.</p>";
  }
}

// ... (existing code) ...

async function deleteMasterPassword() {
  if (!masterPassword) {
    showAlertDialog("No vault is currently unlocked to delete.");
    return;
  }

  const enteredPassword = prompt(
    "Enter your master password to CONFIRM vault deletion. This action is irreversible:"
  );

  if (enteredPassword === null) {
    return; // User cancelled the prompt
  }

  if (enteredPassword === masterPassword) {
    if (
      confirm(
        "ARE YOU ABSOLUTELY SURE? Deleting your master password will PERMANENTLY ERASE ALL your stored credentials. This action cannot be undone."
      )
    ) {
      localStorage.removeItem("vaultx"); // Delete the vault from local storage
      masterPassword = null; // Clear master password from memory
      vaultData = []; // Clear vault data from memory
      showAlertDialog("Your vault has been permanently deleted.");

      // Redirect to the set master password section or initial state
      document.querySelector(".container").style.display = "none";
      document.getElementById("unlock-section").style.display = "none";
      document.getElementById("set-master-password-section").style.display =
        "flex";
      // Clear any input fields that might be populated
      document.getElementById("master-password").value = "";
      document.getElementById("new-master-password").value = "";
      document.getElementById("confirm-new-master-password").value = "";
    }
  } else {
    showAlertDialog("Incorrect master password. Vault deletion denied.");
  }
}

/**
 * Prompts for the master password and reveals the selected credential in an alert.
 * @param {number} index - The index of the credential in the vaultData array.
 */
function revealPassword(index) {
  const enteredPassword = prompt(
    "Please enter your master password to reveal:"
  );

  // Check if the user clicked "Cancel" or left the field empty
  if (enteredPassword === null) {
    return;
  }

  // Verify the master password
  if (enteredPassword === masterPassword) {
    const credential = vaultData[index];
    alert(
      `Credentials for: ${credential.site}\n\nUsername: ${credential.username}\nPassword: ${credential.password}`
    );
  } else {
    showAlertDialog("Incorrect master password. Access denied.");
  }
}

/**
 * Prompts for the master password and deletes the selected credential.
 * @param {number} index - The index of the credential in the vaultData array.
 */
async function deletePassword(index) {
  const enteredPassword = prompt(
    "Please enter your master password to confirm deletion:"
  );

  if (enteredPassword === null) {
    return;
  }

  if (enteredPassword === masterPassword) {
    if (
      confirm(
        "Are you sure you want to delete this credential? This action cannot be undone."
      )
    ) {
      vaultData.splice(index, 1); // Remove the credential from the array
      await saveVault(vaultData); // Save the updated vault
      await displayVault(); // Re-display the vault
      showAlertDialog("Credential deleted successfully.");
    }
  } else {
    showAlertDialog("Incorrect master password. Deletion denied.");
  }
}

// START HELPER FUNCTION: Levenshtein Distance (for typo detection)
function levenshteinDistance(s1, s2) {
  s1 = s1.toLowerCase();
  s2 = s2.toLowerCase();
  const costs = [];
  for (let i = 0; i <= s1.length; i++) {
    let lastValue = i;
    for (let j = 0; j <= s2.length; j++) {
      if (i === 0) {
        costs[j] = j;
      } else if (j > 0) {
        let newValue = costs[j - 1];
        if (s1.charAt(i - 1) !== s2.charAt(j - 1)) {
          newValue = Math.min(Math.min(newValue, lastValue), costs[j]) + 1;
        }
        costs[j - 1] = lastValue;
        lastValue = newValue;
      }
    }
    if (i > 0) {
      costs[s2.length] = lastValue;
    }
  }
  return costs[s2.length];
}
// END HELPER FUNCTION

function copyUsernameToClipboard(index) {
  const credential = vaultData[index];
  if (!credential) {
    showAlertDialog("Could not find username to copy.");
    return;
  }
  navigator.clipboard
    .writeText(credential.username)
    .then(() => showAlertDialog("Username copied to clipboard!"))
    .catch((err) => {
      console.error("Failed to copy username: ", err);
      showAlertDialog("Failed to copy username. Please copy manually.");
    });
}

// New function for copying to clipboard
/**
 * Prompts for the master password and copies the selected credential's password to clipboard.
 * @param {number} index - The index of the credential in the vaultData array.
 */
async function copyToClipboard(index) {
  const enteredPassword = prompt(
    "Please enter your master password to copy the password:"
  ); // Prompt for master password

  // Check if the user clicked "Cancel" or left the field empty
  if (enteredPassword === null) {
    return;
  }

  // Verify the master password
  if (enteredPassword === masterPassword) {
    const credential = vaultData[index]; // Get the credential
    try {
      await navigator.clipboard.writeText(credential.password); // Copy the password to clipboard
      showAlertDialog("Password copied to clipboard!"); // Show success message
      // Optional: clear clipboard after a short delay for security
      // setTimeout(() => navigator.clipboard.writeText(''), 30 * 1000); // Clears after 30 seconds
    } catch (err) {
      console.error("Failed to copy: ", err); // Log error
      showAlertDialog("Failed to copy. Please copy manually."); // Show error message
    }
  } else {
    showAlertDialog("Incorrect master password. Copy denied."); // Show denial message
  }
}

async function checkBreach() {
  const password = document.getElementById("breach-password").value;
  if (!password) {
    showAlertDialog("Please enter a password to check for breaches.");
    return;
  }
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
    result.className = "result-box found";
  } else {
    result.innerHTML = "This password has NOT been found in any known breach.";
    result.className = "result-box not-found";
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
  const variations = ["", "123", "1234", "!", "@", "1!", "2024", "2025"]; // Added current and next year
  return variations.some((v) => password.toLowerCase() === base + v);
}

function isInDictionary(pw) {
  const lowerPw = pw.toLowerCase();

  for (const word of commonPasswords) {
    if (lowerPw === word || isVariant(word, pw)) return true;
    if (new RegExp(`^${word}\\d{2}$`).test(lowerPw)) return true;
    if (new RegExp(`^${word}\\d{3}$`).test(lowerPw)) return true;
    if (new RegExp(`^${word}[\\W_]\\d{1,4}$`).test(lowerPw)) return true;
    const commonPrefixes = ["my", "your", "the", "super"];
    if (
      commonPrefixes.some((prefix) =>
        lowerPw.includes(prefix + word.toLowerCase())
      )
    )
      return true;
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
    /(.)\1{2,}/, // e.g., "aaa", "111"
    /(?:ab|bc|cd|de|ef|fg|gh|hi|ij|jk|kl|lm|mn|no|op|pq|qr|rs|st|tu|uv|vw|wx|xy|yz){2,}/i, // alphabetical sequences
    /(?:01|12|23|34|45|56|67|78|89){2,}/, // numerical sequences
    /(?:!@|@#|#\$|\$\%|\%^|\^&|&\*|\*\()(?:\!@|@#|#\$|\$\%|\%^|\^&|&?\*|\*\(){1,}/, // symbol sequences
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

  // AI-specific weak patterns
  if (pw.length < 8 && entropy < 40) return true; // Very short and low entropy
  if (
    pw.length < 12 &&
    entropy < 60 &&
    (!/[A-Z]/.test(pw) || !/[\W_]/.test(pw))
  )
    return true; // Medium length, missing complexity
  if (/(.)\1{3,}/.test(pw)) return true; // Four or more repeated characters (e.g., "aaaa")
  if (/(..).*\1/.test(pw) && pw.length > 8) return true; // Repeating patterns in longer passwords (e.g., "abc...abc")
  if (/^(\w+?)\1+$/.test(pw)) return true; // Simple repetitions like "passwordpassword"
  if (/[a-z]+[0-9]+[a-z]+/.test(pw) && pw.length < 10) return true; // Very simple alternating patterns
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

function copyGeneratedPassword() {
  const generatedPass = document.getElementById(
    "generated-password-display"
  ).textContent;
  if (generatedPass) {
    copyToClipboard(generatedPass);
  } else {
    showAlertDialog("No password generated yet to copy.");
  }
}

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
];

function randomFromArray(arr) {
  const index = crypto.getRandomValues(new Uint32Array(1))[0] % arr.length;
  return arr[index];
}

function randomNumber(min, max) {
  const rand = crypto.getRandomValues(new Uint32Array(1))[0];
  return min + (rand % (max - min + 1));
}

function shuffleArray(arr) {
  for (let i = arr.length - 1; i > 0; i--) {
    const j = crypto.getRandomValues(new Uint32Array(1))[0] % (i + 1);
    [arr[i], arr[j]] = [arr[j], arr[i]];
  }
  return arr;
}

// New helper to shuffle string characters
function shuffleString(str) {
  const arr = str.split("");
  for (let i = arr.length - 1; i > 0; i--) {
    const j = crypto.getRandomValues(new Uint32Array(1))[0] % (i + 1);
    [arr[i], arr[j]] = [arr[j], arr[i]];
  }
  return arr.join("");
}

const symbols = "!@#$%^&*()_+[]{}|;:,.<>?";
const specialChars = "!@#$%^&*()_+=-`~[]\\{}|;:,.<>?"; // Duplicated for clarity in password generation rules, could merge
const numbersChars = "0123456789";
const lowerCaseChars = "abcdefghijklmnopqrstuvwxyz";
const upperCaseChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

function randomChar(str) {
  const randomIndex =
    crypto.getRandomValues(new Uint32Array(1))[0] % str.length;
  return str.charAt(randomIndex);
}

function scrambleCase(str) {
  return str
    .split("")
    .map((char) => {
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
  "master",
  "admin123",
  "football",
  "ilovecats",
  "computer",
  "security",
  "princess",
  "darkness",
  "infinity",
  "changeit",
];

const keyboardPatterns = [
  "qwerty",
  "asdfghjkl",
  "zxcvbnm",
  "1234567890",
  "qazwsxedcrfv",
  "plokmijnuhbygvft",
  "mnbvcxzlkjhgfdsaqwertyuiop",
  "qaz",
  "wsx",
  "edc",
  "rfv",
  "tgb",
  "yhn",
  "ujm",
  "ik,",
  "ol.",
  "p;/", // common short patterns
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
  "chris",
  "alex",
  "sam",
  "pat",
  "taylor", // more common names
];

function calculateEntropy(password) {
  let charsetSize = 0;
  if (/[a-z]/.test(password)) charsetSize += 26;
  if (/[A-Z]/.test(password)) charsetSize += 26;
  if (/[0-9]/.test(password)) charsetSize += 10;
  if (/[\W_]/.test(password)) charsetSize += 32; // Assuming ~32 common special chars

  if (charsetSize === 0) return 0;
  let entropy = password.length * Math.log2(charsetSize);

  // Deductions for common patterns
  if (/(.)\1{2,}/.test(password)) entropy -= 5; // Repeated characters (e.g., "aaa")
  const sequentialPatterns = [
    "abc",
    "123",
    "qwer",
    "asdf",
    "zxcv",
    "987",
    "edc",
  ];
  for (const pattern of sequentialPatterns) {
    if (password.toLowerCase().includes(pattern)) entropy -= 10;
  }
  // Deduct for simple variations of common words (e.g., password123, welcome!)
  if (isInDictionary(password)) entropy -= 20;
  if (hasPredictablePattern(password)) entropy -= 15;
  if (ruleBasedGuessable(password)) entropy -= 15;

  return Math.max(0, entropy); // Ensure entropy doesn't go below zero
}

function estimateCrackTime(entropy) {
  const guessesPerSecond = 1e12; // Adjusted to a more realistic modern cracking speed (trillions/sec)
  const seconds = Math.pow(2, entropy) / guessesPerSecond;

  if (seconds < 1) return "< 1 second";
  if (seconds < 60) return `${seconds.toFixed(2)} seconds`;
  const minutes = seconds / 60;
  if (minutes < 60) return `${minutes.toFixed(2)} minutes`;
  const hours = minutes / 60;
  if (hours < 24) return `${hours.toFixed(2)} hours`;
  const days = hours / 24;
  if (days < 365) return `${days.toFixed(2)} days`;
  const years = days / 365;

  if (years > 1e6) return `> ${Math.round(years / 1e6)} million years`;
  if (years > 1e3) return `> ${Math.round(years / 1e3)} thousand years`;
  return `${years.toFixed(2)} years`;
}

function entropyRating(entropy, pw) {
  let rating = "Very Weak";
  let feedback = [];

  // Length checks
  if (pw.length < 8) feedback.push("Too short (min 8 characters recommended).");
  else if (pw.length < 12)
    feedback.push("Could be longer for better security.");

  // Character type checks
  const hasLower = /[a-z]/.test(pw);
  const hasUpper = /[A-Z]/.test(pw);
  const hasDigit = /\d/.test(pw);
  const hasSymbol = /[\W_]/.test(pw);

  if (!hasLower) feedback.push("Missing lowercase characters.");
  if (!hasUpper) feedback.push("Missing uppercase characters.");
  if (!hasDigit) feedback.push("Missing numbers.");
  if (!hasSymbol) feedback.push("Missing special symbols.");

  const characterTypesCount = [hasLower, hasUpper, hasDigit, hasSymbol].filter(
    Boolean
  ).length;
  if (characterTypesCount < 3 && pw.length < 12)
    feedback.push("Combine more character types.");

  // Pattern checks (already done by functions like isInDictionary, etc.)
  if (isInDictionary(pw)) feedback.push("Contains common dictionary words.");
  if (hasPredictablePattern(pw))
    feedback.push(
      "Follows a predictable pattern (e.g., sequences, repetitions)."
    );
  if (ruleBasedGuessable(pw))
    feedback.push("Vulnerable to common rule-based attacks.");
  if (aiCrackable(pw))
    feedback.push("Exhibits patterns easily crackable by AI.");
  if (isFakeRandom(pw))
    feedback.push('Contains "fake random" keyboard patterns.');

  if (entropy < 28) rating = "Very Weak";
  else if (entropy < 36) rating = "Weak";
  else if (entropy < 60) rating = "Moderate";
  else if (entropy < 128) rating = "Strong";
  else rating = "Very Strong";

  return { rating, feedback: feedback.length ? feedback : ["Looks good!"] };
}

function testPassword() {
  const pw = document.getElementById("test-password").value;
  const crackResultElement = document.getElementById("crack-result");
  const meter = document.getElementById("password-strength-meter");
  const meterText = document.getElementById("password-strength-text");

  const updateMeter = (rating = "") => {
    let level = 0;
    switch (rating) {
      case "Very Weak":
        level = 1;
        break;
      case "Weak":
        level = 2;
        break;
      case "Moderate":
        level = 3;
        break;
      case "Strong":
        level = 4;
        break;
      case "Very Strong":
        level = 5;
        break;
    }
    meter.className = `strength-${level}`;
    meterText.textContent = rating;
  };

  if (!pw) {
    crackResultElement.textContent = "Enter a password to test.";
    updateMeter();
    return;
  }

  const entropy = calculateEntropy(pw);
  const { rating, feedback } = entropyRating(entropy, pw);
  const time = estimateCrackTime(entropy);

  updateMeter(rating);
  crackResultElement.innerHTML =
    `<strong>Strength: ${rating}</strong><br>` +
    `Estimated crack time: ${time}<br>` +
    `Entropy: ${entropy.toFixed(2)} bits.<br>` +
    `Feedback: <ul>${feedback.map((f) => `<li>${f}</li>`).join("")}</ul>`;
}

function updateCustomWords() {
  const input = document.getElementById("custom-words-input").value;
  customWords = input
    .split(",")
    .map((w) => w.trim())
    .filter((w) => w);
  showAlertDialog(`Custom words updated: ${customWords.join(", ")}`);
}

function showAlertDialog(message) {
  const dialogBox = document.createElement("div");
  dialogBox.style.cssText = `
    position: fixed; top: 50%; left: 50%; transform: translate(-50%, -50%);
    background-color: white; padding: 20px; border-radius: 8px;
    box-shadow: 0 4px 8px rgba(0, 0, 0, 0.2); z-index: 1000; text-align: center;
    font-family: 'Inter', sans-serif; color: #333; max-width: 80%;
    border: 1px solid #ccc;
  `;
  const messagePara = document.createElement("p");
  messagePara.textContent = message;
  messagePara.style.marginBottom = "15px";
  const okButton = document.createElement("button");
  okButton.textContent = "OK";
  okButton.style.cssText = `
    background-color: var(--primary-color); color: white; padding: 10px 20px;
    border: none; border-radius: 5px; cursor: pointer; font-size: 16px;
  `;
  okButton.onclick = () => dialogBox.remove();
  dialogBox.appendChild(messagePara);
  dialogBox.appendChild(okButton);
  document.body.appendChild(dialogBox);
}

// New Export Function
async function exportVault() {
  if (!masterPassword) {
    showAlertDialog("Please unlock your vault before exporting.");
    return;
  }
  const confirmExport = confirm(
    "Exporting your vault will download an ENCRYPTED JSON file. Keep it safe! Do you wish to proceed?"
  );
  if (!confirmExport) {
    return;
  }
  try {
    const encryptedVault = localStorage.getItem("vaultx");
    if (!encryptedVault) {
      showAlertDialog("No vault data to export.");
      return;
    }

    const blob = new Blob([encryptedVault], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `vaultx_export_${new Date().toISOString().slice(0, 10)}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    showAlertDialog("Vault exported successfully!");
  } catch (e) {
    console.error("Error exporting vault:", e);
    showAlertDialog("Failed to export vault. See console for details.");
  }
}

// New Import Function
async function importVault(event) {
  if (!masterPassword) {
    showAlertDialog("Please unlock your vault before importing.");
    return;
  }

  const file = event.target.files[0];
  if (!file) {
    return;
  }

  if (!file.name.endsWith(".json")) {
    showAlertDialog("Please select a valid .json file.");
    event.target.value = ""; // Clear file input
    return;
  }

  const reader = new FileReader();
  reader.onload = async (e) => {
    try {
      const importedEncryptedData = JSON.parse(e.target.result);
      // Attempt to decrypt the imported data with the current master password
      const decryptedImportedData = await decryptData(
        importedEncryptedData,
        masterPassword
      );

      if (
        confirm(
          "Importing will REPLACE your current vault data. Are you sure you want to proceed?"
        )
      ) {
        vaultData = decryptedImportedData;
        await saveVault(vaultData); // Save the imported data (which is already decrypted and re-encrypted by saveVault)
        await displayVault();
        showAlertDialog("Vault imported successfully!");
      }
    } catch (error) {
      console.error("Import error:", error);
      showAlertDialog(
        "Failed to import vault. Make sure it's a valid VaultX export and you're using the correct master password."
      );
    } finally {
      event.target.value = ""; // Clear file input
    }
  };
  reader.onerror = () => {
    showAlertDialog("Error reading file.");
    event.target.value = "";
  };
  reader.readAsText(file);
}

let phishingDetectionModel; // Variable to hold our TensorFlow.js model

// UPDATE: getUrlFeaturesForPhishingAI (Now extracts 9 features)
function getUrlFeaturesForPhishingAI(url) {
  let features = [0, 0, 0, 0, 0, 0, 0, 0, 0]; // Now 9 features
  if (!url || typeof url !== "string" || !url.startsWith("http")) {
    return features; // Return all zeros for invalid URL
  }

  try {
    const lowerUrl = url.toLowerCase();
    const urlObj = new URL(url);
    const hostname = urlObj.hostname;
    // const path = urlObj.pathname; // path is not directly used for new features, but can be for future

    // Feature 1: Normalized URL Length
    features[0] = Math.min(lowerUrl.length / 100, 1); // Normalize to max 100 chars

    // Feature 2: IP address in hostname
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname)) {
      features[1] = 1;
    }

    // Feature 3: Suspicious keywords in URL (expanded list)
    const suspiciousKeywords = [
      "login",
      "verify",
      "account",
      "secure",
      "update",
      "bank",
      "paypal",
      "amazon",
      "apple",
      "support",
      "signin",
      "webscr",
      "confirm",
      "free",
      "gift",
      "prize",
      "discount",
      "offer",
      "alert",
      "security",
      "urgent",
      "restricted",
    ];
    if (suspiciousKeywords.some((keyword) => lowerUrl.includes(keyword))) {
      features[2] = 1;
    }

    // Feature 4: No HTTPS
    if (urlObj.protocol !== "https:") {
      features[3] = 1;
    }

    // Feature 5: Number of subdomains (normalized)
    const parts = hostname.split(".");
    // Calculate subdomains, excluding TLD and main domain (e.g., www.example.com -> 1 subdomain)
    // Normalize: max 5 subdomains for feature, more than that still counts as 1.
    features[4] = Math.min(Math.max(0, parts.length - 2) / 3, 1);

    // Feature 6: Uncommon TLD (expanded list)
    const tld = parts[parts.length - 1];
    const uncommonTLDs = [
      "xyz",
      "top",
      "online",
      "club",
      "info",
      "biz",
      "win",
      "stream",
      "live",
      "link",
      "bid",
      "pw",
      "ga",
      "ml",
      "cf",
      "tk",
      "click",
      "download",
      "zip",
      "app",
      "cc",
      "ru",
      "cn",
      "ws",
    ]; // Added more common suspicious TLDs
    if (uncommonTLDs.includes(tld)) {
      features[5] = 1;
    }

    // Feature 7: More comprehensive Homograph-like check
    // Expanded common substitutions to catch 'amaxon' (e.g., z->2)
    const homographChars = {
      o: ["0"],
      l: ["1", "|"],
      a: ["@", "4"],
      e: ["3"],
      i: ["!"],
      s: ["5", "$"],
      g: ["9"],
      b: ["8"],
      z: ["2"],
      c: ["k"],
      v: ["u"],
    };
    let hasHomographLike = false;
    for (const char in homographChars) {
      if (
        homographChars[char].some(
          (sub) => hostname.includes(sub) && !hostname.includes(char)
        )
      ) {
        hasHomographLike = true;
        break;
      }
    }
    if (hasHomographLike) {
      features[6] = 1;
    }

    // NEW FEATURE 8: Domain Typo/Impersonation (using Levenshtein Distance)
    const knownBrands = [
      "amazon.com",
      "google.com",
      "microsoft.com",
      "paypal.com",
      "apple.com",
      "facebook.com",
      "netflix.com",
      "ebay.com",
      "linkedin.com",
      "twitter.com",
      "instagram.com",
    ]; // More brands
    const domainOnly = hostname.replace(/^www\./, ""); // Remove www. for comparison
    let minLevenshtein = Infinity;
    for (const brand of knownBrands) {
      const distance = levenshteinDistance(domainOnly, brand);
      minLevenshtein = Math.min(minLevenshtein, distance);
    }
    // If distance is 1 or 2 to a known brand (and not an exact match), it's highly suspicious
    if (minLevenshtein <= 2 && minLevenshtein > 0) {
      features[7] = 1; // Flag as potential typo/impersonation
    }

    // NEW FEATURE 9: Brand name in path or subdomain, but not in primary domain (e.g., login.amazon.evil.com)
    let brandInSubdomainOrPath = false;
    const sensitiveBrands = [
      "amazon",
      "google",
      "microsoft",
      "paypal",
      "apple",
      "facebook",
      "netflix",
      "ebay",
      "linkedin",
      "twitter",
      "instagram",
    ]; // Lowercase
    for (const brand of sensitiveBrands) {
      // Check if brand is in the full URL but NOT in the core domain name (excluding TLD)
      // Example: "google.com" is core domain. "google.evil.com" has google not in core.
      const coreDomain = parts.slice(parts.length - 2, parts.length).join("."); // e.g., "amaxon.com" from "www.amaxon.com"
      if (!coreDomain.includes(brand) && lowerUrl.includes(brand)) {
        brandInSubdomainOrPath = true;
        break;
      }
    }
    if (brandInSubdomainOrPath) {
      features[8] = 1;
    }
  } catch (e) {
    console.error("Error parsing URL for features:", e);
  }
  return features;
}

// UPDATE: initializePhishingDetectionModel (Now expects 9 features)
async function initializePhishingDetectionModel() {
  if (typeof tf === "undefined") {
    console.warn(
      "TensorFlow.js is not loaded. AI phishing detection feature will be unavailable."
    );
    return;
  }

  phishingDetectionModel = tf.sequential({
    layers: [
      tf.layers.dense({
        units: 1,
        inputShape: [9], // NOW 9 FEATURES
        activation: "sigmoid", // Outputs a score between 0 and 1
        // Manually set weights and bias for demonstration purposes.
        // These are adjusted to give higher importance to strong phishing indicators.
        weights: [
          // Weights for the input features (tuned for better detection)
          tf.tensor2d([
            [0.1], // 1. Normalized URL length (minor contribution)
            [0.9], // 2. Has IP address (very high risk)
            [0.7], // 3. Has suspicious keywords (high risk)
            [0.6], // 4. No HTTPS (significant risk)
            [0.4], // 5. Number of subdomains (moderate risk)
            [0.5], // 6. Uncommon TLD (moderate risk)
            [0.8], // 7. Homograph-like chars (high risk)
            [1.0], // 8. NEW: Domain Typo/Impersonation (CRITICAL - highest weight)
            [0.8], // 9. NEW: Brand in Path/Subdomain (high risk)
          ]),
          tf.tensor1d([-1.5]), // Adjusted bias: pushes initial score lower, requires strong features to flag
        ],
      }),
    ],
  });

  // Dummy prediction with 9 features to build the model graph
  phishingDetectionModel.predict(
    tf.tensor2d([[0, 0, 0, 0, 0, 0, 0, 0, 0]], [1, 9])
  );
  console.log(
    "TensorFlow.js phishing detection model initialized (significantly improved)."
  );
}

// Function to use the AI model to predict phishing risk
async function predictPhishingRiskAI(url) {
  if (!phishingDetectionModel) {
    await initializePhishingDetectionModel(); // Initialize if not already
  }

  // If model still not available (e.g., TF.js not loaded), return N/A
  if (!phishingDetectionModel) {
    return {
      score: "N/A",
      level: "Unavailable",
      reason: ["AI model not loaded."],
    };
  }

  const features = getUrlFeaturesForPhishingAI(url);
  if (features.every((f) => f === 0) && (!url || !url.startsWith("http"))) {
    return {
      score: "0%",
      level: "Not Analyzed",
      reason: ["Invalid or empty URL provided."],
    };
  }

  const inputTensor = tf.tensor2d([features], [1, 9]); // Reshape for model input

  const prediction = phishingDetectionModel.predict(inputTensor);
  const riskScore = (await prediction.data())[0]; // Get the single output value (0-1)

  inputTensor.dispose(); // Clean up tensors to free memory
  prediction.dispose();

  // Interpret the risk score (0-1 from sigmoid) into a user-friendly percentage and level
  const interpretedRiskPercentage = (riskScore * 100).toFixed(0); // 0-100% risk

  let riskLevel = "Very Low Risk";
  if (interpretedRiskPercentage >= 80) riskLevel = "Very High Risk";
  else if (interpretedRiskPercentage >= 60) riskLevel = "High Risk";
  else if (interpretedRiskPercentage >= 40) riskLevel = "Medium Risk";
  else if (interpretedRiskPercentage >= 20) riskLevel = "Low Risk";

  // Provide simple reasons based on the features that contributed to higher risk (manually derived)
  let reasons = [];
  if (riskScore >= 0.5) {
    // If it's considered suspicious by the model
    const featureNames = [
      "URL length",
      "IP in hostname",
      "Suspicious keywords",
      "No HTTPS",
      "Many subdomains",
      "Uncommon TLD",
      "Homograph-like characters",
    ];
    features.forEach((f, i) => {
      if (f > 0 && featureNames[i]) {
        // If feature is present and contributed
        reasons.push(featureNames[i]);
      }
    });
    if (reasons.length === 0)
      reasons.push("Potential phishing indicators detected.");
  } else {
    reasons.push("No significant phishing indicators detected.");
  }

  return {
    score: interpretedRiskPercentage, // Percentage risk (0-100)
    level: riskLevel,
    reason: reasons,
  };
}

// In script.js, add this function (e.g., near your other event handlers)
async function checkPhishingUrlAI() {
  const urlInput = document.getElementById("phishing-url-input-ai");
  const url = urlInput.value.trim();

  const scoreElement = document.getElementById("ai-phishing-score");
  const levelElement = document.getElementById("ai-phishing-level");
  const reasonsElement = document.getElementById("ai-phishing-reasons");

  if (!url) {
    scoreElement.textContent = "N/A";
    levelElement.textContent = "N/A";
    reasonsElement.textContent = "Please enter a URL.";
    return;
  }

  // Set loading state
  scoreElement.textContent = "Analyzing...";
  levelElement.textContent = "";
  reasonsElement.textContent = "";

  const result = await predictPhishingRiskAI(url);

  scoreElement.textContent = `${result.score}%`;
  levelElement.textContent = result.level;
  reasonsElement.textContent = result.reason.join(", ");

  // Apply color based on risk level
  levelElement.className = `ai-risk-level-text risk-${result.level
    .toLowerCase()
    .replace(/ /g, "-")}`;
}
