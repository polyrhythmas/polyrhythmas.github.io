// Caeser Cipher Implementation

function caesarEncrypt(text, shift) {
  return text.replace(/[a-z]/gi, c => {
    const base = c <= 'Z' ? 65 : 97;
    return String.fromCharCode(
      ((c.charCodeAt(0) - base + shift) % 26) + base
    );
  });
}

function caesarDecrypt(text, shift) {
  return caesarEncrypt(text, 26 - shift);
}

// AES Helpers

function bufferToBase64(buffer) {
  return btoa(String.fromCharCode(...new Uint8Array(buffer)));
}

function base64ToBuffer(base64) {
  return Uint8Array.from(atob(base64), c => c.charCodeAt(0));
}

async function generateAESKey() {
  return crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"]
  );
}

async function exportKey(key) {
  const raw = await crypto.subtle.exportKey("raw", key);
  return bufferToBase64(raw);
}

async function importKey(base64) {
  const raw = base64ToBuffer(base64);
  return crypto.subtle.importKey(
    "raw",
    raw,
    "AES-GCM",
    true,
    ["encrypt", "decrypt"]
  );
}

// AES Implementation

async function aesEncrypt(message) {
  const key = await generateAESKey();
  const iv = crypto.getRandomValues(new Uint8Array(12));

  const encoded = new TextEncoder().encode(message);

  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    encoded
  );

  return {
    key: await exportKey(key),
    iv: bufferToBase64(iv),
    ciphertext: bufferToBase64(ciphertext)
  };
}

async function aesDecrypt(ciphertext, keyBase64, ivBase64) {
  const key = await importKey(keyBase64);
  const iv = base64ToBuffer(ivBase64);
  const data = base64ToBuffer(ciphertext);

  const decrypted = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv },
    key,
    data
  );

  return new TextDecoder().decode(decrypted);
}

// Encryption Implementation

async function encrypt() {
  const text = document.getElementById("plaintext").value;
  const cipher = document.getElementById("cipher").value;

  if (!text) return alert("Enter a message");

  if (cipher === "caesar") {
    const shift = Math.floor(Math.random() * 25) + 1;
    const encrypted = caesarEncrypt(text, shift);

    document.getElementById("encKey").value = shift;
    document.getElementById("ciphertext").value = encrypted;
  }

  if (cipher === "aes") {
    const result = await aesEncrypt(text);

    document.getElementById("encKey").value =
      `KEY:${result.key}\nIV:${result.iv}`;

    document.getElementById("ciphertext").value = result.ciphertext;
  }
}

// Decryption Implementation

async function decrypt() {
  const cipher = document.getElementById("decCipher").value;
  const keyText = document.getElementById("decKey").value.trim();
  const ciphertext = document.getElementById("decCiphertext").value;

  if (cipher === "caesar") {
    const shift = parseInt(keyText);
    const result = caesarDecrypt(ciphertext, shift);
    document.getElementById("decrypted").value = result;
  }

  if (cipher === "aes") {
    try {
      const lines = keyText.split("\n");
      const key = lines[0].replace("KEY:", "").trim();
      const iv = lines[1].replace("IV:", "").trim();

      const result = await aesDecrypt(ciphertext, key, iv);
      document.getElementById("decrypted").value = result;
    } catch {
      alert("Invalid AES key or ciphertext");
    }
  }
}

