// ================= UI TOGGLE =================
function updateEncryptUI(){
  const c=document.getElementById("encCipher").value;

  const showAES = c==="aes";

  document.getElementById("encKeyBox").style.display = showAES ? "none":"block";
  document.getElementById("encAESKeyBox").style.display = showAES ? "block":"none";
  document.getElementById("encIVBox").style.display = showAES ? "block":"none";
}

function updateDecryptUI(){
  const c=document.getElementById("decCipher").value;

  const showAES = c==="aes";

  document.getElementById("decKeyBox").style.display = showAES ? "none":"block";
  document.getElementById("decAESKeyBox").style.display = showAES ? "block":"none";
  document.getElementById("decIVBox").style.display = showAES ? "block":"none";
}

// ================= CAESAR =================

function caesarEncrypt(text, shift){
  shift = parseInt(shift);
  return text.replace(/[a-z]/gi, c=>{
    const base = c <= 'Z' ? 65 : 97;
    return String.fromCharCode(
      ((c.charCodeAt(0)-base+shift)%26)+base
    );
  });
}

function caesarDecrypt(text, shift){
  return caesarEncrypt(text, 26 - parseInt(shift));
}

// ================= PERMUTATION =================

function generatePermutationKey(size){
  let arr=[];
  for(let i=1;i<=size;i++) arr.push(i);

  for(let i=arr.length-1;i>0;i--){
    const j=Math.floor(Math.random()*(i+1));
    [arr[i],arr[j]]=[arr[j],arr[i]];
  }
  return arr;
}

function permutationEncrypt(text, perm){
  let result="";
  const n=perm.length;

  for(let i=0;i<text.length;i+=n){
    let block=text.slice(i,i+n);
    while(block.length<n) block+=" ";

    let newBlock=new Array(n);
    for(let j=0;j<n;j++){
      newBlock[j]=block[perm[j]-1];
    }
    result+=newBlock.join("");
  }
  return result;
}

function permutationDecrypt(text, perm){
  let result="";
  const n=perm.length;

  let inv=new Array(n);
  for(let i=0;i<n;i++) inv[perm[i]-1]=i;

  for(let i=0;i<text.length;i+=n){
    let block=text.slice(i,i+n);
    let newBlock=new Array(n);

    for(let j=0;j<n;j++){
      newBlock[j]=block[inv[j]];
    }
    result+=newBlock.join("");
  }
  return result.trimEnd();
}

// ================= AES =================

function bufferToBase64(buffer){
  return btoa(String.fromCharCode(...new Uint8Array(buffer)));
}

function base64ToBuffer(base64){
  return Uint8Array.from(atob(base64), c=>c.charCodeAt(0));
}

async function generateAESKey(){
  const key = await crypto.subtle.generateKey(
    {name:"AES-GCM", length:256},
    true,
    ["encrypt","decrypt"]
  );

  const raw = await crypto.subtle.exportKey("raw", key);
  return bufferToBase64(raw);
}

async function importAESKey(base64){
  const raw = base64ToBuffer(base64);
  return crypto.subtle.importKey(
    "raw",
    raw,
    "AES-GCM",
    true,
    ["encrypt","decrypt"]
  );
}

async function aesEncrypt(text,keyBase64,ivBase64){
  const key=await importAESKey(keyBase64);
  const iv=base64ToBuffer(ivBase64);

  const enc=new TextEncoder().encode(text);

  const ct=await crypto.subtle.encrypt(
    {name:"AES-GCM",iv},
    key,
    enc
  );

  return bufferToBase64(ct);
}

async function aesDecrypt(ciphertext, keyBase64, ivBase64){
  const key = await importAESKey(keyBase64);
  const iv = base64ToBuffer(ivBase64);
  const data = base64ToBuffer(ciphertext);

  const pt = await crypto.subtle.decrypt(
    {name:"AES-GCM", iv},
    key,
    data
  );

  return new TextDecoder().decode(pt);
}

// ================= KEY GENERATION =================

async function generateKey(){
  const cipher=document.getElementById("keyCipher").value;

  if(cipher==="caesar"){
    const shift=Math.floor(Math.random()*25)+1;
    document.getElementById("generatedKey").value=shift;
  }

  if(cipher==="permutation"){
    const size=parseInt(document.getElementById("permSize").value)||5;
    const perm=generatePermutationKey(size);
    document.getElementById("generatedKey").value=perm.join(" ");
  }

  if(cipher==="aes"){
    const key=await generateAESKey();
    document.getElementById("generatedKey").value=key;
  }
}

// ================= ENCRYPT =================

async function encrypt(){
  const cipher=document.getElementById("encCipher").value;
  const key=document.getElementById("encKey").value.trim();
  const text=document.getElementById("plaintext").value;

  if(cipher==="caesar"){
    document.getElementById("ciphertext").value=
      caesarEncrypt(text,key);
  }

  if(cipher==="permutation"){
    const perm=key.split(/\s+/).map(Number);
    document.getElementById("ciphertext").value=
      permutationEncrypt(text,perm);
  }

  if(cipher==="aes"){
  const key=document.getElementById("encAESKey").value.trim();
  let iv=document.getElementById("encIV").value.trim();

  if(!iv){
    const rand=crypto.getRandomValues(new Uint8Array(12));
    iv=btoa(String.fromCharCode(...rand));
    document.getElementById("encIV").value=iv;
  }

  const result=await aesEncrypt(text,key,iv);
  document.getElementById("ciphertext").value=result;
}

}

// ================= DECRYPT =================

async function decrypt(){
  const cipher=document.getElementById("decCipher").value;
  const key=document.getElementById("decKey").value.trim();
  const text=document.getElementById("decCiphertext").value.trim();

  if(cipher==="caesar"){
    document.getElementById("decrypted").value=
      caesarDecrypt(text,key);
  }

  if(cipher==="permutation"){
    const perm=key.split(/\s+/).map(Number);
    document.getElementById("decrypted").value=
      permutationDecrypt(text,perm);
  }

  if(cipher==="aes"){
  const key=document.getElementById("decAESKey").value.trim();
  const iv=document.getElementById("decIV").value.trim();
  const ct=text;

  const result=await aesDecrypt(ct,key,iv);
  document.getElementById("decrypted").value=result;
}

}
