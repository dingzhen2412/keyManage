import { readFileSync } from "node:fs";
import crypto from "node:crypto";
import vm from "node:vm";

const html = readFileSync("keygen.html", "utf8");
const start = html.indexOf("CORE-START");
const end = html.indexOf("CORE-END");
const core = html.slice(html.indexOf("*/", start) + 2, html.lastIndexOf("/*", end));
const ctx = vm.createContext({ console, TextEncoder });
vm.runInContext(core, ctx);

const enc = s => new TextEncoder().encode(s);
const hex = b => [...b].map(x => x.toString(16).padStart(2, "0")).join("");
let passed = 0, failed = 0;
const check = (name, cond) => {
  if (cond) { passed++; console.log("PASS", name); }
  else { failed++; console.log("FAIL", name); }
};

// 1. SHA-256 标准测试向量（"abc"）
check("sha256('abc') 官方向量",
  hex(vm.runInContext("sha256(new TextEncoder().encode('abc'))", ctx)) ===
  "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

// 2. SHA-256 空串
check("sha256('') 官方向量",
  hex(vm.runInContext("sha256(new TextEncoder().encode(''))", ctx)) ===
  "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

// 3. HMAC-SHA256 RFC4231 测试用例：key="Jefe" —— 期望值由 node crypto 权威生成
check("hmac RFC4231 向量（对拍 node crypto）",
  hex(vm.runInContext(
    "hmacSha256(new TextEncoder().encode('Jefe'), new TextEncoder().encode('what do ya want for nothing?'))",
    ctx)) ===
  crypto.createHmac("sha256", "Jefe").update("what do ya want for nothing?").digest("hex"));

// 4. 长消息（>64 字节，考验流水线分块）——期望值由 node crypto 权威生成
const longMsg = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
check("sha256 长消息（对拍 node crypto）",
  hex(vm.runInContext(
    "sha256(new TextEncoder().encode('" + longMsg + "'))", ctx)) ===
  crypto.createHash("sha256").update(longMsg).digest("hex"));

// 5. buildPassword：确定性
const seed = Uint8Array.from({ length: 32 }, (_, i) => i * 7 + 1);
const opts = { lower: true, upper: true, digit: true, symbol: true, noConfuse: false, len: 16 };
const pw1 = vm.runInContext("buildPassword", ctx)(seed, enc("微信|1380000|v1"), opts);
const pw2 = vm.runInContext("buildPassword", ctx)(seed, enc("微信|1380000|v1"), opts);
check("相同输入 → 输出一致", pw1 === pw2);
console.log("  示例密钥:", pw1);

// 6. 约束满足：长度、字符范围、每类至少一个
const okLen = pw1.length === 16;
const okRange = /^[a-zA-Z0-9!@#$%^&*()\-_=+\[\]{}?~]+$/.test(pw1);
const okClasses = /[a-z]/.test(pw1) && /[A-Z]/.test(pw1) && /[0-9]/.test(pw1) && /[!@#$%^&*()\-_=+\[\]{}?~]/.test(pw1);
check("长度=16", okLen);
check("字符全部在选项范围内", okRange);
check("小写/大写/数字/符号各至少一个", okClasses);

// 7. 版本号变化 → 密钥变化
const pw3 = vm.runInContext("buildPassword", ctx)(seed, enc("微信|1380000|v2"), opts);
check("版本号改变 → 新密钥", pw1 !== pw3);

// 8. 站点不同 → 密钥不同
const pw4 = vm.runInContext("buildPassword", ctx)(seed, enc("淘宝|1380000|v1"), opts);
check("站点不同 → 密钥不同", pw1 !== pw4);

// 9. 排除易混淆字符：只选大写+小写，禁易混
const pw5 = vm.runInContext("buildPassword", ctx)(seed, enc("测试|排除易混淆|v1"),
  { lower: true, upper: true, digit: true, symbol: false, noConfuse: true, len: 40 });
check("noConfuse 不含 0 O 1 l I", !/[0O1lI]/.test(pw5));

// 10. 纯数字模式
const pw6 = vm.runInContext("buildPassword", ctx)(seed, enc("银行卡|x|v1"),
  { lower: false, upper: false, digit: true, symbol: false, noConfuse: true, len: 12 });
check("纯数字模式输出全是数字", /^[23456789]{12}$/.test(pw6));

// 11. 最小长度 8、最大长度 64
const pw7 = vm.runInContext("buildPassword", ctx)(seed, enc("t|a|v1"), { ...opts, len: 8 });
const pw8 = vm.runInContext("buildPassword", ctx)(seed, enc("t|a|v9"), { ...opts, len: 64 });
check("长度边界 8/64", pw7.length === 8 && pw8.length === 64);

// 12. 熵估算取整可用
const bits = vm.runInContext("entropyBits", ctx)(opts);
check("entropyBits ≈ 16*6.5 ≈ 104", bits >= 100 && bits <= 108);

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
