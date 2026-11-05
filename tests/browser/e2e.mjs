// End-to-end test of the site in a real browser: register, sign in, profile, private data, export, proof, password
// change, public lookup, plus screenshots. Run against a local server started with
// ROOTCARD_SITE_URLS=http://127.0.0.1:8080 (see README). Needs Playwright; not part of the binary.
import { createRequire } from "node:module";
const require = createRequire(import.meta.url);
const { chromium } = require("playwright");
const BASE = process.env.BASE ?? "http://127.0.0.1:8080";
const shots = process.env.SHOTS ?? "target/screenshots";
await import("node:fs").then((fs) => fs.mkdirSync(shots, { recursive: true }));
const user = "Tester" + Math.floor(Math.random() * 1e6);
const browser = await chromium.launch();
const ctx = await browser.newContext({ acceptDownloads: true, viewport: { width: 1280, height: 900 } });
const page = await ctx.newPage();
const problems = [];
page.on("console", (m) => { if (m.type() === "error" || m.type() === "warning") problems.push(`${m.type()}: ${m.text()}`); });
page.on("pageerror", (e) => problems.push(`pageerror: ${e.message}`));
const t0 = Date.now();
const step = (s) => console.log(`[${((Date.now() - t0) / 1000).toFixed(1)}s] ${s}`);

await page.goto(BASE + "/");
await page.screenshot({ path: `${shots}/home.png`, fullPage: false });
step("home ok");
await page.goto(BASE + "/create");
await page.fill("#username", user);
await page.fill("#password", "correct horse battery staple");
await page.fill("#password2", "correct horse battery staple");
await page.click("#step1 button[type=submit]");
await page.waitForSelector("#step2:not([hidden])", { timeout: 20000 });
step("card prepared");
await page.screenshot({ path: `${shots}/create2.png` });
const [dl] = await Promise.all([page.waitForEvent("download"), page.click("#saveCard")]);
const cardPath = `${shots}/card.json`;
await dl.saveAs(cardPath);
await page.check("#saved");
await page.click("#activate");
await page.waitForSelector("#step3:not([hidden])", { timeout: 60000 }).catch(async (e) => {
  console.log("status2:", await page.textContent("#status2"));
  throw e;
});
const handle = await page.textContent("#doneHandle");
step("registered " + handle);
await page.screenshot({ path: `${shots}/create3.png` });

await page.goto(BASE + "/account?h=" + encodeURIComponent(handle));
await page.fill("#password", "correct horse battery staple");
await page.click("#signinForm button[type=submit]");
await page.waitForSelector("#signedIn:not([hidden])", { timeout: 60000 }).catch(async (e) => {
  console.log("signin:", await page.textContent("#signinStatus"));
  throw e;
});
step("signed in");
await page.screenshot({ path: `${shots}/account.png` });
await page.click("[data-tab=profile]");
await page.fill("#pName", "Test Person");
await page.fill("#pAbout", "Hello <b>world</b>");
await page.fill("#pNote", "secret note");
await page.click("#profileForm button[type=submit]");
await page.waitForFunction(() => document.querySelector("#profileStatus").textContent.includes("Saved"), null, { timeout: 20000 }).catch(async (e) => {
  console.log("profile:", await page.textContent("#profileStatus"));
  throw e;
});
step("profile saved");
const [exp] = await Promise.all([page.waitForEvent("download"), (async () => { await page.click("[data-tab=overview]"); await page.click("#export"); })()]);
step("exported " + exp.suggestedFilename());
await page.click("[data-tab=prove]");
await page.fill("#recipient", "https://shop.example");
await page.fill("#challenge", "ab".repeat(32));
await page.click("#proveForm button[type=submit]");
await page.waitForSelector("#proofOut:not([hidden])");
const proofText = await page.textContent("#proofOut");
step("proof len " + proofText.length);
// verify proof with the vendored module in the page
const ok = await page.evaluate(async (t) => {
  const rc = await import("/vendor/rootcard/src/index.js");
  const v = rc.parseJson(new TextEncoder().encode(t));
  const st = await rc.verifyProof(v.proof, v.log, rc.hexDecode("ab".repeat(32)), "https://shop.example", { realms: ["global"], now: Math.floor(Date.now() / 1000) });
  return st.handle;
}, proofText);
step("proof verified for " + ok);

await page.click("[data-tab=password]");
await page.fill("#newPassword", "another long passphrase 42");
await page.fill("#newPassword2", "another long passphrase 42");
await page.click("#passwordForm button[type=submit]");
await page.waitForSelector("#signedOut:not([hidden])", { timeout: 60000 }).catch(async (e) => {
  console.log("pw:", await page.textContent("#passwordStatus"));
  throw e;
});
step("password changed: " + (await page.textContent("#signinStatus")));
await page.fill("#password", "correct horse battery staple");
await page.click("#signinForm button[type=submit]");
await page.waitForFunction(() => document.querySelector("#signinStatus .notice.error"), null, { timeout: 60000 });
step("old password rejected: " + (await page.textContent("#signinStatus")));
await page.fill("#password", "another long passphrase 42");
await page.click("#signinForm button[type=submit]");
await page.waitForSelector("#signedIn:not([hidden])", { timeout: 60000 });
step("signed in with new password; note=" + (await page.inputValue("#pNote")));

await page.goto(BASE + "/card?h=" + encodeURIComponent(handle));
await page.waitForSelector("#result:not([hidden])", { timeout: 20000 }).catch(async (e) => {
  console.log("card:", await page.textContent("#lookupStatus"));
  throw e;
});
step("card lookup: " + (await page.textContent("#rAbout")));
await page.screenshot({ path: `${shots}/card.png` });
for (const p of ["/developers", "/keytool", "/nope"]) {
  await page.goto(BASE + p);
  await page.screenshot({ path: `${shots}/${p.slice(1)}.png`, fullPage: true });
}
const m = await browser.newContext({ ...require("playwright").devices["Pixel 7"] });
const mp = await m.newPage();
mp.on("pageerror", (e) => problems.push(`mobile pageerror: ${e.message}`));
await mp.goto(BASE + "/");
await mp.screenshot({ path: `${shots}/mobile-home.png` });
await mp.click(".menu-toggle");
await mp.screenshot({ path: `${shots}/mobile-menu.png` });
await mp.goto(BASE + "/create");
await mp.screenshot({ path: `${shots}/mobile-create.png`, fullPage: true });
const unexpected = problems.filter((p) => !/status of (400|404)/.test(p));
console.log("console:", problems);
if (unexpected.length) { console.error("unexpected browser errors:", unexpected); process.exit(1); }
await browser.close();
