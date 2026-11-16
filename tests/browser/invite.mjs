// End-to-end test of a home by invitation with the minimal pages, in a real browser: a registration without an invite
// and with a wrong one is refused before any recovery card is made; the invitation link fills the invite in, leaves the
// address bar, and registers; the pages that are not served answer 404 and nothing links to them. Run against a server
// started with ROOTCARD_SITE_URLS=$BASE ROOTCARD_SITE_INVITES=$INVITE ROOTCARD_SITE_PAGES=minimal (see the CI workflow).
import { createRequire } from "node:module";
const require = createRequire(import.meta.url);
const { chromium } = require("playwright");
const BASE = process.env.BASE ?? "http://127.0.0.1:8081";
const INVITE = process.env.INVITE ?? "e2e-invite-token";
const shots = process.env.SHOTS ?? "target/screenshots";
await import("node:fs").then((fs) => fs.mkdirSync(shots, { recursive: true }));
const user = "Invited" + Math.floor(Math.random() * 1e6);
const browser = await chromium.launch();
const ctx = await browser.newContext({ acceptDownloads: true, viewport: { width: 1280, height: 900 } });
const page = await ctx.newPage();
const problems = [];
page.on("console", (m) => {
  // The refused invite checks (403) and the pages that are not served (404) are expected.
  if ((m.type() === "error" || m.type() === "warning") && !/status of 40[34]/.test(m.text())) problems.push(`${m.type()}: ${m.text()}`);
});
page.on("pageerror", (e) => problems.push(`pageerror: ${e.message}`));
const fail = (msg) => {
  console.error("FAIL: " + msg);
  process.exit(1);
};
const step = (s) => console.log("ok: " + s);

async function fillCredentials() {
  await page.fill("#username", user);
  await page.fill("#password", "correct horse battery staple");
  await page.fill("#password2", "correct horse battery staple");
}

async function refused(invite, expect) {
  await page.goto(BASE + "/create");
  await page.fill("#invite", invite);
  await fillCredentials();
  await page.click("#step1 button[type=submit]");
  await page.waitForFunction((t) => document.querySelector("#status1").textContent.includes(t), expect, { timeout: 20000 })
    .catch(async () => fail(`status for invite ${JSON.stringify(invite)}: ${await page.textContent("#status1")}`));
  if (!(await page.isHidden("#step2"))) fail("a recovery card was made for a refused invite");
  if ((await page.getAttribute("#invite", "aria-invalid")) !== "true") fail("the invite field is not marked");
}
await refused("", "by invitation only");
step("no invite refused before the recovery card");
await refused("not-the-invite", "does not accept this invite");
step("wrong invite refused before the recovery card");

await page.goto(`${BASE}/create#invite=${INVITE}`);
if ((await page.inputValue("#invite")) !== INVITE) fail("the invitation link did not fill in the invite");
if (page.url() !== `${BASE}/create`) fail(`the invite stayed in the address bar: ${page.url()}`);
step("invitation link fills in the invite and leaves the address bar");
await fillCredentials();
await page.click("#step1 button[type=submit]");
await page.waitForSelector("#step2:not([hidden])", { timeout: 20000 }).catch(async () => fail(await page.textContent("#status1")));
await page.screenshot({ path: `${shots}/invite-create2.png` });
await Promise.all([page.waitForEvent("download"), page.click("#saveCard")]);
await page.check("#saved");
await page.click("#activate");
await page.waitForSelector("#step3:not([hidden])", { timeout: 60000 }).catch(async () => fail(await page.textContent("#status2")));
step("registered with the invite: " + (await page.textContent("#doneHandle")));

// The register endpoint itself refuses without the invite, whatever the page does.
const direct = await page.evaluate(async () => {
  const r = await fetch("/v0/id/register", { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" });
  return [r.status, (await r.json()).error];
});
if (direct[0] !== 403 || direct[1] !== "invite_required") fail(`register without invite: ${direct}`);
step("the API refuses a registration without an invite");

for (const gone of ["/developers", "/rootcard"]) {
  const r = await page.goto(BASE + gone);
  if (r.status() !== 404) fail(`${gone} answers ${r.status()}`);
}
for (const p of ["/", "/account", "/card", "/policy", "/keytool", "/create"]) {
  await page.goto(BASE + p);
  const links = await page.$$eval("a[href^='/developers'], a[href^='/rootcard']", (as) => as.map((a) => a.getAttribute("href")));
  if (links.length) fail(`${p} links to ${links.join(", ")}`);
}
await page.goto(BASE + "/");
await page.screenshot({ path: `${shots}/invite-home.png` });
step("minimal pages: the others answer 404 and nothing links to them");

if (problems.length) fail(problems.join("\n"));
await browser.close();
console.log("invite end to end passed");
