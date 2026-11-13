// End-to-end test of the site in a real browser: register, sign in, profile, private data, export, proofs, password
// change, linked accounts (added, checked, removed), public lookup, proof verification on the card page, the host
// pointer, plus screenshots. Run against a local server started with
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

// Linked accounts (SPEC §12.3). The services are mocked here, so the test never depends on GitHub or the network: a
// GitHub account whose bio holds the token, and a website that does not serve it.
const token = (await page.textContent("#token")).trim();
const cors = { "access-control-allow-origin": "*", "content-type": "application/json" };
const githubCalls = [];
await ctx.route("https://api.github.com/**", (route) => {
  const u = new URL(route.request().url());
  githubCalls.push(u.pathname);
  if (u.pathname === "/users/linktester") return route.fulfill({ status: 200, headers: cors, body: JSON.stringify({ login: "LinkTester", id: 4242 }) });
  if (u.pathname === "/user/4242") {
    return route.fulfill({ status: 200, headers: cors, body: JSON.stringify({ login: "LinkTester", id: 4242, bio: `Me elsewhere: ${token}`, blog: null, score: 1.5 }) });
  }
  return route.fulfill({ status: 404, headers: cors, body: "{}" });
});
await ctx.route("https://example.test/**", (route) =>
  route.fulfill({ status: 200, headers: { "access-control-allow-origin": "*", "content-type": "text/plain" }, body: "rootcard:SOMEONEELSE\n" }));
await page.click("[data-tab=links]");
if (!/^rootcard:[0-9A-Z]{52}$/.test(token)) problems.push(`link token: ${token}`);
const linkStatus = async (re) => {
  await page.waitForFunction((r) => new RegExp(r).test(document.querySelector("#linksStatus").textContent), re.source, { timeout: 20000 }).catch(async (e) => {
    console.log("links:", await page.textContent("#linksStatus"));
    throw e;
  });
};
await page.selectOption("#lService", "github");
await page.fill("#lName", "linktester");
await page.click("#linksForm button[type=submit]");
await page.waitForSelector("#lConfirm:not([hidden])", { timeout: 20000 });
await linkStatus(/Verified by this browser/);
if ((await page.inputValue("#lUid")) !== "4242" || (await page.inputValue("#lName")) !== "LinkTester") problems.push("github uid not filled in");
await page.click("#lPublish");
await linkStatus(/Published/);
step("github link verified and published");
await page.selectOption("#lService", "web");
await page.fill("#lName", "example.test");
await page.click("#linksForm button[type=submit]");
await page.waitForSelector("#lConfirm:not([hidden])", { timeout: 20000 });
await linkStatus(/token is not where the link says/);
await page.click("#lPublish");
await linkStatus(/Published/);
if ((await page.$$("#linksList li")).length !== 2) problems.push("account page does not list both links");
await page.screenshot({ path: `${shots}/account-links.png`, fullPage: true });
step("web link published unverified");
// The profile form keeps the links.
await page.click("[data-tab=profile]");
await page.fill("#pAbout", "Hello <b>world</b>, linked");
await page.click("#profileForm button[type=submit]");
await page.waitForFunction(() => document.querySelector("#profileStatus").textContent.includes("Saved"), null, { timeout: 20000 });
const kept = await page.evaluate(async (acc) => {
  const r = await fetch(`/v0/id/${acc}/public`);
  const p = await r.json();
  return p.data["user.links"]?.links?.length;
}, token.slice("rootcard:".length));
if (kept !== 2) problems.push(`profile save dropped links: ${kept}`);

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
// A public statement proof: signed here, shared as a link, checked and stamped on the card page.
const statement = `I am ${user} on example.social, until 2099-12-31`;
await page.fill("#recipient", "https://example.social");
await page.fill("#challenge", JSON.stringify(statement));
await page.click("#proveForm button[type=submit]");
await page.waitForSelector("#openProof:not([hidden])");
const proofLink = await page.getAttribute("#openProof", "href");
const interactive = proofText;

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
// Take the unverified link off again: the page asks first, then says to take the token down too ([LNK-4]).
await page.click("[data-tab=links]");
page.once("dialog", (d) => d.accept());
await page.click("#linksList li:nth-child(2) .link-actions button:last-child");
await linkStatus(/Removed\. Remove the token too/);
if ((await page.$$("#linksList li")).length !== 1) problems.push("link not taken off");
step("web link taken off");

await page.goto(BASE + "/card?h=" + encodeURIComponent(handle));
await page.waitForSelector("#result:not([hidden])", { timeout: 20000 }).catch(async (e) => {
  console.log("card:", await page.textContent("#lookupStatus"));
  throw e;
});
step("card lookup: " + (await page.textContent("#rAbout")));
// The public half is never labelled "Recovery key", the name of the secret the key tool asks for ([PWR-6]).
const factLabels = await page.$$eval("#rFacts dt", (ds) => ds.map((d) => d.textContent));
if (factLabels.some((l) => /^recovery key$/i.test(l.trim())) || !factLabels.includes("Recovery public key")) {
  problems.push(`public key mislabelled on /card: ${factLabels.join(", ")}`);
}
// The card lists the link and fetches nothing until asked; then the viewer's browser checks it ([LNK-11]).
await page.waitForSelector("#rLinks:not([hidden])");
const before = githubCalls.length;
const linkText = await page.textContent("#rLinksList");
if (!linkText.includes("LinkTester") || !linkText.includes("not checked")) problems.push(`card links: ${linkText}`);
await page.click("#rLinksCheck");
await page.waitForSelector("#rLinksList .badge.ok", { timeout: 20000 });
if (githubCalls.length === before) problems.push("card page did not ask GitHub");
if ((await page.getAttribute("#rLinksList a", "href")) !== "https://github.com/LinkTester") problems.push("github display URL");
step("card link verified: " + (await page.textContent("#rLinksList .link-detail")));
await page.screenshot({ path: `${shots}/card.png` });

// Proofs on the card page ([PRF-4]): the stamp says what was checked.
const stampOf = async () => {
  await page.waitForSelector("#card .ic-stamp", { timeout: 20000 });
  return page.$eval("#card .ic-stamp", (e) => `${e.className} ${e.textContent}`);
};
await page.goto(proofLink);
let stamp = await stampOf();
if (!/\binfo\b/.test(stamp) || !(await page.textContent("#rProof")).includes(statement)) problems.push(`statement link: ${stamp}`);
step("statement link: " + stamp);
await page.screenshot({ path: `${shots}/card-statement.png` });
// The proof box checks as it changes: no button to press.
const waitStamp = (level) => page.waitForFunction((l) => document.querySelector(`#card .ic-stamp.${l}`), level, { timeout: 20000 });
await page.$eval("#proofMore", (d) => (d.open = true));
await page.fill("#proofRecipient", "https://example.social");
await waitStamp("ok");
step("statement for the named recipient: " + (await stampOf()));
await page.goto(BASE + "/card");
await page.click("#proofBox > summary");
await page.click("#proofMore > summary");
await page.fill("#proofChallenge", "ab".repeat(32));
await page.fill("#proofRecipient", "https://shop.example");
await page.fill("#proofText", interactive);
await waitStamp("ok").catch(() => {});
stamp = await stampOf();
if (!/\bok\b/.test(stamp)) problems.push(`interactive proof: ${stamp}`);
step("interactive proof: " + stamp);
if ((await page.$$("#rLog li")).length < 2) problems.push("log events not listed on /card");
await page.screenshot({ path: `${shots}/card-proof.png` });
await page.fill("#proofRecipient", "https://other.example");
await waitStamp("bad");
stamp = await stampOf();
if (!stamp.includes("wrong_recipient")) problems.push(`forwarded proof: ${stamp}`);
step("forwarded proof: " + stamp);
await page.screenshot({ path: `${shots}/card-proof-bad.png` });
await page.fill("#proofRecipient", "");
await page.fill("#proofChallenge", "");
await waitStamp("warn");
step("unchecked challenge: " + (await stampOf()));

// The host pointer ([HST-23]) names this origin as the base URL.
const pointer = await page.evaluate(async () => {
  const rc = await import("/vendor/rootcard/src/index.js");
  const res = await fetch(rc.WELL_KNOWN_PATH, { redirect: "manual" });
  return rc.wellKnownBase(location.origin, rc.parseLimited(new Uint8Array(await res.arrayBuffer()), rc.WELL_KNOWN_LIMIT));
});
if (pointer !== BASE) problems.push(`host pointer: ${pointer}`);
step("host pointer: " + pointer);
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
