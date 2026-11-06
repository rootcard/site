// The front page: two example cards and the number of cards at home here.
import { HOME, REALM, renderCard, tilt } from "/js/common.js";

const SAMPLE = "3F9CQ7M2K8XH4T1VZ6RBNW0J5PDGA9SE3YC7KFM2HQ8T4V1XZ6RB";
const front = document.getElementById("heroFront");
const back = document.getElementById("heroBack");
renderCard(front, { username: "Astra", account: SAMPLE, realm: REALM, home: HOME.url, since: 1793318400, display: "Astra Lindqvist", verified: true });
renderCard(back, { username: "Astra", account: SAMPLE, realm: REALM, recovery: true, key: "RCR 7QK2 M9XD 4TF1 VZ6R BNW0 J5PD GA9S E3YC 7KFM 2HQ8 T4V1 XZ6R" });
tilt(front, "rotate(-4deg)");

fetch("/stats.json", { cache: "no-store" })
  .then((r) => (r.ok ? r.json() : null))
  .then((s) => {
    if (!s || !Number.isInteger(s.cards)) return;
    document.getElementById("statCards").textContent = s.cards.toLocaleString("en");
    document.getElementById("stats").hidden = false;
  })
  .catch(() => {});
