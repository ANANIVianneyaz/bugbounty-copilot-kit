import fs from "fs";
// Analyse du lien de reinitialisation de mot de passe (entropie du token) — non destructif.
const link = (process.env.RESET_LINK || "").trim();
if (!link) { console.log("!! RESET_LINK manquant"); process.exit(1); }
console.log("lien : " + link.replace(/([?&](token|t|code|otp)=[^&]{0,6})[^&]*/i, "$1***"));
let u;
try { u = new URL(link); } catch (e) { console.log("URL invalide"); process.exit(1); }
console.log("hote  : " + u.host);
console.log("chemin: " + u.pathname);
console.log("params: " + [...u.searchParams.keys()].join(", "));
const CAND = ["token", "t", "code", "otp", "key", "resetToken", "verificationToken"];
let tok = null, name = null;
for (const k of CAND) { const v = u.searchParams.get(k); if (v) { tok = v; name = k; break; } }
if (!tok) { const seg = u.pathname.split("/").filter(Boolean).pop(); tok = seg; name = "segment du chemin"; }
console.log("\nTOKEN (" + name + ") :");
console.log("  valeur brute : " + tok);
console.log("  longueur     : " + tok.length);
console.log("  alphabet     : " + [...new Set(tok.split(""))].join(""));
const al = [...new Set(tok.split(""))].length;
console.log("  alphabet size: " + al);
console.log("  entropie     : ~" + (al * Math.log2(al) * tok.length).toFixed(0) + " bits (estimation)");
const isHex = /^[0-9a-f]+$/i.test(tok);
const isDigits = /^[0-9]+$/.test(tok);
console.log("  type         : " + (isDigits ? "CHIFFRES UNIQUEMENT" : isHex ? "hexadécimal" : "alphanumérique"));
if (isDigits) console.log("  >>> ESPACE DE RECHERCHE : " + tok.length + " chiffres = 10^" + tok.length + " combinaisons" + (tok.length === 6 ? "  (brutable)" : ""));
if (isHex && tok.length <= 16) console.log("  >>> ESPACE DE RECHERCHE : 16^" + tok.length + " = 2^" + (4 * tok.length) + " combinaisons");
console.log("\n(non destructif : aucune reinitialisation n est effectuee)");
