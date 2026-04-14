#!/usr/bin/env node
"use strict";

const fs = require("node:fs");
const proc = process;

const SUBMODULE_PREFIXES = ["ETHFALCON/", "ETHDILITHIUM/"];
const LOCATION_SEARCH_WINDOW = 6;

function main() {
  const logPath = proc.argv[2];
  if (!logPath) {
    console.error("usage: check-compile-warnings.js <log-path>");
    proc.exit (2);
  }

  let content;
  try {
    content = fs.readFileSync(logPath, "utf8");
  } catch (err) {
    console.error("cannot read " + logPath + ": " + err.message);
    proc.exit (2);
  }

  const lines = content.split("\n");
  let bad = false;
  let okCount = 0;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const isError = /^Error:/.test(line);
    const isWarning = /^Warning:/.test(line);
    if (!isError && !isWarning) continue;

    if (isError) {
      console.error("compile: error: " + line);
      bad = true;
      continue;
    }

    let location = null;
    const windowEnd = Math.min(i + LOCATION_SEARCH_WINDOW, lines.length);
    for (let j = i + 1; j < windowEnd; j++) {
      const m = lines[j].match(/-->\s+(\S+?):\d+:\d+:?/);
      if (m) {
        location = m[1];
        break;
      }
    }

    if (location === null) {
      console.error("compile: warning without locatable source: " + line);
      bad = true;
      continue;
    }

    const normalized = location.replace(/^\.\//, "");
    const isSubmodule = SUBMODULE_PREFIXES.some((p) => normalized.startsWith(p));
    if (isSubmodule) {
      okCount += 1;
      console.error("compile: tolerated submodule warning at " + normalized);
      continue;
    }

    console.error("compile: warning at " + normalized + " => failing: " + line);
    bad = true;
  }

  if (okCount > 0 && !bad) {
    console.error("compile: " + okCount + " tolerated submodule warning(s); project contracts clean");
  }
  proc.exit (bad ? 1 : 0);
}

main();
