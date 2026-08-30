#!/usr/bin/env node

import { run } from "../index.js";

try {
  await run(process.argv.slice(2));
} catch (error) {
  console.error("\n❌ Salty-Dog encountered an error.\n");
  console.error(error instanceof Error ? error.message : error);
  process.exitCode = 1;
}