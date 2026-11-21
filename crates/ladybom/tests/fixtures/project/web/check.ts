declare function require(name: string): (value: unknown) => boolean;
const isNumber = require("is-number");
if (!isNumber("42") || isNumber("no")) {
  throw new Error("runtime dependency failed");
}
console.log("typescript/npm dependencies OK");
