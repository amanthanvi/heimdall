// Hello-world used for the Bun env-hook research. Prints only non-secret facts.
console.log("HELLO_MAIN argv_len=" + process.argv.length + " execArgv=" + JSON.stringify(process.execArgv));
setTimeout(() => console.log("HELLO_DONE"), 2000);
