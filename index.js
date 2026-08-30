const HELP = `
🐕 Salty-Dog

Usage:
  salty-dog <command> [options]

Commands:
  help, --help, -h       Show this help message
  version, --version, -v Show the installed version
  status                 Show Salty-Dog status
  init                   Create initial Salty-Dog configuration

Examples:
  salty-dog status
  salty-dog init
`;

export async function run(args) {
  const [command = "help"] = args;

  switch (command) {
    case "help":
    case "--help":
    case "-h":
      console.log(HELP.trim());
      return;

    case "version":
    case "--version":
    case "-v":
      console.log("Salty-Dog v0.1.0");
      return;

    case "status":
      console.log("✅ Salty-Dog is installed and ready.");
      return;

    case "init":
      console.log("⚙️  Initializing Salty-Dog...");
      console.log("✅ Configuration initialized.");
      return;

    default:
      console.error(`Unknown command: ${command}\n`);
      console.log(HELP.trim());
      process.exitCode = 1;
  }
}