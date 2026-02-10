#!/usr/bin/env node
/**
 * ClawGuard CLI
 * Revolutionary security scanner for AI agent skills
 */
import { Command } from 'commander';
import { registerScanCommands, registerLibraryCommands, registerAnalysisCommands, registerConfigCommands, registerToolCommands, registerServiceCommands, registerInfoCommands, registerUpdateCommands, } from './commands/index.js';
const VERSION = '1.0.0';
function createProgram() {
    const program = new Command();
    program
        .name('clawguard')
        .description('Revolutionary security scanner for AI agent skills')
        .version(VERSION);
    // Register all command modules
    registerScanCommands(program);
    registerLibraryCommands(program);
    registerAnalysisCommands(program);
    registerConfigCommands(program);
    registerToolCommands(program);
    registerServiceCommands(program);
    registerInfoCommands(program);
    registerUpdateCommands(program);
    return program;
}
async function main() {
    const program = createProgram();
    await program.parseAsync(process.argv);
}
main().catch((error) => {
    console.error('Fatal error:', error);
    process.exit(1);
});
