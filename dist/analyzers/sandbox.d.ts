/**
 * ClawGuard Behavioral Sandbox
 *
 * Runs skills in an isolated Docker container and monitors:
 * - File access (especially credential paths)
 * - Network activity (connections, DNS, HTTP)
 * - Process execution (shell commands, child processes)
 * - Environment variable access
 *
 * Uses honeypot files to detect credential theft attempts.
 */
import type { SandboxAnalyzer } from '../types.js';
declare const HONEYPOT_FILES: {
    path: string;
    content: string;
}[];
interface SandboxResult {
    exitCode: number;
    stdout: string;
    stderr: string;
    fileAccess: FileAccessEvent[];
    networkActivity: NetworkEvent[];
    processExecution: ProcessEvent[];
    honeypotHits: HoneypotHit[];
    duration: number;
}
interface FileAccessEvent {
    path: string;
    operation: 'read' | 'write' | 'stat' | 'open';
    timestamp: number;
}
interface NetworkEvent {
    destination: string;
    port: number;
    protocol: string;
    timestamp: number;
    data?: string;
}
interface ProcessEvent {
    command: string;
    args: string[];
    timestamp: number;
}
interface HoneypotHit {
    path: string;
    operation: string;
    timestamp: number;
}
/**
 * Check if Docker is available
 */
declare function isDockerAvailable(): Promise<boolean>;
/**
 * Run a skill in the sandbox
 */
declare function runInSandbox(skillPath: string, timeout?: number): Promise<SandboxResult>;
/**
 * Create a sandbox analyzer instance
 */
export declare function createSandboxAnalyzer(): SandboxAnalyzer;
export { HONEYPOT_FILES, SandboxResult, runInSandbox, isDockerAvailable };
export default createSandboxAnalyzer;
