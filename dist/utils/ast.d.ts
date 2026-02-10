/**
 * AST parsing utilities for JavaScript/TypeScript analysis
 */
import * as acorn from 'acorn';
import type { Finding } from '../types.js';
export interface AstFinding {
    type: string;
    line: number;
    column: number;
    evidence: string;
    description: string;
}
/**
 * Parse JavaScript/TypeScript source code into an AST
 */
export declare function parseJS(source: string, _filename: string): acorn.Node | null;
/**
 * Analyze an AST for dangerous patterns
 */
export declare function analyzeAST(ast: acorn.Node, source: string, _filename: string): AstFinding[];
/**
 * Convert AST findings to ClawGuard Finding format
 */
export declare function astFindingsToFindings(astFindings: AstFinding[], filename: string): Finding[];
