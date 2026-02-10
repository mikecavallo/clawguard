/**
 * AST parsing utilities for JavaScript/TypeScript analysis
 */
import * as acorn from 'acorn';
import * as walk from 'acorn-walk';
/**
 * Parse JavaScript/TypeScript source code into an AST
 */
export function parseJS(source, _filename) {
    try {
        return acorn.parse(source, {
            ecmaVersion: 'latest',
            sourceType: 'module',
            locations: true,
            allowHashBang: true,
            allowReserved: true,
        });
    }
    catch {
        // Try parsing as script if module fails
        try {
            return acorn.parse(source, {
                ecmaVersion: 'latest',
                sourceType: 'script',
                locations: true,
                allowHashBang: true,
                allowReserved: true,
            });
        }
        catch {
            // Could not parse - might be TypeScript or invalid JS
            return null;
        }
    }
}
/**
 * Get a snippet of the source around a position
 */
function getSnippet(source, start, end, maxLen = 100) {
    let snippet = source.slice(start, Math.min(end, start + maxLen));
    if (end - start > maxLen) {
        snippet += '...';
    }
    return snippet.replace(/\n/g, ' ').trim();
}
/**
 * Safely get a property from a node
 */
function getNodeProp(node, prop) {
    if (node && typeof node === 'object' && prop in node) {
        return node[prop];
    }
    return undefined;
}
/**
 * Check if a node is a call to a specific function name
 */
function isCallTo(node, name) {
    const type = getNodeProp(node, 'type');
    if (type !== 'CallExpression')
        return false;
    const callee = getNodeProp(node, 'callee');
    if (!callee)
        return false;
    const calleeType = getNodeProp(callee, 'type');
    const calleeName = getNodeProp(callee, 'name');
    // Direct call: eval(...)
    if (calleeType === 'Identifier' && calleeName === name) {
        return true;
    }
    return false;
}
/**
 * Check if a require/import has a dynamic (non-literal) argument
 */
function hasDynamicArgument(node) {
    const args = getNodeProp(node, 'arguments');
    if (!args || args.length === 0)
        return false;
    const firstArg = args[0];
    const argType = getNodeProp(firstArg, 'type');
    const argValue = getNodeProp(firstArg, 'value');
    // If the argument is not a literal string, it's dynamic
    return argType !== 'Literal' || typeof argValue !== 'string';
}
/**
 * Analyze an AST for dangerous patterns
 */
export function analyzeAST(ast, source, _filename) {
    const findings = [];
    // Use simple walk with base
    walk.simple(ast, {
        CallExpression(node) {
            const loc = node.loc;
            const line = loc?.start?.line ?? 0;
            const column = loc?.start?.column ?? 0;
            const callee = getNodeProp(node, 'callee');
            const calleeName = getNodeProp(callee, 'name');
            const calleeType = getNodeProp(callee, 'type');
            const args = getNodeProp(node, 'arguments');
            // Check for eval() with non-literal argument
            if (isCallTo(node, 'eval')) {
                if (args && args.length > 0 && getNodeProp(args[0], 'type') !== 'Literal') {
                    findings.push({
                        type: 'eval-dynamic',
                        line,
                        column,
                        evidence: getSnippet(source, node.start, node.end),
                        description: 'eval() called with dynamic argument - potential code injection',
                    });
                }
                else if (args && args.length > 0) {
                    findings.push({
                        type: 'eval-literal',
                        line,
                        column,
                        evidence: getSnippet(source, node.start, node.end),
                        description: 'eval() used - consider alternatives',
                    });
                }
            }
            // Check for Function() constructor
            if (isCallTo(node, 'Function')) {
                findings.push({
                    type: 'function-constructor',
                    line,
                    column,
                    evidence: getSnippet(source, node.start, node.end),
                    description: 'Function() constructor used - equivalent to eval()',
                });
            }
            // Check for dynamic require()
            if (isCallTo(node, 'require') && hasDynamicArgument(node)) {
                findings.push({
                    type: 'dynamic-require',
                    line,
                    column,
                    evidence: getSnippet(source, node.start, node.end),
                    description: 'require() with dynamic argument - potential dependency injection',
                });
            }
            // Check for child_process usage
            if (isCallTo(node, 'require')) {
                if (args && args.length > 0) {
                    const firstArg = args[0];
                    if (getNodeProp(firstArg, 'type') === 'Literal') {
                        const modName = getNodeProp(firstArg, 'value');
                        if (modName === 'child_process') {
                            findings.push({
                                type: 'child-process-import',
                                line,
                                column,
                                evidence: getSnippet(source, node.start, node.end),
                                description: 'child_process module imported - can execute arbitrary commands',
                            });
                        }
                    }
                }
            }
            // Check for exec/spawn/execSync calls
            const dangerousMethods = ['exec', 'execSync', 'spawn', 'spawnSync', 'execFile', 'execFileSync', 'fork'];
            // Check direct call (unlikely but possible if destructured)
            if (calleeName && dangerousMethods.includes(calleeName)) {
                findings.push({
                    type: 'shell-execution',
                    line,
                    column,
                    evidence: getSnippet(source, node.start, node.end),
                    description: `${calleeName}() called - shell command execution`,
                });
            }
            // Check as method call on various objects
            if (calleeType === 'MemberExpression') {
                const prop = getNodeProp(callee, 'property');
                const propType = getNodeProp(prop, 'type');
                const propName = getNodeProp(prop, 'name');
                if (propType === 'Identifier' && propName && dangerousMethods.includes(propName)) {
                    findings.push({
                        type: 'shell-execution',
                        line,
                        column,
                        evidence: getSnippet(source, node.start, node.end),
                        description: `${propName}() called - shell command execution`,
                    });
                }
            }
            // Check for fetch() usage
            if (isCallTo(node, 'fetch')) {
                findings.push({
                    type: 'network-fetch',
                    line,
                    column,
                    evidence: getSnippet(source, node.start, node.end),
                    description: 'fetch() used - verify the URL is trusted',
                });
            }
            // Check for setTimeout/setInterval with string argument (eval-like)
            if (isCallTo(node, 'setTimeout') || isCallTo(node, 'setInterval')) {
                if (args && args.length > 0) {
                    const firstArg = args[0];
                    if (getNodeProp(firstArg, 'type') === 'Literal' &&
                        typeof getNodeProp(firstArg, 'value') === 'string') {
                        findings.push({
                            type: 'timer-string-eval',
                            line,
                            column,
                            evidence: getSnippet(source, node.start, node.end),
                            description: 'setTimeout/setInterval with string argument - equivalent to eval()',
                        });
                    }
                }
            }
        },
        NewExpression(node) {
            const loc = node.loc;
            const line = loc?.start?.line ?? 0;
            const column = loc?.start?.column ?? 0;
            const callee = getNodeProp(node, 'callee');
            // Check for new Function()
            if (getNodeProp(callee, 'type') === 'Identifier' &&
                getNodeProp(callee, 'name') === 'Function') {
                findings.push({
                    type: 'function-constructor',
                    line,
                    column,
                    evidence: getSnippet(source, node.start, node.end),
                    description: 'new Function() used - equivalent to eval()',
                });
            }
        },
        ImportDeclaration(node) {
            const loc = node.loc;
            const line = loc?.start?.line ?? 0;
            const column = loc?.start?.column ?? 0;
            const sourceNode = getNodeProp(node, 'source');
            if (getNodeProp(sourceNode, 'type') === 'Literal' &&
                getNodeProp(sourceNode, 'value') === 'child_process') {
                findings.push({
                    type: 'child-process-import',
                    line,
                    column,
                    evidence: getSnippet(source, node.start, node.end),
                    description: 'child_process module imported - can execute arbitrary commands',
                });
            }
        },
        ImportExpression(node) {
            const loc = node.loc;
            const line = loc?.start?.line ?? 0;
            const column = loc?.start?.column ?? 0;
            const sourceNode = getNodeProp(node, 'source');
            // Dynamic import with non-literal source
            if (sourceNode && getNodeProp(sourceNode, 'type') !== 'Literal') {
                findings.push({
                    type: 'dynamic-import',
                    line,
                    column,
                    evidence: getSnippet(source, node.start, node.end),
                    description: 'Dynamic import() with variable path - potential dependency injection',
                });
            }
        },
    });
    return findings;
}
/**
 * Convert AST findings to ClawGuard Finding format
 */
export function astFindingsToFindings(astFindings, filename) {
    return astFindings.map((af) => {
        let severity = 'medium';
        let id = 'T-CODE-AST';
        switch (af.type) {
            case 'eval-dynamic':
                id = 'T-CODE-003';
                severity = 'critical';
                break;
            case 'eval-literal':
                id = 'T-CODE-003';
                severity = 'high';
                break;
            case 'function-constructor':
                id = 'T-CODE-003';
                severity = 'critical';
                break;
            case 'dynamic-require':
            case 'dynamic-import':
                id = 'T-CODE-004';
                severity = 'high';
                break;
            case 'child-process-import':
                id = 'T-CODE-005';
                severity = 'high';
                break;
            case 'shell-execution':
                id = 'T-CODE-005';
                severity = 'high';
                break;
            case 'timer-string-eval':
                id = 'T-CODE-003';
                severity = 'high';
                break;
            case 'network-fetch':
                id = 'T-CODE-006';
                severity = 'low';
                break;
        }
        return {
            id,
            category: 'code',
            severity,
            title: af.description.split(' - ')[0],
            description: af.description,
            location: `${filename}:${af.line}`,
            evidence: af.evidence,
            remediation: getRemediation(af.type),
        };
    });
}
function getRemediation(type) {
    switch (type) {
        case 'eval-dynamic':
        case 'eval-literal':
            return 'Avoid eval(). Use JSON.parse() for JSON, or restructure code to avoid dynamic execution.';
        case 'function-constructor':
            return 'Avoid Function(). Restructure code to use static function definitions.';
        case 'dynamic-require':
        case 'dynamic-import':
            return 'Use static imports/requires. If dynamic loading is necessary, validate the module path against an allowlist.';
        case 'child-process-import':
        case 'shell-execution':
            return 'Minimize shell command usage. If necessary, never interpolate user input directly; use parameterized commands.';
        case 'timer-string-eval':
            return 'Pass a function reference to setTimeout/setInterval instead of a string.';
        case 'network-fetch':
            return 'Ensure fetch URLs are hardcoded or validated against an allowlist. Never execute fetched content.';
        default:
            return 'Review this code pattern for potential security issues.';
    }
}
