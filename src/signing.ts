/**
 * ClawGuard Skill Signing
 * 
 * Cryptographic provenance for skills:
 * - Generate keypairs for authors
 * - Sign skills with private key
 * - Verify signatures
 * - Chain of trust (author → auditor → registry)
 */

import { createSign, createVerify, generateKeyPairSync, createHash } from 'crypto';
import { readFile, writeFile, mkdir } from 'fs/promises';
import { join } from 'path';
import { homedir } from 'os';
import { glob } from 'glob';

const KEYS_DIR = join(homedir(), '.config', 'clawguard', 'keys');
const SIGNATURE_FILE = 'SIGNATURE.json';

export interface SkillSignature {
  version: '1.0';
  skillHash: string;
  author: {
    id: string;
    publicKey: string;
    signature: string;
    signedAt: string;
  };
  audits?: Array<{
    auditorId: string;
    auditorPublicKey: string;
    signature: string;
    auditedAt: string;
    riskLevel: string;
    notes?: string;
  }>;
}

export interface KeyPair {
  publicKey: string;
  privateKey: string;
  id: string;
  createdAt: string;
}

/**
 * Generate a new keypair for signing
 */
export async function generateKeyPair(authorId: string): Promise<KeyPair> {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519', {
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
  });

  const keyPair: KeyPair = {
    publicKey,
    privateKey,
    id: authorId,
    createdAt: new Date().toISOString()
  };

  // Save to keys directory
  await mkdir(KEYS_DIR, { recursive: true });
  await writeFile(
    join(KEYS_DIR, `${authorId}.json`),
    JSON.stringify(keyPair, null, 2),
    { mode: 0o600 }
  );

  console.log(`✓ Keypair generated for ${authorId}`);
  console.log(`  Private key: ${join(KEYS_DIR, `${authorId}.json`)}`);
  console.log(`  Public key ID: ${authorId}`);

  return keyPair;
}

/**
 * Load keypair from disk
 */
export async function loadKeyPair(authorId: string): Promise<KeyPair | null> {
  try {
    const data = await readFile(join(KEYS_DIR, `${authorId}.json`), 'utf-8');
    return JSON.parse(data);
  } catch {
    return null;
  }
}

/**
 * Calculate deterministic hash of skill contents
 */
export async function hashSkill(skillPath: string): Promise<string> {
  const files = await glob('**/*.{md,js,ts,py,sh,json,yaml,yml}', {
    cwd: skillPath,
    ignore: ['node_modules/**', '.git/**', SIGNATURE_FILE],
    nodir: true
  });

  const hash = createHash('sha256');
  
  for (const file of files.sort()) {
    const content = await readFile(join(skillPath, file), 'utf-8');
    hash.update(`${file}:${content}`);
  }

  return hash.digest('hex');
}

/**
 * Sign a skill
 */
export async function signSkill(
  skillPath: string,
  authorId: string
): Promise<SkillSignature> {
  const keyPair = await loadKeyPair(authorId);
  if (!keyPair) {
    throw new Error(`No keypair found for ${authorId}. Run: clawguard sign --generate ${authorId}`);
  }

  const skillHash = await hashSkill(skillPath);
  
  // Create signature
  const sign = createSign('SHA256');
  sign.update(skillHash);
  const signature = sign.sign(keyPair.privateKey, 'base64');

  const sig: SkillSignature = {
    version: '1.0',
    skillHash,
    author: {
      id: authorId,
      publicKey: keyPair.publicKey,
      signature,
      signedAt: new Date().toISOString()
    }
  };

  // Write signature file
  await writeFile(
    join(skillPath, SIGNATURE_FILE),
    JSON.stringify(sig, null, 2)
  );

  console.log(`✓ Skill signed by ${authorId}`);
  console.log(`  Hash: ${skillHash.slice(0, 16)}...`);
  console.log(`  Signature: ${join(skillPath, SIGNATURE_FILE)}`);

  return sig;
}

/**
 * Verify skill signature
 */
export async function verifySkill(skillPath: string): Promise<{
  valid: boolean;
  author?: string;
  signedAt?: string;
  audits?: number;
  error?: string;
}> {
  try {
    const sigPath = join(skillPath, SIGNATURE_FILE);
    const sigData = await readFile(sigPath, 'utf-8');
    const sig: SkillSignature = JSON.parse(sigData);

    // Recalculate hash
    const currentHash = await hashSkill(skillPath);
    
    if (currentHash !== sig.skillHash) {
      return {
        valid: false,
        error: 'Skill content has been modified since signing'
      };
    }

    // Verify author signature
    const verify = createVerify('SHA256');
    verify.update(sig.skillHash);
    const validSig = verify.verify(sig.author.publicKey, sig.author.signature, 'base64');

    if (!validSig) {
      return {
        valid: false,
        error: 'Invalid author signature'
      };
    }

    return {
      valid: true,
      author: sig.author.id,
      signedAt: sig.author.signedAt,
      audits: sig.audits?.length || 0
    };
  } catch (error) {
    return {
      valid: false,
      error: `No valid signature: ${(error as Error).message}`
    };
  }
}

/**
 * Add audit signature to skill
 */
export async function auditSkill(
  skillPath: string,
  auditorId: string,
  riskLevel: string,
  notes?: string
): Promise<void> {
  const keyPair = await loadKeyPair(auditorId);
  if (!keyPair) {
    throw new Error(`No keypair found for ${auditorId}`);
  }

  const sigPath = join(skillPath, SIGNATURE_FILE);
  const sigData = await readFile(sigPath, 'utf-8');
  const sig: SkillSignature = JSON.parse(sigData);

  // Sign the skill hash + our audit
  const auditData = `${sig.skillHash}:${auditorId}:${riskLevel}:${notes || ''}`;
  const sign = createSign('SHA256');
  sign.update(auditData);
  const signature = sign.sign(keyPair.privateKey, 'base64');

  // Add audit
  sig.audits = sig.audits || [];
  sig.audits.push({
    auditorId,
    auditorPublicKey: keyPair.publicKey,
    signature,
    auditedAt: new Date().toISOString(),
    riskLevel,
    notes
  });

  await writeFile(sigPath, JSON.stringify(sig, null, 2));
  
  console.log(`✓ Audit added by ${auditorId}`);
  console.log(`  Risk level: ${riskLevel}`);
  console.log(`  Total audits: ${sig.audits.length}`);
}
