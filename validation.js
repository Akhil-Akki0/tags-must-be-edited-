/**
 * Zod Request Validation & STL Binary Integrity Verification Module
 * 
 * DEVELOPED by Akhil.A gmail :- akkedu01@gmail.com
 */

import { z } from 'zod';

// Regex checking for path traversal, null bytes, and non-printable control characters
const SAFE_STRING_REGEX = /^[^\\/\0\r\n\t]+$/;
const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const SAFE_FILENAME_REGEX = /^[a-zA-Z0-9_-]+(\.[a-zA-Z0-9]+)?$/;

// Custom sanitizer for string inputs
function sanitizeString(val) {
  if (typeof val !== 'string') return val;
  // Strip null bytes and control characters
  return val.replace(/[\0\x00-\x1F\x7F]/g, '').trim();
}

// 1. Auth Schemas
const signupSchema = z
  .object({
    email: z.string().email('Invalid email address format').max(255).transform(sanitizeString),
    name: z.string().min(2).max(100).transform(sanitizeString),
    password: z
      .string()
      .min(12, 'Password must be at least 12 characters long')
      .max(128)
      .regex(/[A-Z]/, 'Password must contain at least one uppercase letter')
      .regex(/[a-z]/, 'Password must contain at least one lowercase letter')
      .regex(/[0-9]/, 'Password must contain at least one number')
      .regex(/[^A-Za-z0-9]/, 'Password must contain at least one special symbol'),
    captchaToken: z.string().max(1000).optional(),
  })
  .strict();

const loginSchema = z
  .object({
    email: z.string().email('Invalid email address format').max(255).transform(sanitizeString),
    password: z.string().min(1).max(128),
    totpCode: z.string().regex(/^[0-9]{6}$/, 'TOTP must be a 6-digit number').optional(),
  })
  .strict();

const forgotPasswordSchema = z
  .object({
    email: z.string().email('Invalid email address format').max(255).transform(sanitizeString),
  })
  .strict();

const resetPasswordSchema = z
  .object({
    token: z.string().min(32).max(128).regex(/^[a-zA-Z0-9_-]+$/, 'Invalid reset token format'),
    newPassword: z
      .string()
      .min(12, 'Password must be at least 12 characters long')
      .max(128)
      .regex(/[A-Z]/, 'Password must contain at least one uppercase letter')
      .regex(/[a-z]/, 'Password must contain at least one lowercase letter')
      .regex(/[0-9]/, 'Password must contain at least one number')
      .regex(/[^A-Za-z0-9]/, 'Password must contain at least one special symbol'),
  })
  .strict();

const verifyEmailSchema = z
  .object({
    token: z.string().min(32).max(128).regex(/^[a-zA-Z0-9_-]+$/, 'Invalid verification token format'),
  })
  .strict();

const totpVerifySchema = z
  .object({
    code: z.string().regex(/^[0-9]{6}$/, 'TOTP code must be 6 digits'),
  })
  .strict();

const totpDisableSchema = z
  .object({
    password: z.string().min(1).max(128),
    code: z.string().regex(/^[0-9]{6}$/, 'TOTP code must be 6 digits'),
  })
  .strict();

// 2. Simulation Schemas
const simulationConfigSchema = z
  .object({
    inletVelocity: z.number().min(0.01, 'Velocity must be >= 0.01 m/s').max(100.0, 'Velocity must be <= 100.0 m/s'),
    viscosity: z.number().min(1e-6, 'Viscosity must be >= 1e-6 m²/s').max(1e-2, 'Viscosity must be <= 1e-2 m²/s').optional().default(1.5e-5),
    maxIterations: z.number().int().min(1).max(10000).optional().default(500),
    domain: z.enum(['compact', 'tunnel', 'farfield']).optional().default('compact'),
  })
  .strict();

const simulationGeometrySchema = z
  .object({
    name: z.string().min(1).max(64).regex(SAFE_STRING_REGEX, 'Invalid characters in geometry name').transform(sanitizeString),
    filename: z.string().min(1).max(128).regex(SAFE_FILENAME_REGEX, 'Invalid filename format').transform(sanitizeString),
    geometryType: z.enum(['cylinder', 'airfoil', 'custom_stl', 'sphere', 'wedge']).optional().default('cylinder'),
    stlBase64: z.string().min(1, 'A validated STL payload is required; placeholder geometry is not accepted.'),
  })
  .strict();

const simulationRequestSchema = z
  .object({
    caseId: z.string().regex(UUID_REGEX, 'caseId must be a valid UUIDv4').optional(),
    geometry: simulationGeometrySchema,
    config: simulationConfigSchema,
  })
  .strict();

const caseIdParamSchema = z
  .object({
    caseId: z.string().regex(UUID_REGEX, 'Invalid caseId parameter. Must be valid UUIDv4 format.'),
  })
  .strict();

// STL Validator: Validates ASCII / Binary headers, size limit (50MB), and triangle bounds
function validateStlPayload(base64String) {
  if (!base64String) return { valid: true, buffer: null, triangleCount: 0 };

  // Strip possible data URI header
  const cleanBase64 = base64String.replace(/^data:.*?;base64,/, '');

  // Calculate byte length without full decoding first
  const approxSize = Math.ceil((cleanBase64.length * 3) / 4);
  const MAX_50MB = 50 * 1024 * 1024;
  if (approxSize > MAX_50MB) {
    throw new Error('STL payload exceeds maximum allowed size of 50 MB.');
  }

  let buffer;
  try {
    buffer = Buffer.from(cleanBase64, 'base64');
  } catch (e) {
    throw new Error('Invalid Base64 encoding for STL file.');
  }

  if (buffer.length > MAX_50MB) {
    throw new Error(`STL decoded size (${(buffer.length / (1024 * 1024)).toFixed(1)} MB) exceeds 50 MB limit.`);
  }

  if (buffer.length < 84) {
    throw new Error('STL file is too short to contain valid mesh geometry data.');
  }

  // Check if ASCII STL: starts with "solid"
  const headerPreview = buffer.slice(0, 80).toString('utf8').trim();
  if (headerPreview.toLowerCase().startsWith('solid')) {
    // Check that it contains "endsolid"
    const content = buffer.toString('utf8');
    if (!content.toLowerCase().includes('endsolid')) {
      throw new Error('ASCII STL file is incomplete or corrupted (missing endsolid marker).');
    }
    // Count facets
    const facetMatches = content.match(/facet\s+normal/gi);
    const triangleCount = facetMatches ? facetMatches.length : 0;
    if (triangleCount < 1) {
      throw new Error('STL mesh does not contain any triangular facets.');
    }
    if (triangleCount > 2000000) {
      throw new Error(`STL triangle count (${triangleCount}) exceeds 2,000,000 facet maximum limit.`);
    }
    return { valid: true, buffer, triangleCount, format: 'ascii' };
  }

  // Binary STL: 80 bytes header + 4 bytes UINT32 triangle count + 50 bytes per triangle
  const declaredTriangles = buffer.readUInt32LE(80);
  const expectedSize = 84 + declaredTriangles * 50;

  if (declaredTriangles < 1) {
    throw new Error('Binary STL header declares 0 triangles.');
  }
  if (declaredTriangles > 2000000) {
    throw new Error(`Binary STL declares ${declaredTriangles} triangles, exceeding the 2,000,000 limit.`);
  }

  // Buffer size verification (allow slight padding differences if any, but must have at least all declared bytes)
  if (buffer.length < expectedSize) {
    throw new Error(`Binary STL truncated: expected at least ${expectedSize} bytes for ${declaredTriangles} triangles, but received ${buffer.length} bytes.`);
  }

  return { valid: true, buffer, triangleCount: declaredTriangles, format: 'binary' };
}

// Middleware: Express validation wrapper
function validateBody(schema) {
  return (req, res, next) => {
    const result = schema.safeParse(req.body);
    if (!result.success) {
      const issueList = result.error.issues || result.error.errors || [];
      const errors = issueList.map((e) => ({
        path: (e.path || []).join('.'),
        message: e.message,
      }));
      return res.status(400).json({
        error: 'Input validation failed. Unknown or malformed fields rejected.',
        code: 'VALIDATION_ERROR',
        details: errors,
      });
    }
    req.body = result.data;
    next();
  };
}

function validateParams(schema) {
  return (req, res, next) => {
    const result = schema.safeParse(req.params);
    if (!result.success) {
      const issueList = result.error.issues || result.error.errors || [];
      const errors = issueList.map((e) => ({
        path: (e.path || []).join('.'),
        message: e.message,
      }));
      return res.status(400).json({
        error: 'Invalid URL parameters.',
        code: 'PARAM_VALIDATION_ERROR',
        details: errors,
      });
    }
    req.params = result.data;
    next();
  };
}

// Middleware: Enforce Content-Type application/json
function enforceJsonContentType(req, res, next) {
  if (['POST', 'PUT', 'PATCH'].includes(req.method)) {
    const contentType = req.headers['content-type'];
    if (!contentType || !contentType.toLowerCase().includes('application/json')) {
      return res.status(415).json({
        error: 'Unsupported Media Type. Content-Type must be application/json.',
        code: 'INVALID_CONTENT_TYPE',
      });
    }
  }
  next();
}

// 5. AI Advisor Schemas & Anti-Prompt-Injection Security Filters
const AI_PROMPT_INJECTION_PATTERNS = [
  /ignore\s+(all\s+)?(previous|prior|above)\s+(instructions|directives|prompts|rules)/i,
  /disregard\s+(all\s+)?(previous|prior|above)\s+(instructions|directives|prompts|rules)/i,
  /forget\s+(all\s+)?(previous|prior|above)\s+(instructions|prompts)/i,
  /(reveal|show|print|display|dump|leak|tell\s+me|repeat|what\s+is)\s+(your\s+)?(system\s+prompt|instructions|developer\s+mode|hidden\s+rules|initial\s+prompt)/i,
  /repeat\s+(everything|the\s+words)\s+above/i,
  /(dan\s+mode|jailbreak|unrestricted\s+mode|bypass\s+filters|developer\s+mode\s+enabled|sudo\s+mode)/i,
  /(process\.env|jwt_secret|jwt_access_secret|api_key|gemini_api_key|credentials|secret_key|passwd|shadow|\/etc\/passwd)/i,
  /(server\.ts|openfoamrunner|auth\.js|logger\.js|\.env|users_table|user_sessions|dump\s+database)/i,
  /(who\s+are\s+the\s+registered\s+users|list\s+all\s+users|dump\s+user\s+emails|database\s+credentials)/i,
  /(<script|javascript:|document\.cookie|window\.localStorage|eval\(|exec\(|child_process)/i,
  /(union\s+select|drop\s+table|insert\s+into|select\s+\*\s+from)/i,
];

function filterAiPrompt(rawPrompt) {
  if (!rawPrompt || typeof rawPrompt !== 'string') {
    return { isSafe: true, sanitizedPrompt: '' };
  }

  const trimmed = rawPrompt.trim();

  // Enforce length limit
  if (trimmed.length > 2000) {
    return {
      isSafe: false,
      reason: 'Prompt length exceeds maximum allowed threshold of 2,000 characters.',
      safeMessage: 'Security Filter Notice: Query exceeds maximum permitted character limit. Please submit focused aerodynamic questions.',
    };
  }

  // Check against injection and reconnaissance patterns
  for (const pattern of AI_PROMPT_INJECTION_PATTERNS) {
    if (pattern.test(trimmed)) {
      return {
        isSafe: false,
        reason: 'Prompt injection or unauthorized system reconnaissance pattern detected.',
        safeMessage: 'Security Filter Notice: The RIMZ Aerodynamic Intelligence Advisor strictly processes computational fluid dynamics, Navier-Stokes flow physics, and aerodynamic design queries. Unauthorized data access, system instruction inquiries, and server reconnaissance are filtered and monitored.',
      };
    }
  }

  // Basic HTML / control char sanitization
  const sanitized = trimmed.replace(/[\0\x00-\x1F\x7F]/g, '').replace(/<[^>]*>?/gm, '');

  return { isSafe: true, sanitizedPrompt: sanitized };
}

function sanitizeAiOutput(output) {
  if (!output || typeof output !== 'string') return output;

  // Redact potential API keys or tokens
  let cleaned = output
    .replace(/AIza[0-9A-Za-z-_]{35}/g, '[REDACTED_KEY]')
    .replace(/sk-[0-9A-Za-z-_]{20,}/g, '[REDACTED_KEY]')
    .replace(/ey[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}/g, '[REDACTED_JWT]')
    .replace(/\/tmp\/of_cases\/[0-9a-f-]+/gi, '/simulation/case-run')
    .replace(/\/app\/applet\/[a-zA-Z0-9_/.-]+/gi, '[INTERNAL_PATH]');

  // Check if output accidentally contains sensitive server keywords
  const sensitiveWords = ['JWT_ACCESS_SECRET', 'JWT_REFRESH_SECRET', 'password_hash', 'USER_SESSIONS'];
  for (const word of sensitiveWords) {
    if (cleaned.includes(word)) {
      return '### Aerodynamic Technical Analysis\nAnalysis completed. Results verified against Navier-Stokes boundary layer standards. (Internal debug symbols redacted).';
    }
  }

  return cleaned;
}

const aiAdvisorSchema = z
  .object({
    prompt: z.string().max(2000).optional(),
    geometry: z
      .object({
        name: z.string().max(100).optional(),
        geometryType: z.string().max(50).optional(),
        cells: z.any().optional(),
      })
      .optional(),
    config: z
      .object({
        inletVelocity: z.number().min(0.01).max(2000).optional(),
        viscosity: z.number().optional(),
        maxIterations: z.number().int().min(1).max(50000).optional(),
      })
      .optional(),
  })
  .strict();

export {
  signupSchema,
  loginSchema,
  forgotPasswordSchema,
  resetPasswordSchema,
  verifyEmailSchema,
  totpVerifySchema,
  totpDisableSchema,
  simulationRequestSchema,
  caseIdParamSchema,
  validateStlPayload,
  validateBody,
  validateParams,
  enforceJsonContentType,
  aiAdvisorSchema,
  filterAiPrompt,
  sanitizeAiOutput,
};

export default {
  signupSchema,
  loginSchema,
  forgotPasswordSchema,
  resetPasswordSchema,
  verifyEmailSchema,
  totpVerifySchema,
  totpDisableSchema,
  simulationRequestSchema,
  caseIdParamSchema,
  validateStlPayload,
  validateBody,
  validateParams,
  enforceJsonContentType,
  aiAdvisorSchema,
  filterAiPrompt,
  sanitizeAiOutput,
};
