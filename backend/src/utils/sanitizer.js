/**
 * Input Sanitization Utilities
 * Provides comprehensive input sanitization and validation
 */

const logger = require('./logger');

/**
 * HTML entity encoding map
 */
const HTML_ENTITIES = {
  '&': '&amp;',
  '<': '&lt;',
  '>': '&gt;',
  '"': '&quot;',
  "'": '&#x27;',
  '/': '&#x2F;',
  '`': '&#x60;',
  '=': '&#x3D;'
};

/**
 * Dangerous HTML tags that should be removed or encoded
 */
const DANGEROUS_TAGS = [
  'script', 'iframe', 'object', 'embed', 'applet', 'form', 'input', 
  'textarea', 'select', 'button', 'meta', 'link', 'style', 'base',
  'frame', 'frameset', 'noframes', 'noscript', 'xml', 'svg'
];

/**
 * Dangerous HTML attributes that should be removed
 */
const DANGEROUS_ATTRIBUTES = [
  'onload', 'onerror', 'onclick', 'onmouseover', 'onfocus', 'onblur',
  'onchange', 'onsubmit', 'onreset', 'onselect', 'onunload', 'onabort',
  'oncanplay', 'oncanplaythrough', 'ondurationchange', 'onemptied',
  'onended', 'onloadeddata', 'onloadedmetadata', 'onloadstart',
  'onpause', 'onplay', 'onplaying', 'onprogress', 'onratechange',
  'onseeked', 'onseeking', 'onstalled', 'onsuspend', 'ontimeupdate',
  'onvolumechange', 'onwaiting', 'ondrag', 'ondragend', 'ondragenter',
  'ondragleave', 'ondragover', 'ondragstart', 'ondrop', 'onscroll',
  'onwheel', 'oncopy', 'oncut', 'onpaste', 'oncontextmenu', 'onkeydown',
  'onkeypress', 'onkeyup', 'onmousedown', 'onmouseenter', 'onmouseleave',
  'onmousemove', 'onmouseout', 'onmouseover', 'onmouseup', 'onmousewheel',
  'style', 'background', 'bgcolor', 'dynsrc', 'lowsrc'
];

/**
 * URL protocols that should be blocked
 */
const DANGEROUS_PROTOCOLS = [
  'javascript:', 'vbscript:', 'data:', 'file:', 'ftp:', 'jar:',
  'mailto:', 'news:', 'gopher:', 'ldap:', 'feed:', 'urn:', 'aim:',
  'callto:', 'cid:', 'mid:', 'tel:', 'xmpp:', 'webcal:', 'wtai:'
];

/**
 * Encode HTML entities to prevent XSS
 */
function encodeHtmlEntities(str) {
  if (typeof str !== 'string') {
    return str;
  }
  
  return str.replace(/[&<>"'`=\/]/g, (match) => HTML_ENTITIES[match]);
}

/**
 * Decode HTML entities
 */
function decodeHtmlEntities(str) {
  if (typeof str !== 'string') {
    return str;
  }
  
  const entityMap = Object.fromEntries(
    Object.entries(HTML_ENTITIES).map(([key, value]) => [value, key])
  );
  
  return str.replace(/&amp;|&lt;|&gt;|&quot;|&#x27;|&#x2F;|&#x60;|&#x3D;/g, 
    (match) => entityMap[match] || match
  );
}

/**
 * Remove dangerous HTML tags
 */
function removeDangerousTags(str) {
  if (typeof str !== 'string') {
    return str;
  }
  
  let sanitized = str;
  
  // Remove dangerous tags (both opening and closing)
  DANGEROUS_TAGS.forEach(tag => {
    const openingTagRegex = new RegExp(`<${tag}[^>]*>`, 'gi');
    const closingTagRegex = new RegExp(`<\/${tag}>`, 'gi');
    const selfClosingTagRegex = new RegExp(`<${tag}[^>]*\/>`, 'gi');
    
    sanitized = sanitized
      .replace(openingTagRegex, '')
      .replace(closingTagRegex, '')
      .replace(selfClosingTagRegex, '');
  });
  
  return sanitized;
}

/**
 * Remove dangerous HTML attributes
 */
function removeDangerousAttributes(str) {
  if (typeof str !== 'string') {
    return str;
  }
  
  let sanitized = str;
  
  // Remove dangerous attributes
  DANGEROUS_ATTRIBUTES.forEach(attr => {
    const attrRegex = new RegExp(`\\s+${attr}\\s*=\\s*["'][^"']*["']`, 'gi');
    const attrRegexNoQuotes = new RegExp(`\\s+${attr}\\s*=\\s*[^\\s>]+`, 'gi');
    
    sanitized = sanitized
      .replace(attrRegex, '')
      .replace(attrRegexNoQuotes, '');
  });
  
  return sanitized;
}

/**
 * Remove dangerous URL protocols
 */
function removeDangerousProtocols(str) {
  if (typeof str !== 'string') {
    return str;
  }
  
  let sanitized = str;
  
  DANGEROUS_PROTOCOLS.forEach(protocol => {
    const protocolRegex = new RegExp(protocol.replace(':', '\\s*:'), 'gi');
    sanitized = sanitized.replace(protocolRegex, 'blocked:');
  });
  
  return sanitized;
}

/**
 * Remove or encode Unicode and hex encodings that might be used for XSS
 */
function removeEncodedPayloads(str) {
  if (typeof str !== 'string') {
    return str;
  }
  
  let sanitized = str;
  
  // Remove Unicode encodings
  sanitized = sanitized.replace(/\\u[0-9a-f]{4}/gi, '');
  
  // Remove hex encodings
  sanitized = sanitized.replace(/\\x[0-9a-f]{2}/gi, '');
  
  // Remove excessive HTML entity encodings
  sanitized = sanitized.replace(/&#x?[0-9a-f]+;/gi, (match) => {
    // Allow basic entities but remove suspicious ones
    const basicEntities = ['&lt;', '&gt;', '&amp;', '&quot;', '&#x27;'];
    return basicEntities.includes(match) ? match : '';
  });
  
  return sanitized;
}

/**
 * Remove CSS expressions and dangerous CSS
 */
function removeDangerousCSS(str) {
  if (typeof str !== 'string') {
    return str;
  }
  
  let sanitized = str;
  
  // Remove CSS expressions
  sanitized = sanitized.replace(/expression\s*\([^)]*\)/gi, '');
  
  // Remove CSS behavior
  sanitized = sanitized.replace(/behavior\s*:[^;]*/gi, '');
  
  // Remove CSS imports
  sanitized = sanitized.replace(/@import[^;]*/gi, '');
  
  // Remove CSS URLs with JavaScript
  sanitized = sanitized.replace(/url\s*\(\s*javascript:[^)]*\)/gi, '');
  
  return sanitized;
}

/**
 * Comprehensive XSS sanitization
 */
function sanitizeXSS(input, options = {}) {
  if (typeof input !== 'string') {
    return input;
  }
  
  const {
    encodeEntities = true,
    removeTags = true,
    removeAttributes = true,
    removeProtocols = true,
    removeEncodings = true,
    removeCSS = true,
    allowedTags = [],
    allowedAttributes = []
  } = options;
  
  let sanitized = input;
  
  try {
    // Step 1: Remove encoded payloads
    if (removeEncodings) {
      sanitized = removeEncodedPayloads(sanitized);
    }
    
    // Step 2: Remove dangerous CSS
    if (removeCSS) {
      sanitized = removeDangerousCSS(sanitized);
    }
    
    // Step 3: Remove dangerous protocols
    if (removeProtocols) {
      sanitized = removeDangerousProtocols(sanitized);
    }
    
    // Step 4: Remove dangerous attributes
    if (removeAttributes) {
      sanitized = removeDangerousAttributes(sanitized);
    }
    
    // Step 5: Remove dangerous tags (unless in allowed list)
    if (removeTags) {
      sanitized = removeDangerousTags(sanitized);
    }
    
    // Step 6: Encode HTML entities
    if (encodeEntities) {
      sanitized = encodeHtmlEntities(sanitized);
    }
    
    logger.debug('XSS sanitization completed', {
      originalLength: input.length,
      sanitizedLength: sanitized.length,
      changed: input !== sanitized
    });
    
    return sanitized;
    
  } catch (error) {
    logger.error('Error during XSS sanitization:', error);
    // Fallback: encode everything
    return encodeHtmlEntities(input);
  }
}

/**
 * Sanitize SQL injection attempts
 */
function sanitizeSQL(input) {
  if (typeof input !== 'string') {
    return input;
  }
  
  let sanitized = input;
  
  // Remove SQL comments
  sanitized = sanitized.replace(/--[^\r\n]*/g, '');
  sanitized = sanitized.replace(/\/\*[\s\S]*?\*\//g, '');
  
  // Remove dangerous SQL keywords (case insensitive)
  const dangerousKeywords = [
    'DROP', 'DELETE', 'INSERT', 'UPDATE', 'CREATE', 'ALTER', 'EXEC',
    'EXECUTE', 'UNION', 'SELECT', 'FROM', 'WHERE', 'HAVING', 'GROUP BY',
    'ORDER BY', 'TRUNCATE', 'REPLACE', 'HANDLER'
  ];
  
  dangerousKeywords.forEach(keyword => {
    const regex = new RegExp(`\\b${keyword}\\b`, 'gi');
    sanitized = sanitized.replace(regex, `[${keyword}]`);
  });
  
  // Escape single quotes
  sanitized = sanitized.replace(/'/g, "''");
  
  return sanitized;
}

/**
 * Sanitize NoSQL injection attempts
 */
function sanitizeNoSQL(input) {
  if (typeof input !== 'string') {
    return input;
  }
  
  let sanitized = input;
  
  // Remove MongoDB operators
  const mongoOperators = [
    '$ne', '$gt', '$gte', '$lt', '$lte', '$in', '$nin', '$exists',
    '$regex', '$where', '$or', '$and', '$not', '$nor', '$eval'
  ];
  
  mongoOperators.forEach(operator => {
    const regex = new RegExp(`\\${operator.replace('$', '\\$')}`, 'gi');
    sanitized = sanitized.replace(regex, `[${operator}]`);
  });
  
  return sanitized;
}

/**
 * Sanitize command injection attempts
 */
function sanitizeCommand(input) {
  if (typeof input !== 'string') {
    return input;
  }
  
  let sanitized = input;
  
  // Remove command separators
  sanitized = sanitized.replace(/[|&;`$(){}[\]]/g, '');
  
  // Remove command substitution
  sanitized = sanitized.replace(/\$\([^)]*\)/g, '');
  sanitized = sanitized.replace(/`[^`]*`/g, '');
  
  // Remove dangerous commands
  const dangerousCommands = [
    'rm', 'del', 'format', 'fdisk', 'mkfs', 'cat', 'ls', 'dir', 'type',
    'wget', 'curl', 'nc', 'netcat', 'telnet', 'ssh', 'ftp', 'tftp'
  ];
  
  dangerousCommands.forEach(cmd => {
    const regex = new RegExp(`\\b${cmd}\\b`, 'gi');
    sanitized = sanitized.replace(regex, `[${cmd}]`);
  });
  
  return sanitized;
}

/**
 * Sanitize path traversal attempts
 */
function sanitizePath(input) {
  if (typeof input !== 'string') {
    return input;
  }
  
  let sanitized = input;
  
  // Remove directory traversal sequences
  sanitized = sanitized.replace(/\.\.[\/\\]/g, '');
  sanitized = sanitized.replace(/%2e%2e[%2f%5c]/gi, '');
  
  // Remove absolute paths
  sanitized = sanitized.replace(/^[\/\\]/, '');
  
  // Remove dangerous paths
  const dangerousPaths = [
    '/etc/passwd', '/etc/shadow', '/windows/system32', '/boot.ini',
    '/proc/version', '/etc/hosts'
  ];
  
  dangerousPaths.forEach(path => {
    const regex = new RegExp(path.replace(/[\/\\]/g, '[\/\\\\]'), 'gi');
    sanitized = sanitized.replace(regex, '[BLOCKED_PATH]');
  });
  
  return sanitized;
}

/**
 * Comprehensive input sanitization
 */
function sanitizeInput(input, options = {}) {
  if (input === null || input === undefined) {
    return input;
  }
  
  const {
    type = 'all', // 'xss', 'sql', 'nosql', 'command', 'path', 'all'
    strict = false
  } = options;
  
  // Handle different input types
  if (typeof input === 'object') {
    if (Array.isArray(input)) {
      return input.map(item => sanitizeInput(item, options));
    } else {
      const sanitizedObj = {};
      for (const [key, value] of Object.entries(input)) {
        sanitizedObj[sanitizeInput(key, options)] = sanitizeInput(value, options);
      }
      return sanitizedObj;
    }
  }
  
  if (typeof input !== 'string') {
    return input;
  }
  
  let sanitized = input;
  
  try {
    switch (type) {
      case 'xss':
        sanitized = sanitizeXSS(sanitized, { strict });
        break;
      case 'sql':
        sanitized = sanitizeSQL(sanitized);
        break;
      case 'nosql':
        sanitized = sanitizeNoSQL(sanitized);
        break;
      case 'command':
        sanitized = sanitizeCommand(sanitized);
        break;
      case 'path':
        sanitized = sanitizePath(sanitized);
        break;
      case 'all':
      default:
        sanitized = sanitizeXSS(sanitized, { strict });
        sanitized = sanitizeSQL(sanitized);
        sanitized = sanitizeNoSQL(sanitized);
        sanitized = sanitizeCommand(sanitized);
        sanitized = sanitizePath(sanitized);
        break;
    }
    
    return sanitized;
    
  } catch (error) {
    logger.error('Error during input sanitization:', error);
    // Fallback: encode HTML entities
    return encodeHtmlEntities(input);
  }
}

/**
 * Validate and sanitize email addresses
 */
function sanitizeEmail(email) {
  if (typeof email !== 'string') {
    return null;
  }
  
  // Basic email regex
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  
  if (!emailRegex.test(email)) {
    return null;
  }
  
  // Remove dangerous characters
  return email.replace(/[<>"'&]/g, '');
}

/**
 * Validate and sanitize URLs
 */
function sanitizeURL(url) {
  if (typeof url !== 'string') {
    return null;
  }
  
  try {
    const urlObj = new URL(url);
    
    // Check for dangerous protocols
    if (DANGEROUS_PROTOCOLS.some(protocol => 
      urlObj.protocol.toLowerCase().startsWith(protocol.replace(':', ''))
    )) {
      return null;
    }
    
    return urlObj.toString();
  } catch (error) {
    return null;
  }
}

/**
 * Create Content Security Policy header
 */
function generateCSPHeader(options = {}) {
  const {
    defaultSrc = ["'self'"],
    scriptSrc = ["'self'"],
    styleSrc = ["'self'", "'unsafe-inline'"],
    imgSrc = ["'self'", "data:", "https:"],
    connectSrc = ["'self'"],
    fontSrc = ["'self'"],
    objectSrc = ["'none'"],
    mediaSrc = ["'self'"],
    frameSrc = ["'none'"],
    childSrc = ["'none'"],
    formAction = ["'self'"],
    frameAncestors = ["'none'"],
    baseUri = ["'self'"],
    upgradeInsecureRequests = true,
    blockAllMixedContent = true
  } = options;
  
  const directives = [
    `default-src ${defaultSrc.join(' ')}`,
    `script-src ${scriptSrc.join(' ')}`,
    `style-src ${styleSrc.join(' ')}`,
    `img-src ${imgSrc.join(' ')}`,
    `connect-src ${connectSrc.join(' ')}`,
    `font-src ${fontSrc.join(' ')}`,
    `object-src ${objectSrc.join(' ')}`,
    `media-src ${mediaSrc.join(' ')}`,
    `frame-src ${frameSrc.join(' ')}`,
    `child-src ${childSrc.join(' ')}`,
    `form-action ${formAction.join(' ')}`,
    `frame-ancestors ${frameAncestors.join(' ')}`,
    `base-uri ${baseUri.join(' ')}`
  ];
  
  if (upgradeInsecureRequests) {
    directives.push('upgrade-insecure-requests');
  }
  
  if (blockAllMixedContent) {
    directives.push('block-all-mixed-content');
  }
  
  return directives.join('; ');
}

module.exports = {
  // Core sanitization functions
  sanitizeInput,
  sanitizeXSS,
  sanitizeSQL,
  sanitizeNoSQL,
  sanitizeCommand,
  sanitizePath,
  
  // Utility functions
  encodeHtmlEntities,
  decodeHtmlEntities,
  sanitizeEmail,
  sanitizeURL,
  
  // Security headers
  generateCSPHeader,
  
  // Constants for external use
  DANGEROUS_TAGS,
  DANGEROUS_ATTRIBUTES,
  DANGEROUS_PROTOCOLS
};