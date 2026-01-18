// Security patterns for detecting various types of attacks
const securityPatterns = {
  sqlInjection: [
    {
      pattern: /(\bunion\s+select\b)|(\bdrop\s+table\b)|(\bdelete\s+from\b)|(\binsert\s+into\b)/gi,
      severity: 'critical',
      description: 'SQL injection keywords detected'
    },
    {
      pattern: /('.*'.*=.*'.*')|(".*".*=.*".*")/gi,
      severity: 'high',
      description: 'Potential SQL injection string comparison'
    },
    {
      pattern: /(\s+(or|and)\s+[\w\s]*\s*=\s*[\w\s]*\s*--)/gi,
      severity: 'high',
      description: 'SQL injection boolean logic with comment'
    }
  ],

  nosqlInjection: [
    {
      pattern: /\$ne|\$gt|\$gte|\$lt|\$lte|\$in|\$nin|\$exists|\$regex|\$where/gi,
      severity: 'high',
      description: 'MongoDB operator injection detected'
    },
    {
      pattern: /\$or|\$and|\$not|\$nor/gi,
      severity: 'medium',
      description: 'MongoDB logical operator detected'
    },
    {
      pattern: /\$eval|\$where.*function/gi,
      severity: 'critical',
      description: 'MongoDB code execution detected'
    }
  ],

  xss: [
    {
      pattern: /<script[^>]*>.*?<\/script>/gi,
      severity: 'high',
      description: 'Script tag detected'
    },
    {
      pattern: /<script[^>]*>/gi,
      severity: 'high',
      description: 'Script tag opening detected'
    },
    {
      pattern: /<\/script>/gi,
      severity: 'high',
      description: 'Script tag closing detected'
    },
    {
      pattern: /javascript\s*:/gi,
      severity: 'high',
      description: 'JavaScript protocol detected'
    },
    {
      pattern: /vbscript\s*:/gi,
      severity: 'high',
      description: 'VBScript protocol detected'
    },
    {
      pattern: /data\s*:\s*text\/html/gi,
      severity: 'high',
      description: 'Data URI with HTML detected'
    },
    {
      pattern: /on\w+\s*=\s*["'][^"']*["']/gi,
      severity: 'medium',
      description: 'HTML event handler detected'
    },
    {
      pattern: /on(load|error|click|mouseover|focus|blur|change|submit)\s*=/gi,
      severity: 'high',
      description: 'Common XSS event handler detected'
    },
    {
      pattern: /<iframe[^>]*>.*?<\/iframe>/gi,
      severity: 'medium',
      description: 'Iframe tag detected'
    },
    {
      pattern: /<iframe[^>]*>/gi,
      severity: 'medium',
      description: 'Iframe opening tag detected'
    },
    {
      pattern: /<object[^>]*>.*?<\/object>/gi,
      severity: 'medium',
      description: 'Object tag detected'
    },
    {
      pattern: /<embed[^>]*>/gi,
      severity: 'medium',
      description: 'Embed tag detected'
    },
    {
      pattern: /<applet[^>]*>.*?<\/applet>/gi,
      severity: 'high',
      description: 'Applet tag detected'
    },
    {
      pattern: /<form[^>]*>.*?<\/form>/gi,
      severity: 'low',
      description: 'Form tag detected'
    },
    {
      pattern: /<meta[^>]*>/gi,
      severity: 'medium',
      description: 'Meta tag detected'
    },
    {
      pattern: /<link[^>]*>/gi,
      severity: 'medium',
      description: 'Link tag detected'
    },
    {
      pattern: /<style[^>]*>.*?<\/style>/gi,
      severity: 'medium',
      description: 'Style tag detected'
    },
    {
      pattern: /expression\s*\(/gi,
      severity: 'high',
      description: 'CSS expression detected'
    },
    {
      pattern: /behavior\s*:/gi,
      severity: 'high',
      description: 'CSS behavior detected'
    },
    {
      pattern: /@import/gi,
      severity: 'medium',
      description: 'CSS import detected'
    },
    {
      pattern: /url\s*\(\s*javascript:/gi,
      severity: 'high',
      description: 'CSS URL with JavaScript detected'
    },
    {
      pattern: /&#x?[0-9a-f]+;/gi,
      severity: 'medium',
      description: 'HTML entity encoding detected'
    },
    {
      pattern: /%3c%73%63%72%69%70%74/gi,
      severity: 'high',
      description: 'URL encoded script tag detected'
    },
    {
      pattern: /\\u[0-9a-f]{4}/gi,
      severity: 'medium',
      description: 'Unicode encoding detected'
    },
    {
      pattern: /\\x[0-9a-f]{2}/gi,
      severity: 'medium',
      description: 'Hex encoding detected'
    },
    {
      pattern: /<svg[^>]*>.*?<\/svg>/gi,
      severity: 'medium',
      description: 'SVG tag detected'
    },
    {
      pattern: /<svg[^>]*onload/gi,
      severity: 'high',
      description: 'SVG with onload event detected'
    },
    {
      pattern: /data:.*base64.*[a-zA-Z0-9+\/=]{20,}/gi,
      severity: 'medium',
      description: 'Base64 encoded data URI detected'
    },
    {
      pattern: /alert\s*\(/gi,
      severity: 'high',
      description: 'JavaScript alert function detected'
    },
    {
      pattern: /confirm\s*\(/gi,
      severity: 'high',
      description: 'JavaScript confirm function detected'
    },
    {
      pattern: /prompt\s*\(/gi,
      severity: 'high',
      description: 'JavaScript prompt function detected'
    },
    {
      pattern: /eval\s*\(/gi,
      severity: 'critical',
      description: 'JavaScript eval function detected'
    },
    {
      pattern: /document\.cookie/gi,
      severity: 'high',
      description: 'Cookie access attempt detected'
    },
    {
      pattern: /document\.write/gi,
      severity: 'high',
      description: 'Document write attempt detected'
    },
    {
      pattern: /window\.location/gi,
      severity: 'medium',
      description: 'Window location access detected'
    },
    {
      pattern: /\{\{.*\}\}/g,
      severity: 'medium',
      description: 'Template injection syntax detected'
    },
    {
      pattern: /\$\{.*\}/g,
      severity: 'medium',
      description: 'Template literal injection detected'
    }
  ],

  commandInjection: [
    {
      pattern: /\|\s*(rm|del|format|fdisk|mkfs|cat|ls|dir|type)/gi,
      severity: 'critical',
      description: 'Command piping detected'
    },
    {
      pattern: /&&\s*(rm|del|format|fdisk|mkfs)/gi,
      severity: 'critical',
      description: 'Destructive command chaining detected'
    },
    {
      pattern: /\$\([^)]*\)/g,
      severity: 'high',
      description: 'Command substitution detected'
    },
    {
      pattern: /`[^`]*`/g,
      severity: 'high',
      description: 'Backtick command execution detected'
    }
  ],

  pathTraversal: [
    {
      pattern: /\.\.[\/\\]/g,
      severity: 'high',
      description: 'Directory traversal detected'
    },
    {
      pattern: /[\/\\]etc[\/\\]passwd/gi,
      severity: 'critical',
      description: 'Unix password file access attempt'
    },
    {
      pattern: /[\/\\]windows[\/\\]system32/gi,
      severity: 'critical',
      description: 'Windows system directory access attempt'
    },
    {
      pattern: /%2e%2e[%2f%5c]/gi,
      severity: 'high',
      description: 'URL encoded directory traversal'
    }
  ]
};

// Function to check input against all patterns
function checkForVulnerabilities(input, type = 'all') {
  const vulnerabilities = [];
  
  if (!input || typeof input !== 'string') {
    return vulnerabilities;
  }

  const patternsToCheck = type === 'all' ? 
    Object.keys(securityPatterns) : 
    [type].filter(t => securityPatterns[t]);

  for (const patternType of patternsToCheck) {
    const patterns = securityPatterns[patternType];
    
    for (const patternObj of patterns) {
      if (patternObj.pattern.test(input)) {
        vulnerabilities.push({
          type: patternType,
          pattern: patternObj.pattern.toString(),
          severity: patternObj.severity,
          description: patternObj.description,
          match: input.match(patternObj.pattern)
        });
      }
    }
  }

  return vulnerabilities;
}

// Function to get threat level based on vulnerabilities
function getThreatLevel(vulnerabilities) {
  if (!vulnerabilities || vulnerabilities.length === 0) {
    return 'low';
  }

  const severities = vulnerabilities.map(v => v.severity);
  
  if (severities.includes('critical')) {
    return 'critical';
  } else if (severities.includes('high')) {
    return 'high';
  } else if (severities.includes('medium')) {
    return 'medium';
  } else {
    return 'low';
  }
}

module.exports = {
  securityPatterns,
  checkForVulnerabilities,
  getThreatLevel
};