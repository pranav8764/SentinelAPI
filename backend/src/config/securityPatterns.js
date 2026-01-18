// Security patterns for detecting various types of attacks
export const securityPatterns = {
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
      pattern: /javascript\s*:/gi,
      severity: 'high',
      description: 'JavaScript protocol detected'
    },
    {
      pattern: /on\w+\s*=\s*["'][^"']*["']/gi,
      severity: 'medium',
      description: 'HTML event handler detected'
    },
    {
      pattern: /<iframe[^>]*>.*?<\/iframe>/gi,
      severity: 'medium',
      description: 'Iframe tag detected'
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
      pattern: /expression\s*\(/gi,
      severity: 'high',
      description: 'CSS expression detected'
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
export function checkForVulnerabilities(input, type = 'all') {
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
export function getThreatLevel(vulnerabilities) {
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