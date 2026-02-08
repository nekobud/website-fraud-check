#!/usr/bin/env node

import { execSync } from 'child_process';
import https from 'https';
import http from 'http';
import { URL } from 'url';
import fs from 'fs'; // Moved from inside loadLegitimateDomains
import path from 'path'; // Moved from inside loadLegitimateDomains
import { parse, differenceInDays, parseISO } from 'date-fns'; // Import date-fns functions
import * as Whoiser from 'whoiser';

class WebsiteFraudChecker {
    constructor() {
        this.config = this._loadFraudData();
        this.legitimateDomains = this.loadLegitimateDomains();
    }

    /**
     * Load legitimate domains from configuration file
     */
    loadLegitimateDomains() {
        try {
            const filePath = path.resolve(__dirname, '../config/legitimate-domains.txt');
            
            // Read the file content
            const content = fs.readFileSync(filePath, 'utf8');
            
            // Parse the file content to extract domains
            const domains = content
                .split('\n')
                .map(line => line.trim())
                .filter(line => line && !line.startsWith('#')) // Exclude empty lines and comments
                .filter(line => line.length > 0); // Ensure no empty strings
            
            return domains;
        } catch (error) {
            console.debug(`Could not load legitimate domains from file: ${error.message}`);
            // Return an empty array if the file cannot be loaded
            return [];
        }
    }

    /**
     * Load fraud detection configuration from fraud-data.json
     */
    _loadFraudData() {
        try {
            const filePath = path.resolve(__dirname, '../config/fraud-data.json');
            const content = fs.readFileSync(filePath, 'utf8');
            const config = JSON.parse(content);

            // Convert pattern strings to RegExp objects
            config.suspiciousPatterns = config.suspiciousPatterns.map(p => new RegExp(p.pattern, p.flags));
            config.fraudPatterns = config.fraudPatterns.map(p => new RegExp(p.pattern, p.flags));

            return config;
        } catch (error) {
            console.debug(`Could not load fraud data from file: ${error.message}`);
            // Return default empty configurations if file cannot be loaded
            return {
                suspiciousPatterns: [],
                targetBrands: [],
                fraudPatterns: [],
                multiPartTlds: [],
                suspiciousTlds: [],
                homoglyphs: [],
                digitSubstitutions: [],
                maxImpersonationScore: 10,
                bankBrands: [],
                riskScoreMultipliers: { // Default values in case of loading error
                    urlIssue: 3,
                    uncertainDomainAge: 5,
                    newDomainAge: 10,
                    invalidSSL: 15,
                    contentAnalysisUnavailable: 10,
                    fraudIndicator: 2,
                    threatFeedUnavailable: 5,
                    blacklisted: 50,
                    phishingIndicator: 5,
                    bankBrandImpersonation: 10,
                    otherBrandImpersonation: 5
                },
                thresholds: { // Default values in case of loading error
                    domainAgeIsNewDays: 365,
                    excessiveSubdomains: 2,
                    unusualDotCount: 4,
                    unusualDashCount: 4,
                    excessiveHyphens: 2,
                    popularityRankTopMillion: 1000000,
                    popularityReductionPoints: 20
                },
                commonSubdomains: [] // Default value
            };
        }
    }

    /**
     * Analyze URL for suspicious patterns
     */
    analyzeUrl(urlString) {
        try {
            const url = new URL(urlString);
            const issues = [];

            // Check for IP address in URL
            const ipPattern = /\b(?:\d{1,3}\.){3}\d{1,3}\b/;
            if (ipPattern.test(url.hostname)) {
                issues.push(`⚠️  URL uses IP address instead of domain: ${url.hostname}`);
            }

            // Check for URL shorteners
            const shortenerPattern = /(?:bit\.ly|tinyurl\.com|goo\.gl|t\.co|lnkd\.in|is\.gd|ow\.ly|bit\.do|adf\.ly|bc\.vc|cur\.lv|ity\.im|v\.gd|tr\.im|cli\.gs|flic\.kr|po\.st|doiop\.com|shorte\.st|u\.bb|vzturl\.com|buff\.ly|wp\.me|fb\.me|bitly\.com|j\.mp|bit\.ws|t2m\.io|link\.zip\.net|rb\.gy|gen\.iu|tiny\.cc|viralstories\.in)/i;
            if (shortenerPattern.test(url.hostname)) {
                issues.push(`⚠️  URL uses URL shortener service: ${url.hostname}`);
            }

            // Check for excessive subdomains (may indicate typo-squatting)
            const subdomainCount = url.hostname.split('.').length - 2;
            if (subdomainCount > this.config.thresholds.excessiveSubdomains) {
                issues.push(`⚠️  Excessive subdomains detected: ${subdomainCount} levels`);
            }

            // Check for suspicious patterns in the URL
            for (const pattern of this.config.suspiciousPatterns) {
                if (pattern.test(url.hostname) || pattern.test(url.pathname) || pattern.test(url.search)) {
                    issues.push(`⚠️  Suspicious pattern detected: ${pattern.toString()}`);
                }
            }


            // Check for homograph attacks (using characters that look similar to Latin letters)
            const nonLatinPattern = /[^\u0000-\u007F]/; // Non-ASCII characters
            if (nonLatinPattern.test(url.hostname)) {
                issues.push(`⚠️  Non-ASCII characters detected in hostname (possible homograph attack)`);
            }

            // Check for too many dots or dashes in the hostname
            const dotCount = (url.hostname.match(/\./g) || []).length;
            const dashCount = (url.hostname.match(/-/g) || []).length;
            if (dotCount > this.config.thresholds.unusualDotCount || dashCount > this.config.thresholds.unusualDashCount) {
                issues.push(`⚠️  Unusual number of dots (${dotCount}) or dashes (${dashCount}) in hostname`);
            }

            // Check for suspicious TLDs (free domains often used in phishing)
            for (const tld of this.config.suspiciousTlds) {
                if (url.hostname.endsWith(tld)) {
                    issues.push(`⚠️  Suspicious TLD detected: ${tld}`);
                }
            }

            // Check for multiple domains in URL (typo-squatting)
            const suspiciousCombos = ['google.com.', 'facebook.com.', 'paypal.com.', 'amazon.com.', 'apple.com.'];
            for (const combo of suspiciousCombos) {
                if (url.hostname.includes(combo) && !url.hostname.startsWith(combo.replace('.', ''))) {
                    issues.push(`⚠️  Suspicious domain combination detected: ${combo}`);
                }
            }

            return issues;
        } catch (error) {
            return [`❌ Invalid URL: ${error.message}`];
        }
    }

    /**
     * Extract the root domain from a hostname, handling subdomains properly
     */
    async checkDomainAge(hostname) {
        try {
            // Extract the root domain from the hostname to check the actual domain age
            const rootDomain = this.extractRootDomain(hostname);
            console.log(`   ℹ️  Checking domain age for root domain: ${rootDomain}`);
            
            // Sanitize the root domain to prevent command injection
            const sanitizedRootDomain = this._sanitizeDomain(rootDomain);

            // Use whoiser to perform the WHOIS lookup
            // whoiser returns an object where keys are WHOIS servers and values are their raw responses
            const whoisResponse = await Whoiser.whois(sanitizedRootDomain);

            const possibleDateFormats = [
                'yyyy-MM-ddTHH:mm:ssX', // ISO 8601 with timezone (e.g., 2016-11-15T03:23:26Z, 2023-01-15T10:30:00+00:00)
                'yyyy-MM-ddTHH:mm:ss',  // ISO 8601 without timezone
                'yyyy-MM-dd',           // Standard YYYY-MM-DD (e.g., 2022-01-15)
                'dd-MM-yyyy',           // DD-MM-YYYY (e.g., 15-08-2020)
                'MM-dd-yyyy',           // MM-DD-YYYY
                'dd/MM/yyyy',           // DD/MM/YYYY
                'MM/dd/yyyy',           // MM/DD/YYYY
                'yyyy/MM/dd',           // YYYY/MM/DD
            ];

            // Helper function to find and parse date
            const _findAndParseDate = (dateStr) => { 
                if (!dateStr) return null;
                dateStr = dateStr.trim();

                // Try parseISO first as it's optimized for ISO 8601
                let parsedDate = parseISO(dateStr);
                if (!isNaN(parsedDate.getTime())) {
                    return parsedDate;
                }

                // Fallback to trying other explicit formats
                for (const fmt of possibleDateFormats) {
                    try { // <--- Added try-catch here
                        parsedDate = parse(dateStr, fmt, new Date());
                        if (!isNaN(parsedDate.getTime())) {
                            return parsedDate;
                        }
                    } catch (e) {
                        // If parse throws an error, consider it a failed parse for this format
                        // and continue to the next format.
                        // For example, some date-fns versions might throw on "T" mismatch.
                        continue;
                    }
                }
                return null;
            };


            // Iterate through WHOIS server responses to find a creation date
            for (const serverResponse of Object.values(whoisResponse)) {
                if (typeof serverResponse === 'string') { // Raw string response
                    const dateFieldPatterns = [
                        { regex: /(?:Creation Date|Created|Creation date|Registered On|Registrar Registration Date):?\s*([0-9\-\/\.\s:TZ]+)/i, name: "Creation Date" },
                        { regex: /(?:Domain Name Commencement Date|Registro|Fecha de registro|Date de création|登録日|등록일|注册时间|註冊時間):?\s*([0-9\-\/\.\s:TZ]+)/i, name: "Local Creation Date" },
                        { regex: /(?:Updated Date):?\s*([0-9\-\/\.\s:TZ]+)/i, name: "Updated Date" },
                        { regex: /(?:Registry Expiry Date):?\s*([0-9\-\/\.\s:TZ]+)/i, name: "Expiry Date" },
                    ];

                    for (const dateFieldPattern of dateFieldPatterns) {
                        const match = serverResponse.match(dateFieldPattern.regex);
                        if (match && match[1]) {
                            const candidateDateString = match[1].trim();
                            const parsedDate = _findAndParseDate(candidateDateString); // Removed hostname debug param
                            if (parsedDate) {
                                return {
                                    ageInDays: differenceInDays(new Date(), parsedDate),
                                    creationDate: candidateDateString,
                                    isNew: differenceInDays(new Date(), parsedDate) < this.config.thresholds.domainAgeIsNewDays,
                                    rootDomain: rootDomain
                                };
                            }
                        }
                    }
                } else if (typeof serverResponse === 'object' && serverResponse !== null) { // Structured object response
                    // Prioritize standard fields
                    const dateFields = [
                        'Creation Date', 'Registered On', 'Created Date', 'Updated Date',
                        'Registration Date', 'Domain Registration Date'
                    ];

                    for (const field of dateFields) {
                        if (serverResponse[field]) {
                            const candidateDateString = serverResponse[field].trim();
                            const parsedDate = _findAndParseDate(candidateDateString); // Removed hostname debug param
                            if (parsedDate) {
                                return {
                                    ageInDays: differenceInDays(new Date(), parsedDate),
                                    creationDate: candidateDateString,
                                    isNew: differenceInDays(new Date(), parsedDate) < this.config.thresholds.domainAgeIsNewDays,
                                    rootDomain: rootDomain
                                };
                            }
                        }
                    }
                }
            }
            
            // If no creation date found after all loops, return null
            return null;
        } catch (error) {
            // If whois command fails, try alternative methods or return null
            // This could happen if whois is not installed or accessible
            console.debug(`Could not check domain age for ${hostname} (root: ${this.extractRootDomain(hostname)}): ${error.message}`);
            return null;
        }
    }

    /**
     * Check SSL certificate validity
     */
    checkSSL(hostname) {
        return new Promise((resolve) => {
            const options = {
                hostname: hostname,
                port: 443,
                method: 'GET',
                timeout: 5000
            };

            const req = https.request(options, (res) => {
                // The certificate is available in res.connection.getPeerCertificate()
                if (res.connection && typeof res.connection.getPeerCertificate === 'function') {
                    const cert = res.connection.getPeerCertificate();

                    if (Object.keys(cert).length === 0) {
                        resolve({ isValid: false, issuer: null, error: 'Could not retrieve certificate' });
                    } else {
                        resolve({ 
                            isValid: true, 
                            issuer: cert.issuer ? `${cert.issuer.O || 'Unknown'} CA` : 'Unknown', 
                            error: null 
                        });
                    }
                } else {
                    // If we can't get the certificate, the connection may still be valid
                    // but we can't verify the certificate
                    resolve({ isValid: true, issuer: 'Unknown', error: null });
                }
            });

            req.on('error', (err) => {
                resolve({ isValid: false, issuer: null, error: err.message });
            });

            req.on('timeout', () => {
                req.destroy();
                resolve({ isValid: false, issuer: null, error: 'Connection timeout' });
            });

            req.end();
        });
    }

    /**
     * Fetch website content with Playwright first (if available), static as fallback
     */
    async fetchWebsiteContent(urlString) {
        let browser = null; // Initialize browser to null
        try {
            const { chromium } = await import('playwright');
            browser = await chromium.launch({ headless: true, args: ['--no-sandbox', '--disable-setuid-sandbox'] });
            const page = await browser.newPage();
            
            // Set a realistic user agent
            await page.setUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36');
            
            // Navigate to the page
            await page.goto(urlString, { waitUntil: 'networkidle', timeout: 15000 });
            
            // Wait for content to load
            await page.waitForLoadState('domcontentloaded', { timeout: 10000 });
            
            // Get the content after JavaScript execution
            const dynamicContent = await page.content();
            
            console.log('   ✅ Content fetched successfully with Playwright (dynamic rendering)');
            
            return {
                statusCode: 200, // Assume success since Playwright loaded the page
                headers: {},
                content: dynamicContent
            };
        } catch (dynamicError) {
            // Playwright failed, warn user about reduced accuracy
            console.log(`   ⚠️  Playwright failed: ${dynamicError.message}`);
            console.log('   ⚠️  Falling back to static content fetching - accuracy may be reduced without dynamic rendering');
            // Do not re-throw here, let the outer function handle the fallback.
        } finally {
            if (browser) {
                await browser.close(); // Ensure browser is always closed
            }
        }

        // Fallback to static content fetching
        try {
            const staticContent = await this.fetchStaticContent(urlString);
            console.log('   ⚠️  Content fetched with static method - some dynamic elements may be missing');
            return staticContent;
        } catch (staticError) {
            console.debug(`Failed to fetch website content: ${staticError.message}`);
            throw staticError;
        }
    }

    /**
     * Fetch website content statically
     */
    async fetchStaticContent(urlString) {
        return new Promise((resolve, reject) => {
            const url = new URL(urlString);
            const options = {
                hostname: url.hostname,
                port: url.port || (url.protocol === 'https:' ? 443 : 80),
                path: url.pathname + url.search,
                method: 'GET',
                headers: {
                    'User-Agent': 'Mozilla/5.0 (compatible; FraudCheckBot/1.0)'
                },
                timeout: 10000
            };

            const protocol = url.protocol === 'https:' ? https : http;
            
            const req = protocol.request(options, (res) => {
                let data = '';
                
                res.on('data', (chunk) => {
                    data += chunk;
                });
                
                res.on('end', () => {
                    resolve({
                        statusCode: res.statusCode,
                        headers: res.headers,
                        content: data
                    });
                });
            });
            
            req.on('error', (error) => {
                reject(error);
            });
            
            req.on('timeout', () => {
                req.destroy();
                reject(new Error('Request timeout'));
            });
            
            req.end();
        });
    }

    /**
     * Analyze website content for fraud indicators
     */
    analyzeWebsiteContent(content, hostname) {
        const impersonation = [];
        const fraudIndicators = [];
        const brandMentions = [];

        // Brands that are commonly impersonated
        const targetBrands = this.config.targetBrands;

        // Convert content to lowercase for comparison
        const lowerContent = content.toLowerCase();

        // Check for brand mentions
        for (const brand of targetBrands) {
            // Use word boundaries to avoid partial matches
            const regex = new RegExp(`\\b${brand}\\b`, 'gi');
            const matches = content.match(regex) || [];
            
            if (matches.length > 0) {
                // Determine if this is likely impersonation
                const isOfficialDomain = this.legitimateDomains.some(domain => 
                    hostname.includes(domain.toLowerCase()) || domain.toLowerCase().includes(hostname.toLowerCase())
                );
                
                if (!isOfficialDomain) {
                    impersonation.push({
                        brand: brand,
                        count: matches.length,
                        confidence: matches.length > 5 ? 'high' : 'medium'
                    });
                }
                
                // Always add to brand mentions for analysis
                brandMentions.push({
                    brand: brand,
                    count: matches.length
                });
            }
        }

        // Look for common fraud indicators in the content
        const fraudPatterns = this.config.fraudPatterns;

        for (const pattern of fraudPatterns) {
            const matches = content.match(pattern) || [];
            if (matches.length > 0) {
                fraudIndicators.push({
                    pattern: pattern.toString(),
                    count: matches.length
                });
            }
        }

        return {
            impersonation,
            fraudIndicators,
            brandMentions
        };
    }

    /**
     * Analyze content without fetching (used for testing)
     */
    analyzeContentWithoutFetching(urlString, hostname) {
        try {
            // For this implementation, we'll return an empty result
            // since we're not actually fetching content
            return { impersonation: [], fraudIndicators: [], brandMentions: [] };
        } catch (error) {
            console.debug(`Error in analyzeContentWithoutFetching: ${error.message}`);
            return { impersonation: [], fraudIndicators: [], brandMentions: [] };
        }
    }

    /**
     * Check website against PhishTank database
     */
    async checkPhishTank(domain) {
        try {
            // PhishTank API requires an HTTP POST request to the correct endpoint
            // Endpoint: https://checkurl.phishtank.com/checkurl/
            // Request parameters: url, format (json), app_key (optional)
            // Headers: Descriptive User-Agent required

            const urlToCheck = `https://${domain}`;
            const postData = `url=${encodeURIComponent(urlToCheck)}&format=json`;

            // Create the HTTPS request options for the correct endpoint
            const options = {
                hostname: 'checkurl.phishtank.com',
                port: 443,  // Note: the endpoint uses HTTPS, not HTTP
                path: '/checkurl/',
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'Content-Length': Buffer.byteLength(postData),
                    'User-Agent': 'WebsiteFraudChecker/1.0 (contact: contact@example.com)'
                } 
            };

            // Make the POST request using Node.js http module
            return new Promise((resolve) => {
                const req = https.request(options, (res) => {
                    let data = '';

                    res.on('data', (chunk) => {
                        data += chunk;
                    });

                    res.on('end', () => {
                        try {
                            // Parse the response
                            const response = JSON.parse(data);

                            // Check if the URL is in the PhishTank database
                            if (response.results && response.results.valid) {
                                // The URL is in the database, check if it's verified as a phishing site
                                if (response.results.in_database && response.results.verified) {
                                    if (response.results.verified == true && response.results.phishy == true) {
                                        resolve({
                                            isBlacklisted: true,
                                            threatsFound: ['PhishTank verified phishing site'],
                                            confidence: 'high'
                                        });
                                    } else {
                                        // The URL is in the database but not verified as phishing
                                        resolve({
                                            isBlacklisted: false,
                                            threatsFound: [],
                                            confidence: 'low'
                                        });
                                    }
                                } else {
                                    // URL not in database or not yet verified
                                    resolve({
                                        isBlacklisted: false,
                                        threatsFound: [],
                                        confidence: 'low'
                                    });
                                }
                            } else {
                                // Unexpected response format
                                resolve({
                                    isBlacklisted: false,
                                    threatsFound: [],
                                    checkUnavailable: true,
                                    message: 'PhishTank check unavailable: Unexpected API response format.',
                                    confidence: 'low'
                                });
                            }
                        } catch (parseError) {
                            console.debug(`Failed to parse PhishTank response: ${parseError.message}`);
                            // Show first 500 characters of response when parsing fails
                            if (data && data.length > 0) {
                                console.debug(`First 500 chars of response: ${data.substring(0, 500)}`);
                            }
                            resolve({
                                isBlacklisted: false,
                                threatsFound: [],
                                checkUnavailable: true,
                                message: `PhishTank check unavailable: Failed to parse response (${parseError.message})`,
                                confidence: 'low'
                            });
                        }
                    });
                });

                req.on('error', (error) => {
                    console.debug(`PhishTank API request failed: ${error.message}`);
                    resolve({
                        isBlacklisted: false,
                        threatsFound: [],
                        checkUnavailable: true,
                        message: `PhishTank check unavailable: API request failed (${error.message})`,
                        confidence: 'low'
                    });
                });

                req.write(postData);
                req.end();
            });
        } catch (error) {
            console.debug(`Error checking PhishTank: ${error.message}`);
            return {
                isBlacklisted: false,
                threatsFound: [],
                checkUnavailable: true,
                message: `PhishTank check unavailable: An unexpected error occurred (${error.message})`,
                confidence: 'low'
            };
        }
    }

    /**
     * Check website against Google Safe Browsing API
     */
    async checkGoogleSafeBrowsing(url) {
        const apiKey = process.env.GOOGLE_SAFE_BROWSING_API_KEY;
        
        if (!apiKey) {
            return {
                isBlacklisted: false,
                threatsFound: [],
                checkUnavailable: true,
                message: 'Google Safe Browsing check unavailable: API key not provided',
                confidence: 'low'
            };
        }

        try {
            const response = await fetch('https://safebrowsing.googleapis.com/v4/threatMatches:find', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    client: {
                        clientId: "website-fraud-checker",
                        clientVersion: "1.0"
                    },
                    threatInfo: {
                        threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                        platformTypes: ["ANY_PLATFORM"],
                        threatEntryTypes: ["URL"],
                        threatEntries: [{ url: url }]
                    }
                })
            });

            if (response.ok) {
                const data = await response.json();
                if (data.matches && data.matches.length > 0) {
                    const threats = data.matches.map(match => match.threatType);
                    return {
                        isBlacklisted: true,
                        threatsFound: threats,
                        confidence: 'high'
                    };
                }
            }

            return {
                isBlacklisted: false,
                threatsFound: [],
                confidence: 'high'
            };
        } catch (error) {
            console.debug(`Error checking Google Safe Browsing: ${error.message}`);
            return {
                isBlacklisted: false,
                threatsFound: [],
                checkUnavailable: true,
                message: `Google Safe Browsing check unavailable: An unexpected error occurred (${error.message})`,
                confidence: 'low'
            };
        }
    }

    /**
     * Check website against multiple threat intelligence services
     */
    async checkThreatIntelligence(urlString) {
        try {
            const url = new URL(urlString);
            const domain = url.hostname;

            // Check each service and collect results
            const phishTankResult = await this.checkPhishTank(domain);
            const googleResult = await this.checkGoogleSafeBrowsing(urlString);

            // Aggregate results
            const allThreats = [
                ...phishTankResult.threatsFound,
                ...googleResult.threatsFound
            ];
            
            const isBlacklisted = phishTankResult.isBlacklisted || googleResult.isBlacklisted;

            let statusMessages = [];
            if (phishTankResult.checkUnavailable) {
                statusMessages.push(phishTankResult.message || 'PhishTank check unavailable.');
            }
            if (googleResult.checkUnavailable) {
                statusMessages.push(googleResult.message || 'Google Safe Browsing check unavailable.');
            }
            
            return {
                isBlacklisted,
                threatsFound: allThreats,
                confidence: 'high', // Will adjust confidence dynamically later if needed
                statusMessage: statusMessages.length > 0 ? statusMessages.join(' ') : ''
            };
        } catch (error) {
            console.debug(`Error in threat intelligence check: ${error.message}`);
            return {
                isBlacklisted: false,
                threatsFound: [],
                checkUnavailable: true,
                message: `Threat intelligence check unavailable: An unexpected error occurred (${error.message})`,
                confidence: 'low',
                statusMessage: `Warning: Threat intelligence check failed due to unexpected error (${error.message})`
            };
        }
    }

    /**
     * Extract the root domain from a hostname, handling subdomains and multi-part TLDs properly
     */
    extractRootDomain(hostname) {
        // Split the hostname into parts
        const parts = hostname.split('.');

        // Handle multi-part TLDs like .co.uk, .com.au, etc.
        // Common multi-part TLDs
        const multiPartTlds = this.config.multiPartTlds;

        // If the last two parts form a known multi-part TLD, take the last three parts
        if (parts.length >= 3) {
            const lastTwoParts = parts.slice(-2).join('.');
            if (multiPartTlds.includes(lastTwoParts)) {
                // For multi-part TLDs, only remove the first part if it's a common subdomain
                if (parts.length > 3) {
                    const commonSubdomains = this.config.commonSubdomains;
                    if (commonSubdomains.includes(parts[0].toLowerCase())) {
                        return parts.slice(-3).join('.'); // Return last 3 parts (subdomain.domain.tld)
                    }
                }
                return parts.slice(-3).join('.'); // Return last 3 parts for multi-part TLDs
            }
        }

        // For regular domains, handle common subdomains properly
        // The logic should remove only the FIRST part if it's a common subdomain
        if (parts.length > 2) {
            const commonSubdomains = this.config.commonSubdomains;
            
            // Only check if the first part is a common subdomain
            if (commonSubdomains.includes(parts[0].toLowerCase())) {
                // Remove just the first common subdomain, keep the rest
                // e.g., 'api.subdomain.site.net' -> 'subdomain.site.net'
                return parts.slice(1).join('.'); 
            } else {
                // If the first part is not a common subdomain, take the last two parts
                // e.g., 'docs.openclaw.ai' -> 'openclaw.ai'
                return parts.slice(-2).join('.');
            }
        }

        // If it's already a root domain (like 'openclaw.ai'), return as is
        return hostname;
    }

    /**
     * Safely sanitize a domain name for use in shell commands to prevent injection.
     * Allows only alphanumeric characters, hyphens, and dots.
     */
    _sanitizeDomain(domain) {
        // Remove any characters that are not alphanumeric, hyphens, or dots
        // This regex ensures that only valid domain name characters are present
        const sanitized = domain.replace(/[^a-zA-Z0-9.-]/g, '');
        // Further remove any leading/trailing dots or hyphens that might have been introduced or remained
        return sanitized.replace(/^[.-]+|[.-]+$/g, '');
    }

    /**
     * Check website popularity using Tranco list to reduce risk for popular sites
     */
    async checkWebsitePopularity(hostname) {
        try {
            console.log('🌐 Checking website popularity...');
            
            // Check both the full hostname and the root domain
            const rootDomain = this.extractRootDomain(hostname);
            let bestReduction = 0;
            let foundPopularDomain = null;
            
            // First check the full hostname
            const hostReduction = await this.getPopularityReduction(hostname);
            if (hostReduction > bestReduction) {
                bestReduction = hostReduction;
                foundPopularDomain = hostname;
            }
            
            // Then check the root domain if it's different from the hostname
            if (rootDomain !== hostname) {
                const domainReduction = await this.getPopularityReduction(rootDomain);
                if (domainReduction > bestReduction) {
                    bestReduction = domainReduction;
                    foundPopularDomain = rootDomain;
                }
            }
            
            if (foundPopularDomain && bestReduction > 0) {
                console.log(`   ✅ Popular domain found: ${foundPopularDomain} (applied ${bestReduction} point risk reduction)`);
            } else if (!foundPopularDomain) {
                console.log('   ℹ️  Neither hostname nor root domain found in Tranco popularity list');
            }
            
            return bestReduction;
        } catch (error) {
            console.debug(`Error checking website popularity: ${error.message}`);
            return 0; // Return 0 reduction if there's an error
        }
    }

    /**
     * Get popularity reduction for a specific domain
     */
    async getPopularityReduction(domain) {
        try {
            const rankResponse = await fetch(`https://tranco-list.eu/api/ranks/domain/${domain}`);
            if (!rankResponse.ok) {
                if (rankResponse.status === 404) {
                    // Domain not found in Tranco list
                    return 0;
                } else {
                    console.debug(`Could not check Tranco rank for ${domain}: ${rankResponse.status}`);
                    return 0;
                }
            }
            
            const rankData = await rankResponse.json();
            if (rankData.ranks && rankData.ranks.length > 0) {
                // Get the most recent rank
                const latestRank = rankData.ranks[0];
                if (latestRank && latestRank.rank) {
                    const rank = latestRank.rank;
                    
                    // Apply risk reduction based on popularity
                    // As of today, being in top 1,000,000 is considered popular and gets 20 point deduction
                    if (rank <= this.config.thresholds.popularityRankTopMillion) {
                        return this.config.thresholds.popularityReductionPoints; // Popular sites get configurable point reduction
                    }
                }
            }
            
            return 0;
        } catch (error) {
            console.debug(`Error checking popularity for ${domain}: ${error.message}`);
            return 0;
        }
    }

    /**
     * Check for common phishing indicators in domain
     */
    checkPhishingIndicators(hostname) {
        const indicators = [];

        // Check for IP address in hostname
        const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
        if (ipRegex.test(hostname)) {
            indicators.push('IP address in hostname');
        }

        // Check for suspicious TLDs
        for (const tld of this.config.suspiciousTlds) {
            if (hostname.endsWith(tld)) {
                indicators.push(`Suspicious TLD: ${tld}`);
            }
        }

        // Check for character substitution (homoglyphs)
        for (const glyph of this.config.homoglyphs) {
            if (hostname.includes(glyph.char)) {
                indicators.push(`Homoglyph detected: '${glyph.char}' looks like '${glyph.replacement}'`);
            }
        }

        // Check for excessive hyphens (often used in typo-squatting)
        const hyphenCount = (hostname.match(/-/g) || []).length;
        if (hyphenCount > this.config.thresholds.excessiveHyphens) {
            indicators.push(`Excessive hyphens (${hyphenCount}) may indicate typo-squatting`);
        }

        // Check for digits that look like letters
        for (const sub of this.config.digitSubstitutions) {
            // Check if the character exists but the lookalike letter doesn't
            // This suggests intentional substitution
            const originalLetterExists = hostname.includes(sub.replacement);
            const digitExists = hostname.includes(sub.char);
            
            if (digitExists && originalLetterExists) {
                // If both exist, check if they appear in suspicious patterns
                const pattern = new RegExp(`${sub.char}[^a-z]*${sub.replacement}|${sub.replacement}[^a-z]*${sub.char}`, 'i');
                if (pattern.test(hostname)) {
                    indicators.push(`Potential digit-letter substitution: '${sub.char}' and '${sub.replacement}'`);
                }
            }
        }

        return indicators;
    }

    /**
     * Main function to check website risk
     */
    async checkWebsiteRisk(urlString) {
        console.log(`🔍 Analyzing website: ${urlString}`);

        // Normalize the URL
        let normalizedUrl;
        try {
            if (!urlString.startsWith('http')) {
                normalizedUrl = new URL(`https://${urlString}`);
            } else {
                normalizedUrl = new URL(urlString);
            }
        } catch (error) {
            throw new Error(`Invalid URL: ${error.message}`);
        }

        const websiteUrl = normalizedUrl.href;
        const hostname = normalizedUrl.hostname;

        // Initialize risk score
        let riskScore = 0;

        // Step 1: Analyze URL structure
        console.log('\n🔍 Analyzing URL structure...');
        const urlIssues = this.analyzeUrl(websiteUrl);
        if (urlIssues.length > 0) {
            console.log(`   ⚠️  Found ${urlIssues.length} potential issues:`);
            urlIssues.forEach(issue => console.log(`      ${issue}`));
            riskScore += urlIssues.length * this.config.riskScoreMultipliers.urlIssue; // Add configurable points per URL issue
        } else {
            console.log('   ✅ URL appears structurally sound');
        }

        // Step 2: Check domain age
        console.log('\n📅 Checking domain registration age...');
        const domainAge = await this.checkDomainAge(hostname);
        if (domainAge) {
            if (domainAge.isNew) {
                console.log(`   ⚠️  Domain ${domainAge.rootDomain} is relatively new (${domainAge.ageInDays} days old)`);
                riskScore += this.config.riskScoreMultipliers.newDomainAge; // New domains get higher risk
            } else {
                console.log(`   ✅ Domain ${domainAge.rootDomain} has been registered for ${domainAge.ageInDays} days`);
            }
        } else {
            console.log('   ℹ️  Could not determine domain age (whois may not be available)');
            riskScore += this.config.riskScoreMultipliers.uncertainDomainAge; // Uncertain domain age increases risk slightly
        }

        // Step 3: Check SSL certificate
        console.log('\n🔒 Checking SSL certificate...');
        const sslResult = await this.checkSSL(hostname);
        if (sslResult.isValid) {
            console.log(`   ✅ SSL certificate is valid (issued by: ${sslResult.issuer})`);
        } else {
            console.log(`   ⚠️  SSL certificate issue: ${sslResult.error || 'Invalid certificate'}`);
            riskScore += this.config.riskScoreMultipliers.invalidSSL; // Invalid SSL significantly increases risk
        }

        // Step 4: Analyze website content
        console.log('\n📄 Analyzing website content...');
        let contentResult;
        try {
            const fetchedContent = await this.fetchWebsiteContent(websiteUrl); 
            contentResult = this.analyzeWebsiteContent(fetchedContent.content, hostname);
            console.log(`   ✅ Content fetched successfully (${fetchedContent.content.length} chars)`);
            
            if (contentResult.impersonation.length > 0) {
                console.log(`   ⚠️  Found ${contentResult.impersonation.length} potential impersonation indicators:`);
                contentResult.impersonation.forEach(imp => {
                    console.log(`      - Brand name "${imp.brand}" found in content but site is not on official domain (confidence: ${imp.confidence})`);
                });
            }
            
            if (contentResult.fraudIndicators.length > 0) {
                console.log(`   ⚠️  Found ${contentResult.fraudIndicators.length} potential fraud indicators:`);
                contentResult.fraudIndicators.forEach(ind => {
                    console.log(`      - Pattern "${ind.pattern}" found ${ind.count} times`);
                });
                riskScore += contentResult.fraudIndicators.length * this.config.riskScoreMultipliers.fraudIndicator;
            }
        } catch (error) {
            console.log(`   ⚠️  Could not fetch website content: ${error.message}`);
            console.log('   ℹ️  Proceeding with analysis based on other factors');
            riskScore += this.config.riskScoreMultipliers.contentAnalysisUnavailable; // Can't analyze content, increase risk
        }

        // Step 5: Check against threat intelligence feeds
        console.log('\n🛡️  Checking against threat intelligence feeds...');
        const threatResult = await this.checkThreatIntelligence(websiteUrl);
        
        if (threatResult.statusMessage) {
            console.log(`   ⚠️  ${threatResult.statusMessage}`);
            riskScore += this.config.riskScoreMultipliers.threatFeedUnavailable; // Add a small risk for unavailable checks
        }

        if (threatResult.isBlacklisted) {
            console.log(`   ❌ Site found in threat feeds: ${threatResult.threatsFound.join(', ')}`);
            riskScore += this.config.riskScoreMultipliers.blacklisted; // Blacklisted sites get very high risk
        } else if (!threatResult.statusMessage) { // Only log "Site not found" if no statusMessage (i.e., checks were performed and found nothing)
            console.log('   ✅ Site not found in threat feeds');
        }
        // Step 6: Check for phishing indicators in domain
        const phishingIndicators = this.checkPhishingIndicators(hostname);
        if (phishingIndicators.length > 0) {
            console.log(`   ⚠️  Found ${phishingIndicators.length} phishing indicators in domain:`);
            phishingIndicators.forEach(indicator => console.log(`      - ${indicator}`));
            riskScore += phishingIndicators.length * this.config.riskScoreMultipliers.phishingIndicator;
        }

        // Step 7: Add points for impersonation indicators with differentiated scoring
        
        // Calculate impersonation score with a cap to prevent unlimited accumulation
        let impersonationScore = 0;
        const MAX_IMPERSONATION_SCORE = this.config.maxImpersonationScore; // Cap the total points from impersonation indicators
        
        for (const impersonation of contentResult?.impersonation || []) {
            const brand = impersonation.brand.toLowerCase();
            
            // Higher risk for banking/financial brands
            const bankBrands = this.config.bankBrands;
            
            if (bankBrands.includes(brand)) {
                impersonationScore += this.config.riskScoreMultipliers.bankBrandImpersonation; // Configurable points for banking brands
            } else {
                impersonationScore += this.config.riskScoreMultipliers.otherBrandImpersonation;  // Configurable points for other tech brands
            }
            
            // Check if we've reached the cap
            if (impersonationScore >= MAX_IMPERSONATION_SCORE) {
                impersonationScore = MAX_IMPERSONATION_SCORE;
                break; // Stop processing additional impersonations once cap is reached
            }
        }
        
        // Add the capped impersonation score to the total risk score
        riskScore += impersonationScore;

        // Step 8: Check website popularity to reduce risk for popular sites
        const popularityReduction = await this.checkWebsitePopularity(hostname);
        riskScore = Math.max(0, riskScore - popularityReduction); // Ensure score doesn't go below 0

        // Step 9: Calculate final risk assessment
        console.log('\n📊 Calculating risk assessment...');
        console.log(`   Overall Risk Score: ${riskScore}/100`);

        let riskLevel, riskColor, recommendation;
        if (riskScore <= 14) {
            riskLevel = 'LOW';
            riskColor = '🟢';
            recommendation = 'Appears safe, exercise normal caution';
        } else if (riskScore <= 29) {
            riskLevel = 'MEDIUM';
            riskColor = '🟠';
            recommendation = 'Exercise caution, verify legitimacy';
        } else if (riskScore <= 49) {
            riskLevel = 'HIGH';
            riskColor = '🟡';
            recommendation = 'Exercise extreme caution';
        } else {
            riskLevel = 'CRITICAL';
            riskColor = '🔴';
            recommendation = 'Do not trust, avoid entering information';
        }

        console.log(`   Risk Level: ${riskColor} ${riskLevel}`);
        console.log('\n📋 Recommendations:');
        console.log(`   ${riskColor} ${recommendation}`);

        // Final assessment
        console.log(`\nFinal Assessment: This website is ${riskColor} ${riskLevel} risk for fraud/scam`);

        return {
            url: websiteUrl,
            riskScore,
            riskLevel,
            riskColor,
            recommendations: recommendation,
            details: {
                urlAnalysis: urlIssues,
                domainAge,
                ssl: sslResult,
                contentAnalysis: contentResult || null,
                threatIntelligence: threatResult,
                phishingIndicators,
                popularityImpact: {
                    reduction: popularityReduction,
                    domainChecked: hostname,
                    rootDomain: this.extractRootDomain(hostname)
                }
            }
        };
    }
}

// Export the class for use in other modules
export { WebsiteFraudChecker };

// If this script is run directly, execute the main function
if (import.meta.url === `file://${process.argv[1]}`) {
    async function main() {
        if (process.argv.length < 3) {
            console.log('Usage: node website_fraud_check.mjs <website_url>');
            process.exit(1);
        }

        const url = process.argv[2];
        const checker = new WebsiteFraudChecker();

        // Show threat intelligence service status
        console.log('Threat Intelligence Service Status:');
        console.log('  PhishTank: Active - Basic lookups available without API key');
        if (process.env.GOOGLE_SAFE_BROWSING_API_KEY) {
            console.log('  Google Safe Browsing: Active - API key provided');
        } else {
            console.log('  Google Safe Browsing: Inactive - Missing GOOGLE_SAFE_BROWSING_API_KEY environment variable');
        }
        console.log('');

        try {
            await checker.checkWebsiteRisk(url);
        } catch (error) {
            console.error(`Error analyzing website: ${error.message}`);
            process.exit(1);
        }
    }

    main();
}