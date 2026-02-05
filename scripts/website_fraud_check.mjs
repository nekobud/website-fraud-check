#!/usr/bin/env node

import { execSync } from 'child_process';
import https from 'https';
import http from 'http';
import { URL } from 'url';

class WebsiteFraudChecker {
    constructor() {
        // Common suspicious patterns in URLs
        this.suspiciousPatterns = [
            /\.tk(?![a-z])/,         // Free domain providers
            /\.ml(?![a-z])/,         // Free domain providers
            /\.ga(?![a-z])/,         // Free domain providers
            /\.cf(?![a-z])/,         // Free domain providers
            /\.bit(?![a-z])/,        // Free domain providers
            /secure/i,               // Impersonation keywords
            /login/i,
            /account/i,
            /verify/i,
            /confirm/i,
            /update/i,
            /payment/i,
            /bank/i,
            /paypal/i,
            /appleid/i,
            /microsoft/i,
            /google/i,
            /facebook/i,
            /amazon/i,
            /sso/i,                  // Single sign-on impersonation
            /oauth/i,                // OAuth impersonation
            /auth/i,                 // Authentication impersonation
            /signin/i,
            /sign_in/i,
            /log-in/i,
            /log_in/i,
            /www\d*\./,             // Multiple www variations
            /-\w*-\w*-/              // Too many hyphens (typo-squatting)
        ];

        // Known legitimate domains (add more as needed)
        this.legitimateDomains = [
            'google.com',
            'www.google.com',
            'accounts.google.com',
            'drive.google.com',
            'mail.google.com',
            'gmail.com',
            'www.gmail.com',
            'youtube.com',
            'www.youtube.com',
            'facebook.com',
            'www.facebook.com',
            'instagram.com',
            'www.instagram.com',
            'twitter.com',
            'www.twitter.com',
            'linkedin.com',
            'www.linkedin.com',
            'microsoft.com',
            'www.microsoft.com',
            'office.com',
            'www.office.com',
            'live.com',
            'www.live.com',
            'hotmail.com',
            'www.hotmail.com',
            'outlook.com',
            'www.outlook.com',
            'apple.com',
            'www.apple.com',
            'icloud.com',
            'www.icloud.com',
            'amazon.com',
            'www.amazon.com',
            'aws.amazon.com',
            'paypal.com',
            'www.paypal.com',
            'ebay.com',
            'www.ebay.com',
            'netflix.com',
            'www.netflix.com',
            'spotify.com',
            'www.spotify.com',
            'adobe.com',
            'www.adobe.com',
            'github.com',
            'www.github.com',
            'stackoverflow.com',
            'www.stackoverflow.com',
            'wikipedia.org',
            'www.wikipedia.org',
            'yahoo.com',
            'www.yahoo.com',
            'bing.com',
            'www.bing.com',
            'duckduckgo.com',
            'www.duckduckgo.com',
            // Hong Kong banks
            'hangseng.com',
            'www.hangseng.com',
            'hkbea.com',
            'www.hkbea.com',
            'standardchartered.com.hk',
            'www.standardchartered.com.hk',
            'hsbc.com.hk',
            'www.hsbc.com.hk',
            'sc.com',
            'www.sc.com',
            'dbs.com.hk',
            'www.dbs.com.hk',
            'ocbc.com.hk',
            'www.ocbc.com.hk',
            'bankcomm.com.hk',
            'www.bankcomm.com.hk',
            'citicbank.com.hk',
            'www.citicbank.com.hk',
            // Other Hong Kong financial institutions
            'bochk.com',
            'www.bochk.com',
            'winglungbank.com',
            'www.winglungbank.com',
            'chbank.com',
            'www.chbank.com',
            // Government domains
            '.gov.hk',
            '.gov.cn'
        ];

        // Suspicious keywords that might indicate impersonation
        this.suspiciousKeywords = [
            'secure', 'login', 'account', 'verify', 'confirm', 'update', 'payment',
            'bank', 'paypal', 'appleid', 'microsoft', 'google', 'facebook', 'amazon',
            'sso', 'oauth', 'auth', 'signin', 'sign_in', 'log-in', 'log_in',
            'www', 'customer', 'service', 'support', 'help', 'recovery', 'reset',
            'password', 'forgot', 'change', 'manage', 'access', 'authorize'
        ];

        // Brand names to watch for impersonation
        this.brandNames = [
            'google', 'facebook', 'paypal', 'apple', 'microsoft', 'amazon', 'netflix',
            'spotify', 'adobe', 'github', 'twitter', 'instagram', 'linkedin',
            'youtube', 'gmail', 'outlook', 'hotmail', 'icloud', 'yahoo', 'bing',
            'duckduckgo', 'wikipedia', 'stackoverflow', 'hangseng', 'hsbc', 'bochk',
            'bankofchina', 'standardchartered', 'dbs', 'ocbc', 'citicbank', 'winglung',
            'chbank', 'hkbea', 'bankcomm'
        ];
    }

    /**
     * Analyze URL for suspicious patterns
     */
    analyzeUrl(urlString) {
        const issues = [];

        // Validate URL format
        try {
            new URL(urlString);
        } catch (e) {
            issues.push('Invalid URL format');
            return issues; // If URL is invalid, return early
        }

        // Check for IP address in URL
        const ipRegex = /\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/;
        if (ipRegex.test(urlString)) {
            issues.push('URL contains IP address instead of domain name');
        }

        // Check for URL shorteners
        const shortenerDomains = [
            'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd',
            'buff.ly', 'rebrand.ly', 'cli.re', 'qr.ae', 'youtu.be'
        ];
        for (const shortener of shortenerDomains) {
            if (urlString.includes(shortener)) {
                issues.push(`URL uses known URL shortener: ${shortener}`);
                break;
            }
        }

        // Check for excessive subdomains (could indicate typo-squatting)
        const subdomainParts = urlString.split('.');
        if (subdomainParts.length > 4) {
            issues.push('Excessive number of subdomains');
        }

        // Check for suspicious patterns in the full URL
        for (const pattern of this.suspiciousPatterns) {
            if (pattern.test(urlString)) {
                issues.push(`Contains suspicious pattern: ${pattern}`);
            }
        }

        // Check for excessive special characters
        const specialCharCount = (urlString.match(/[^a-zA-Z0-9.-]/g) || []).length;
        const ratio = specialCharCount / urlString.length;
        if (ratio > 0.3) {
            issues.push('High proportion of special characters');
        }

        return issues;
    }

    /**
     * Check domain age using whois
     */
    async checkDomainAge(domain) {
        try {
            // On some systems, whois might not be available or may require sudo
            // We'll handle this gracefully
            const result = execSync(`whois "${domain}"`, { encoding: 'utf8', timeout: 10000 });
            
            // Look for creation/registration date patterns in the whois output
            const datePatterns = [
                /created[^\d]*(\d{4}-\d{2}-\d{2})/i,
                /creation date[^\d]*(\d{4}-\d{2}-\d{2})/i,
                /registration date[^\d]*(\d{4}-\d{2}-\d{2})/i,
                /registered[^\d]*(\d{4}-\d{2}-\d{2})/i,
                /created on[^\d]*(\d{4}-\d{2}-\d{2})/i,
                /create date[^\d]*(\d{4}-\d{2}-\d{2})/i,
                /register date[^\d]*(\d{4}-\d{2}-\d{2})/i,
                /registrar registration[^\d]*(\d{4}-\d{2}-\d{2})/i
            ];

            for (const pattern of datePatterns) {
                const match = result.match(pattern);
                if (match) {
                    const creationDate = new Date(match[1]);
                    const today = new Date();
                    const diffTime = Math.abs(today - creationDate);
                    const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));

                    return {
                        ageInDays: diffDays,
                        creationDate: match[1],
                        isNew: diffDays < 365 // Less than 1 year old
                    };
                }
            }

            // If no creation date found, return null
            return null;
        } catch (error) {
            // If whois command fails, try alternative methods or return null
            // This could happen if whois is not installed or accessible
            console.debug(`Could not check domain age for ${domain}: ${error.message}`);
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
                        resolve({
                            isValid: false,
                            issuer: null,
                            error: 'No certificate presented'
                        });
                    } else {
                        const now = new Date();
                        const validFrom = new Date(cert.valid_from);
                        const validUntil = new Date(cert.valid_to);

                        resolve({
                            isValid: now >= validFrom && now <= validUntil,
                            issuer: cert.issuer.CN || cert.issuer.O,
                            error: now < validFrom ? 'Certificate not yet valid' : 
                                  now > validUntil ? 'Certificate expired' : null
                        });
                    }
                } else {
                    resolve({
                        isValid: false,
                        issuer: null,
                        error: 'Could not retrieve certificate'
                    });
                }

                // End the request to prevent hanging
                res.destroy();
            }).on('error', (err) => {
                resolve({
                    isValid: false,
                    issuer: null,
                    error: err.message
                });
            }).on('timeout', () => {
                req.destroy();
                resolve({
                    isValid: false,
                    issuer: null,
                    error: 'Connection timeout'
                });
            });

            req.end();
        });
    }

    /**
     * Check against known threat intelligence feeds (PhishTank API, Google Safe Browsing API)
     */
    async checkThreatIntelligence(domain) {
        try {
            // Initialize results array to collect findings from all threat feeds
            const allThreats = [];
            let isBlacklisted = false;
            let confidence = 'low';
            const serviceStatus = {
                phishTank: { active: false, message: '' },
                googleSafeBrowsing: { active: false, message: '' }
            };

            // Check PhishTank (doesn't require API key)
            const phishTankResult = await this.checkPhishTank(domain);
            serviceStatus.phishTank.active = true;
            serviceStatus.phishTank.message = 'Active - Basic lookups available without API key';
            if (phishTankResult.isBlacklisted) {
                isBlacklisted = true;
                allThreats.push(...phishTankResult.threatsFound);
                confidence = 'high';
            }

            // Check Google Safe Browsing API (requires API key)
            const googleResult = await this.checkGoogleSafeBrowsing(domain);
            if (process.env.GOOGLE_SAFE_BROWSING_API_KEY) {
                serviceStatus.googleSafeBrowsing.active = true;
                serviceStatus.googleSafeBrowsing.message = 'Active - API key provided';
            } else {
                serviceStatus.googleSafeBrowsing.message = 'Inactive - Missing GOOGLE_SAFE_BROWSING_API_KEY environment variable';
            }
            if (googleResult.isBlacklisted) {
                isBlacklisted = true;
                allThreats.push(...googleResult.threatsFound);
                confidence = 'high';
            }

            // Log service status for transparency
            console.log('Threat Intelligence Service Status:');
            console.log(`  PhishTank: ${serviceStatus.phishTank.message}`);
            console.log(`  Google Safe Browsing: ${serviceStatus.googleSafeBrowsing.message}`);

            return {
                isBlacklisted,
                threatsFound: allThreats,
                confidence,
                serviceStatus  // Include service status in the result
            };
        } catch (error) {
            console.debug(`Threat intelligence check failed: ${error.message}. Using fallback.`);
            // Fallback to phishing indicators check
            return this.checkPhishingIndicators(domain);
        }
    }

    /**
     * Check URL against PhishTank API
     */
    async checkPhishTank(domain) {
        try {
            // PhishTank API requires an HTTP POST request to the correct endpoint
            // Endpoint: http://checkurl.phishtank.com/checkurl/
            // Request parameters: url, format (json), app_key (optional)
            // Headers: Descriptive User-Agent required

            // Prepare the POST request body with URL encoding
            const urlToCheck = `https://${domain}`;
            const postData = `url=${encodeURIComponent(urlToCheck)}&format=json`;

            // Create the HTTP request options for the correct endpoint
            const options = {
                hostname: 'checkurl.phishtank.com',
                port: 80,  // Note: the endpoint uses HTTP, not HTTPS
                path: '/checkurl/',
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'Content-Length': Buffer.byteLength(postData),
                    'User-Agent': 'phishtank/Nekochan'  // Required descriptive User-Agent
                }
            };

            // Make the POST request using Node.js http module
            return new Promise((resolve) => {
                const req = http.request(options, (res) => {
                    let data = '';

                    res.on('data', (chunk) => {
                        data += chunk;
                    });

                    res.on('end', () => {
                        try {
                            const response = JSON.parse(data);

                            // Check if the URL is in PhishTank database
                            if (response && response.results) {
                                // Look for the URL entry in results (format varies by URL)
                                const urlKey = Object.keys(response.results).find(key =>
                                    key.startsWith('url')
                                );

                                if (urlKey && response.results[urlKey]) {
                                    const urlResult = response.results[urlKey];

                                    if (urlResult.in_database && urlResult.valid) {
                                        resolve({
                                            isBlacklisted: true,
                                            threatsFound: [`Verified phishing site in PhishTank database (ID: ${urlResult.phish_id})`],
                                            confidence: 'high'
                                        });
                                    } else {
                                        resolve({
                                            isBlacklisted: false,
                                            threatsFound: [],
                                            confidence: 'high'
                                        });
                                    }
                                } else {
                                    // If URL not found in database
                                    resolve({
                                        isBlacklisted: false,
                                        threatsFound: [],
                                        confidence: 'high'
                                    });
                                }
                            } else {
                                resolve({
                                    isBlacklisted: false,
                                    threatsFound: [],
                                    confidence: 'high'
                                });
                            }
                        } catch (parseError) {
                            console.debug(`Failed to parse PhishTank response: ${parseError.message}`);
                            resolve({
                                isBlacklisted: false,
                                threatsFound: [],
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
                        confidence: 'low'
                    });
                });

                // Write the post data and end the request
                req.write(postData);
                req.end();
            });
        } catch (error) {
            console.debug(`PhishTank API check failed: ${error.message}`);
            return {
                isBlacklisted: false,
                threatsFound: [],
                confidence: 'low'
            };
        }
    }

    /**
     * Check URL against Google Safe Browsing API
     */
    async checkGoogleSafeBrowsing(domain) {
        try {
            // Google Safe Browsing API requires an API key
            // API endpoint: https://safebrowsing.googleapis.com/v4/threatMatches:find
            // Requires registration at https://developers.google.com/safe-browsing/

            // For this implementation, we'll check for the presence of an API key in environment
            const apiKey = process.env.GOOGLE_SAFE_BROWSING_API_KEY;

            if (!apiKey) {
                // Without an API key, we cannot make requests to Google Safe Browsing
                return {
                    isBlacklisted: false,
                    threatsFound: [],
                    confidence: 'low'
                };
            }

            const urlToCheck = `https://${domain}`;
            const requestBody = {
                client: {
                    clientId: "website-fraud-check-skill",
                    clientVersion: "1.0.0"
                },
                threatInfo: {
                    threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                    platformTypes: ["ANY_PLATFORM"],
                    threatEntryTypes: ["URL"],
                    threatEntries: [
                        { url: urlToCheck }
                    ]
                }
            };

            // Create the HTTP request options
            const options = {
                hostname: 'safebrowsing.googleapis.com',
                port: 443,
                path: `/v4/threatMatches:find?key=${apiKey}`,
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Content-Length': Buffer.byteLength(JSON.stringify(requestBody))
                }
            };

            return new Promise((resolve) => {
                const req = https.request(options, (res) => {
                    let data = '';

                    res.on('data', (chunk) => {
                        data += chunk;
                    });

                    res.on('end', () => {
                        try {
                            const response = JSON.parse(data);

                            if (response && response.matches && response.matches.length > 0) {
                                // URL is flagged as dangerous
                                const threatTypes = response.matches.map(match => match.threatType);
                                resolve({
                                    isBlacklisted: true,
                                    threatsFound: [`Flagged by Google Safe Browsing as: ${threatTypes.join(', ')}`],
                                    confidence: 'high'
                                });
                            } else {
                                // URL is not in the threat list
                                resolve({
                                    isBlacklisted: false,
                                    threatsFound: [],
                                    confidence: 'high'
                                });
                            }
                        } catch (parseError) {
                            console.debug(`Failed to parse Google Safe Browsing response: ${parseError.message}`);
                            resolve({
                                isBlacklisted: false,
                                threatsFound: [],
                                confidence: 'low'
                            });
                        }
                    });
                });

                req.on('error', (error) => {
                    console.debug(`Google Safe Browsing API request failed: ${error.message}`);
                    resolve({
                        isBlacklisted: false,
                        threatsFound: [],
                        confidence: 'low'
                    });
                });

                // Write the request body and end the request
                req.write(JSON.stringify(requestBody));
                req.end();
            });
        } catch (error) {
            console.debug(`Google Safe Browsing API check failed: ${error.message}`);
            return {
                isBlacklisted: false,
                threatsFound: [],
                confidence: 'low'
            };
        }
    }

    /**
     * Analyze website content for impersonation and fraud indicators
     */
    analyzeWebsiteContent(content, hostname) {
        const impersonation = [];
        const fraudIndicators = [];
        const brandMentions = [];

        // Convert content to lowercase for easier searching
        const lowerContent = content.toLowerCase();

        // Look for brand names in the content
        for (const brand of this.brandNames) {
            if (lowerContent.includes(brand.toLowerCase())) {
                brandMentions.push(brand);
                
                // Check if the brand is being impersonated (not on legitimate domain)
                const isLegitimate = this.legitimateDomains.some(domain => 
                    hostname.includes(domain) || domain.includes(hostname)
                );
                
                if (!isLegitimate) {
                    impersonation.push({
                        brand: brand,
                        evidence: `Brand name "${brand}" found in content but site is not on official domain`,
                        confidence: 'high'
                    });
                }
            }
        }

        // Look for suspicious phrases that indicate phishing or fraud
        const suspiciousPhrases = [
            'urgent', 'immediate action required', 'verify your account',
            'confirm your information', 'update your details', 'secure login',
            'suspicious activity', 'unauthorized access', 'locked account',
            'compromised account', 'verify identity', 'confirm identity',
            'enter password', 'login now', 'act now', 'limited time',
            'suspicious login', 'security alert', 'identity verification'
        ];

        for (const phrase of suspiciousPhrases) {
            if (lowerContent.includes(phrase.toLowerCase())) {
                fraudIndicators.push(phrase);
            }
        }

        // Look for form elements that might collect sensitive information
        const sensitiveFormFields = ['password', 'ssn', 'creditcard', 'cvv', 'pin'];
        for (const field of sensitiveFormFields) {
            if (lowerContent.includes(`<input`) && lowerContent.includes(field)) {
                fraudIndicators.push(`Form contains ${field} field`);
            }
        }

        return {
            impersonation,
            fraudIndicators,
            brandMentions
        };
    }

    /**
     * Fetch website content for analysis
     */
    async fetchWebsiteContent(urlString) {
        const url = new URL(urlString);

        return new Promise((resolve, reject) => {
            const protocol = url.protocol === 'https:' ? https : http;
            const requestOptions = {
                hostname: url.hostname,
                port: url.port,
                path: url.pathname + url.search,
                method: 'GET',
                headers: {
                    'User-Agent': 'Mozilla/5.0 (compatible; FraudCheckBot/1.0)'
                },
                timeout: 10000,
                rejectUnauthorized: false
            };

            const req = protocol.request(requestOptions, (res) => {
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
     * Main function to check website risk
     */
    async checkWebsiteRisk(websiteUrl) {
        console.log(`🔍 Analyzing website: ${websiteUrl}`);
        console.log('');

        // Parse the URL to extract hostname
        let parsedUrl;
        try {
            parsedUrl = new URL(websiteUrl);
        } catch (error) {
            console.error(`❌ Invalid URL: ${error.message}`);
            return;
        }

        const hostname = parsedUrl.hostname;

        // 1. Analyze URL for suspicious patterns
        console.log('🔍 Analyzing URL structure...');
        const urlIssues = this.analyzeUrl(websiteUrl);
        if (urlIssues.length > 0) {
            console.log(`   ❌ Found ${urlIssues.length} potential issues:`);
            for (const issue of urlIssues) {
                console.log(`      - ${issue}`);
            }
        } else {
            console.log(`   ✅ URL appears structurally sound`);
        }
        console.log('');

        // 2. Check domain age
        console.log('📅 Checking domain registration age...');
        const domainAge = await this.checkDomainAge(hostname);
        if (domainAge) {
            if (domainAge.isNew) {
                console.log(`   ⚠️  Domain is relatively new (${domainAge.ageInDays} days old)`);
            } else {
                console.log(`   ✅ Domain has been registered for ${domainAge.ageInDays} days`);
            }
        } else {
            console.log(`   ℹ️  Could not determine domain age (whois may not be available)`);
        }
        console.log('');

        // 3. Check SSL certificate
        console.log('🔒 Checking SSL certificate...');
        const sslCheck = await this.checkSSL(hostname);
        if (sslCheck.isValid) {
            console.log(`   ✅ SSL certificate is valid (issued by: ${sslCheck.issuer})`);
        } else {
            console.log(`   ❌ SSL certificate issue: ${sslCheck.error || 'Invalid certificate'}`);
        }
        console.log('');

        // 4. Analyze website content
        console.log('📄 Analyzing website content...');
        try {
            const response = await this.fetchWebsiteContent(websiteUrl);
            if (response.statusCode >= 200 && response.statusCode < 400) {
                console.log(`   ✅ Content fetched successfully (${response.content.length} chars)`);

                const contentAnalysis = this.analyzeWebsiteContent(response.content, hostname);
                if (contentAnalysis.impersonation.length > 0) {
                    console.log(`   ⚠️  Found ${contentAnalysis.impersonation.length} potential impersonation indicators:`);
                    for (const imp of contentAnalysis.impersonation) {
                        console.log(`      - ${imp.evidence} (confidence: ${imp.confidence})`);
                    }
                } else {
                    console.log(`   ✅ No clear impersonation indicators found`);
                }
            } else {
                console.log(`   ❌ Failed to fetch content: Status ${response.statusCode}`);
            }
        } catch (error) {
            console.log(`   ⚠️  Could not fetch content: ${error.message}`);
        }
        console.log('');

        // 5. Check against threat intelligence (simulated)
        console.log('🛡️  Checking against threat intelligence feeds...');
        const threatResult = await this.checkThreatIntelligence(hostname);
        if (threatResult.isBlacklisted) {
            console.log(`   ❌ Site is blacklisted in threat feeds!`);
            console.log(`   Threats found: ${threatResult.threatsFound.join(', ')}`);
        } else {
            console.log(`   ✅ Site not found in threat feeds`);
        }
        console.log('');

        // 6. Calculate risk score
        console.log('📊 Calculating risk assessment...');
        let riskScore = 0;

        // Add points for URL issues
        riskScore += urlIssues.length * 10;

        // Add points for new domain
        if (domainAge && domainAge.isNew) {
            riskScore += 20;
        }

        // Add points for SSL issues
        if (!sslCheck.isValid) {
            riskScore += 15;
        }

        // Add points for impersonation indicators
        const contentAnalysis = await this.analyzeContentWithoutFetching(websiteUrl, hostname).catch(() => ({ impersonation: [] }));
        riskScore += contentAnalysis.impersonation.length * 25;

        // Add points if blacklisted
        if (threatResult.isBlacklisted) {
            riskScore += 50;
        }

        // Determine risk level
        let riskLevel;
        let riskColor;
        if (riskScore < 15) {
            riskLevel = 'LOW';
            riskColor = '🟢';
        } else if (riskScore < 30) {
            riskLevel = 'MEDIUM';
            riskColor = '🟠';
        } else if (riskScore < 50) {
            riskLevel = 'HIGH';
            riskColor = '🟡';
        } else {
            riskLevel = 'CRITICAL';
            riskColor = '🔴';
        }

        console.log(`   Overall Risk Score: ${riskScore}/100`);
        console.log(`   Risk Level: ${riskColor} ${riskLevel}`);
        console.log('');

        // 7. Provide recommendations
        console.log('📋 Recommendations:');
        if (riskScore < 15) {
            console.log(`   ✅ Appears safe, exercise normal caution`);
        } else if (riskScore < 30) {
            console.log(`   ⚠️  Exercise caution. Double-check the website before entering sensitive information.`);
            console.log(`   🔍 Verify this is a legitimate new site before providing any information.`);
        } else if (riskScore < 50) {
            console.log(`   ⚠️  Exercise extreme caution. Verify authenticity before proceeding.`);
            console.log(`   ❌ Avoid entering any sensitive information until legitimacy is confirmed.`);
        } else {
            console.log(`   ❌ Do not trust this site. Avoid entering any information.`);
            console.log(`   🔴 Highly likely to be fraudulent or malicious.`);
        }
        console.log('');

        // Final assessment
        console.log(`Final Assessment: This website is ${riskColor} ${riskLevel} risk for fraud/scam`);

        return {
            url: websiteUrl,
            riskScore,
            riskLevel,
            issues: {
                urlIssues,
                domainAge,
                sslCheck,
                threatResult
            }
        };
    }

    /**
     * Helper function to analyze content without fetching (used for error handling)
     */
    async analyzeContentWithoutFetching(websiteUrl, hostname) {
        // This is a helper to avoid fetching content when there are other issues
        // In a real implementation, we'd fetch the content as needed
        try {
            const response = await this.fetchWebsiteContent(websiteUrl);
            if (response.statusCode >= 200 && response.statusCode < 400) {
                return this.analyzeWebsiteContent(response.content, hostname);
            }
        } catch (error) {
            console.debug(`Could not fetch content for analysis: ${error.message}`);
        }
        return { impersonation: [], fraudIndicators: [], brandMentions: [] };
    }

    /**
     * Helper function to check for common phishing indicators in domain
     */
    checkPhishingIndicators(domain) {
        // Fallback: check for common phishing indicators
        const phishingIndicators = [
            'secure-login', 'verify-account', 'update-information',
            'confirm-details', 'banking-alert', 'suspicious-login'
        ];

        // Check if domain contains common phishing indicators
        const hasPhishingIndicators = phishingIndicators.some(indicator =>
            domain.toLowerCase().includes(indicator)
        );

        if (hasPhishingIndicators) {
            return {
                isBlacklisted: true,
                threatsFound: ['Domain contains common phishing indicators'],
                confidence: 'medium'
            };
        }

        return {
            isBlacklisted: false,
            threatsFound: [],
            confidence: 'high'
        };
    }
}

async function main() {
    const args = process.argv.slice(2);

    if (args.length === 0) {
        console.error('Usage: node website_fraud_check.mjs <website_url>');
        console.error('Example: node website_fraud_check.mjs https://example.com');
        process.exit(1);
    }

    const checker = new WebsiteFraudChecker();

    try {
        await checker.checkWebsiteRisk(args[0]);
    } catch (error) {
        console.error('Error during fraud check:', error.message);
        process.exit(1);
    }
}

if (import.meta.url === `file://${process.argv[1]}`) {
    main();
}

export { WebsiteFraudChecker };