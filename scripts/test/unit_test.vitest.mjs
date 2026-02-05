import { test, describe, expect, beforeEach, afterEach } from 'vitest';
import { WebsiteFraudChecker } from '../website_fraud_check.mjs';

describe('WebsiteFraudChecker', () => {
    let checker;

    beforeEach(() => {
        checker = new WebsiteFraudChecker();
    });

    test('should detect suspicious patterns in URLs', () => {
        const suspiciousUrls = [
            'https://facebook.fps-hk.band/merchant/bank-confirm/chb/522444241',
            'https://secure-paypal.login.com/',
            'https://hsbc.verify-account.com/',
            'https://bank.update-payment.info/'
        ];

        for (const url of suspiciousUrls) {
            const issues = checker.analyzeUrl(url);
            expect(issues.length).toBeGreaterThan(0);
        }
    });

    test('should identify legitimate domains correctly', () => {
        const legitimateDomains = [
            'https://www.facebook.com/',
            'https://www.google.com/',
            'https://www.hsbc.com.hk/',
            'https://www.hangseng.com/'
        ];

        for (const url of legitimateDomains) {
            // We can't test domain age without whois, so we'll focus on URL analysis
            const issues = checker.analyzeUrl(url);
            // Legitimate sites shouldn't have many suspicious patterns
            expect(issues.length).toBeLessThan(2);
        }
    });

    test('should detect suspicious keywords in URL', () => {
        const urlWithKeywords = 'https://fake-site.com/bank-confirm/verify-payment';
        const issues = checker.analyzeUrl(urlWithKeywords);
        
        // Should detect suspicious patterns like 'bank', 'confirm', 'verify'
        expect(issues.length).toBeGreaterThan(0);
    });

    test('should identify IP addresses in URLs as suspicious', () => {
        const urlWithIP = 'https://192.168.1.1/login.php';
        const issues = checker.analyzeUrl(urlWithIP);
        
        expect(issues.some(issue => issue.includes('IP address'))).toBe(true);
    });

    test('should identify URL shorteners as suspicious', () => {
        const urlWithShortener = 'https://bit.ly/3abc123';
        const issues = checker.analyzeUrl(urlWithShortener);
        
        expect(issues.some(issue => issue.includes('URL shortener'))).toBe(true);
    });

    test('should properly initialize with suspicious patterns', () => {
        expect(checker.suspiciousPatterns).toBeDefined();
        expect(Array.isArray(checker.suspiciousPatterns)).toBe(true);
        expect(checker.suspiciousPatterns.length).toBeGreaterThan(0);
    });

    test('should properly initialize with legitimate domains', () => {
        expect(checker.legitimateDomains).toBeDefined();
        expect(Array.isArray(checker.legitimateDomains)).toBe(true);
        expect(checker.legitimateDomains.length).toBeGreaterThan(0);
    });
});