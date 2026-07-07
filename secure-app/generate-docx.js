const fs = require('fs');
const { Document, Packer, Paragraph, TextRun, HeadingLevel, AlignmentType } = require('docx');

function H(text, level, color = "000000") {
    return new Paragraph({
        text: text,
        heading: level,
        spacing: { before: 300, after: 150 }
    });
}

function P(text, bold = false) {
    return new Paragraph({
        children: [new TextRun({ text: text, bold: bold })],
        spacing: { after: 150 }
    });
}

function ListP(text) {
    return new Paragraph({
        children: [new TextRun({ text: "• " + text })],
        spacing: { after: 100 },
        indent: { left: 400 }
    });
}

function Placeholder(title, instructions) {
    return [
        new Paragraph({
            children: [
                new TextRun({ text: `🖼️ [ SCREENSHOT NEEDED: ${title} ]`, bold: true, color: "FF0f0f", highlight: "yellow", size: 28 })
            ],
            spacing: { before: 200, after: 100 },
            alignment: AlignmentType.CENTER
        }),
        new Paragraph({
            children: [
                new TextRun({ text: `👉 Instruction for you: ${instructions}`, italics: true, color: "555555" })
            ],
            spacing: { after: 300 },
            alignment: AlignmentType.CENTER
        })
    ];
}

const doc = new Document({
    sections: [{
        properties: {},
        children: [
            // Title
            new Paragraph({
                children: [
                    new TextRun({ text: "Cybersecurity Internship Final Report", bold: true, size: 48, color: "2c3e50" }),
                ],
                alignment: AlignmentType.CENTER,
                spacing: { before: 1000, after: 200 }
            }),
            new Paragraph({
                children: [
                    new TextRun({ text: "Weeks 4–6: Advanced Web Security & Ethical Hacking", size: 32, color: "34495e" })
                ],
                alignment: AlignmentType.CENTER,
                spacing: { after: 1000 }
            }),

            new Paragraph({
                children: [new TextRun({ text: "Name: [ ENTER YOUR NAME ]", size: 24, bold: true })],
                spacing: { after: 100 }
            }),
            new Paragraph({
                children: [new TextRun({ text: "Date: July 2026", size: 24, bold: true })],
                spacing: { after: 600 }
            }),

            // Week 4
            H("Week 4: Advanced Threat Detection & Web Security Enhancements", HeadingLevel.HEADING_1),
            P("Goal: Implemented advanced security measures, detected threats in real-time, and secured API endpoints."),
            
            H("1. Intrusion Detection & Monitoring", HeadingLevel.HEADING_2),
            P("A real-time intrusion detection system (monitor.js) was created to tail log files continuously and ban IPs that trigger multiple failed logins. A dynamic IP blocker middleware drops requests from banned IPs instantly."),
            ...Placeholder("Real-Time IDS Logs", "Run 'node server.js' and 'node monitor.js' in secure-app. Try failing login 5 times. Take a screenshot of the monitor.js terminal showing the IP ban trigger and writing to blocked-ips.json."),

            H("2. API Security Hardening", HeadingLevel.HEADING_2),
            ListP("Rate Limiting: express-rate-limit applied globally (100 req/min) and strictly to logins (5 req/15 min) to prevent brute force."),
            ListP("CORS: Properly configured to restrict origins to a whitelist defined in environment variables."),
            ListP("API Keys & OAuth: Implemented robust Authentication middleware validating Bearer JWTs and custom x-api-key headers."),
            ...Placeholder("Rate Limit Output", "In Postman or terminal, trigger the /api/auth/login endpoint 6 times rapidly. Take a screenshot showing the '429 Too Many Requests' response."),

            H("3. Security Headers & CSP Implementation", HeadingLevel.HEADING_2),
            P("Utilised Helmet.js to enforce Strict-Transport-Security (HSTS) ensuring forced HTTPS, and Content Security Policy (CSP) blocking unauthorized scripts to mitigate XSS."),
            ...Placeholder("Security Headers Check", "Run 'node test-security.js' in the secure-app directory. Take a screenshot of the terminal showing all Green 🟢 passing tests for Security Headers and CORS."),

            // Week 5
            H("Week 5: Ethical Hacking & Exploiting Vulnerabilities", HeadingLevel.HEADING_1),
            P("Goal: Learned ethical hacking, exploited vulnerabilities in a test environment, and enhanced application security."),

            H("1. Exploitation & Pentesting", HeadingLevel.HEADING_2),
            P("Two parallel environments were set up: a vulnerable baseline app (port 3001) and a remediated app (port 3002). The vulnerable app was exploited using techniques mirroring tools like SQLMap and Burp Suite."),
            ...Placeholder("Vulnerability Testing Output", "Run both 'node vuln-demo-server.js' and 'node vuln-demo-server-remediated.js'. Then run 'node test-exploits.js'. Take a screenshot of the terminal output showing the Red 🔴 VULNERABLE indicators on the vulnerable app."),

            H("2. SQL Injection (SQLi)", HeadingLevel.HEADING_2),
            P("SQL Injection flaws, including login bypass and UNION-based DB dumping, were identified. They were remediated globally by replacing raw template strings with strict Parameterized Prepared Statements in sqlite3."),
            ...Placeholder("SQLi Prevention", "Take a screenshot of the test-exploits.js output specifically showing the SQLi Login Bypass Test where the Remediated App displays Green 🟢 SECURED."),
            
            H("3. Cross-Site Request Forgery (CSRF)", HeadingLevel.HEADING_2),
            P("Discovered CSRF flaws that allowed unauthorized money transfers from an external domain. Fully mitigated by integrating the `csrf-csrf` middleware implementing double-submit tokens validated on every POST request."),

            // Week 6
            H("Week 6: Advanced Security Audits & Final Deployment", HeadingLevel.HEADING_1),
            H("1. Security Audits & Compliance", HeadingLevel.HEADING_2),
            P("Manual and automated checks verified the application's compliance with OWASP Top 10 standards spanning injections, broken access control (IDOR), and security misconfigurations. All dependencies were scanned for vulnerabilities."),

            H("2. Secure Deployment Practices", HeadingLevel.HEADING_2),
            P("Dependabot configured in GitHub for weekly scans. Docker container hardened following best practices (Alpine base, multi-stage build, running as non-root 'node' user)."),
            ...Placeholder("Docker File Security", "Open your 'Dockerfile' in the editor showing line 11 'USER node'. Take a screenshot of this secure best-practice implementation."),

            H("3. Final Penetration Testing", HeadingLevel.HEADING_2),
            P("The final automated test suite confirmed 100% remediation. Every attack vector (XSS, SQLi, CSRF, IDOR) that successfully compromised the vulnerable module was categorically blocked by the remediated stack."),
            ...Placeholder("Final Penetration Success", "Take a screenshot of the test-exploits.js output showing the Remediated App returning ALL GREEN 🟢 SECURED for every test."),

            // Bonus
            H("Bonus Challenge: Zero Trust & Social Engineering", HeadingLevel.HEADING_1),
            ListP("Zero Trust: Implemented strict per-request validation. API keys and valid JWTs required at the edge; non-root user prevents file system writes."),
            ListP("WAF Setup: Designed edge security mapping and ModSecurity / AWS WAF rule strategies to filter botnets & OWASP vulnerabilities prior to hitting the container."),
            ListP("Social Engineering Simulation: Built a phishing trap (/csrf-trap) to simulate attacks utilizing urgency/prize scenarios and generated a user awareness training report based on the findings.")
        ],
    }],
});

Packer.toBuffer(doc).then((buffer) => {
    fs.writeFileSync("CyberSecurity_Weeks4_6_Submission.docx", buffer);
    console.log("SUCCESS: Created the DOCX report at: CyberSecurity_Weeks4_6_Submission.docx");
});
