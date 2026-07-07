const fs = require('fs');
const { Document, Packer, Paragraph, TextRun, HeadingLevel, AlignmentType, Table, TableRow, TableCell, WidthType, BorderStyle, ShadingType } = require('docx');

function P(text, bold=false, italic=false) {
    return new Paragraph({
        children: [new TextRun({ text, bold, italics: italic })],
        spacing: { after: 120 }
    });
}
function Center(text, bold=false, italic=false) {
    return new Paragraph({
        children: [new TextRun({ text, bold, italics: italic })],
        alignment: AlignmentType.CENTER,
        spacing: { after: 120 }
    });
}
function H1(text) {
    return new Paragraph({ children: [new TextRun({ text, bold: true, size: 32 })], spacing: { before: 240, after: 120 } });
}
function H2(text) {
    return new Paragraph({ children: [new TextRun({ text, bold: true, size: 28 })], spacing: { before: 200, after: 120 } });
}
function createMetaTable() {
    return new Table({
        width: { size: 100, type: WidthType.PERCENTAGE },
        rows: [
            new TableRow({ children: [ new TableCell({ children: [P("Secured App Repo", true)] }), new TableCell({ children: [P("https://github.com/yellow-ducky-dev/secured-app.git")] }) ] }),
            new TableRow({ children: [ new TableCell({ children: [P("Vulnerable App Repo", true)] }), new TableCell({ children: [P("https://github.com/yellow-ducky-dev/secured-app.git")] }) ] }),
            new TableRow({ children: [ new TableCell({ children: [P("Paths", true)] }), new TableCell({ children: [P("/secure-app & /vuln-demo")] }) ] }),
            new TableRow({ children: [ new TableCell({ children: [P("Version", true)] }), new TableCell({ children: [P("1.0.0")] }) ] }),
            new TableRow({ children: [ new TableCell({ children: [P("Date", true)] }), new TableCell({ children: [P("July 2026")] }) ] }),
            new TableRow({ children: [ new TableCell({ children: [P("Author", true)] }), new TableCell({ children: [P("[ ENTER YOUR NAME ]")] }) ] })
        ]
    });
}

function Placeholder(title, inst) {
    return [
        new Paragraph({
            children: [
                new TextRun({ text: `\n[ SCREENSHOT: ${title} ]`, bold: true, color: "FF0000", highlight: "yellow" })
            ],
            spacing: { before: 200 }
        }),
        P(`=> Action required: ${inst}`, false, true),
        new Paragraph({ spacing: { after: 200 } })
    ];
}

// ---------------------------------------------------------
// 1. Cybersecurity Internship Report (Weeks 4-6)
// ---------------------------------------------------------
const reportDoc = new Document({
    sections: [{
        children: [
            Center("CYBERSECURITY INTERNSHIP", true),
            Center("Security Assessment & Hardening Report"),
            Center("Secured User Management System", true),
            Center("Weeks 4–6 | Submitted: July 2026", false, true),
            createMetaTable(),
            P("Made by [ ENTER YOUR NAME ] • © 2026", false, true),
            
            H1("1. Executive Summary"),
            P("This report documents the concluding three weeks (Weeks 4-6) of the cybersecurity internship. It focuses on advanced threat detection, ethical hacking via pentest simulations, and secure deployment auditing. The implementation successfully demonstrates the setup of an IDS, rate limiting, secure headers, Zero trust principles, and mitigation of top OWASP vectors (SQLi, IDOR, CSRF, XSS)."),

            H1("2. Week 4: Threat Detection & API Security"),
            H2("2.1 Intrusion Detection System (IDS)"),
            P("Developed monitor.js to tail security logs and track failed login attempts within sliding windows. IPs executing 5 failed attempts in 60s are globally banned via ipBlocker.js."),
            ...Placeholder("IDS Automatic Ban", "Run 'node server.js' and 'node monitor.js'. Try failing login 5 times. Screenshot the monitor terminal showing the IP ban trigger."),

            H2("2.2 API Hardening & Security Headers"),
            P("Implemented express-rate-limit to stop brute forcing, strict CORS to block unauthorized origins, API key and JWT authentication. Applied Helmet.js for CSP and HSTS enforcement."),
            ...Placeholder("Helmet Headers", "Screenshot 'test-security.js' output showing green tests for 'HSTS Header' and 'CSP Header'."),

            H1("3. Week 5: Ethical Hacking & Exploiting"),
            H2("3.1 Pentest Architecture"),
            P("A test vulnerability environment was set up holding a vulnerable app (Port 3001) and security remediated app (Port 3002). Automated exploit strings simulating SQLMap and XSS were applied."),
            ...Placeholder("Pentest Summary", "Screenshot the end of the 'node test-exploits.js' terminal run showing the contrast in vulnerabilities between Remediated and Vulnerable."),

            H1("4. Week 6: Audits & Advanced Deploy Actions"),
            H2("4.1 Compliance Auditing"),
            P("Ensured compliance with OWASP Top 10 preventing Injection, Broken Auth, Security Misconfigs, and XSS. Docker container was rewritten to adhere to least-privilege using 'USER node' (non-root execution)."),
            ...Placeholder("Docker Non-Root Config", "Take a screenshot of the Dockerfile showing the line 'USER node'."),

            H1("5. Bonus Challenges"),
            P("Applied Zero Trust architecture by verifying JWT/API keys on every request edge. Generated a WAF rulesheet (waf-rules.md). Built a phishing simulation endpoint (/csrf-trap) resulting in the 'social-engineering-report' proving awareness against Cross-Site Request Forgery.")
        ]
    }]
});

// ---------------------------------------------------------
// 2. Vulnerability Testing Evidence (Weeks 4-6)
// ---------------------------------------------------------
const evidenceDoc = new Document({
    sections: [{
        children: [
            Center("VULNERABILITY ASSESSMENT", true),
            Center("Final Penetration Testing Evidence & Attack Demonstrations"),
            Center("Secured App vs Vulnerable Demo", true),
            Center("Cybersecurity Internship | July 2026", false, true),
            Center("⚠️ FOR EDUCATIONAL PURPOSES ONLY CONTROLLED ENVIRONMENT", true),
            createMetaTable(),

            H1("Vulnerability Summary Table"),
            new Table({
                width: { size: 100, type: WidthType.PERCENTAGE },
                rows: [
                    new TableRow({ children: [ new TableCell({ children: [P("ID",true)] }), new TableCell({ children: [P("Vulnerability",true)] }), new TableCell({ children: [P("Status in Remediated App",true)] }), new TableCell({ children: [P("Severity",true)] }) ] }),
                    new TableRow({ children: [ new TableCell({ children: [P("V1")] }), new TableCell({ children: [P("Reflected XSS")] }),  new TableCell({ children: [P("Escaped (validator.escape)")] }), new TableCell({ children: [P("🔴 CRITICAL")] }) ] }),
                    new TableRow({ children: [ new TableCell({ children: [P("V2")] }), new TableCell({ children: [P("SQLi Login Bypass")] }),new TableCell({ children: [P("Blocked (Parameterized Query)")] }), new TableCell({ children: [P("🔴 CRITICAL")] }) ] }),
                    new TableRow({ children: [ new TableCell({ children: [P("V3")] }), new TableCell({ children: [P("SQLi UNION Dump")] }), new TableCell({ children: [P("Blocked (Parameterized Query)")] }), new TableCell({ children: [P("🔴 HIGH")] }) ] }),
                    new TableRow({ children: [ new TableCell({ children: [P("V4")] }), new TableCell({ children: [P("IDOR (Profile Dump)")] }), new TableCell({ children: [P("Blocked (Auth JWT check)")] }), new TableCell({ children: [P("🔴 HIGH")] }) ] }),
                    new TableRow({ children: [ new TableCell({ children: [P("V5")] }), new TableCell({ children: [P("CSRF Fund Transfer")] }), new TableCell({ children: [P("Blocked (csrf-csrf double submit)")] }), new TableCell({ children: [P("🔴 HIGH")] }) ] }),
                ]
            }),

            H1("Attack 1 — Reflected XSS (V1)"),
            P("Payload: <script>alert('XSS-TEST')</script> submitted via URL search parameter q."),
            ...Placeholder("XSS Test Output", "Screenshot the test-exploits.js console output under '[Test 1: Reflected XSS]'."),

            H1("Attack 2 & 3 — SQL Injection (V2, V3)"),
            P("Payloads: admin' -- inside username, and alice' UNION SELECT... inside search parameter."),
            P("The vulnerable app leaks all MD5 hashes via union dump, and bypasses login completely."),
            ...Placeholder("SQLi Output", "Screenshot the console output under '[Test 2: SQLi Login Bypass]' and '[Test 3: SQLi UNION DB Dump]'."),

            H1("Attack 4 — IDOR Info Disclosure (V4)"),
            P("Directly accessing /api/user/1 exposed the password hash of the admin on the vulnerable environment."),
            ...Placeholder("IDOR Output", "Screenshot the console output under '[Test 4: IDOR]'."),

            H1("Attack 5 — Cross-Site Request Forgery CSRF (V5)"),
            P("Triggered an automated 3rd-party POST request transferring wallet funds utilizing the local valid cookie session."),
            ...Placeholder("CSRF Output", "Screenshot the console output under '[Test 5: Cross-Site Request Forgery]'."),
        ]
    }]
});

Packer.toBuffer(reportDoc).then((buf) => fs.writeFileSync("Cybersecurity_Internship_Report_Weeks4_6.docx", buf));
Packer.toBuffer(evidenceDoc).then((buf) => fs.writeFileSync("Vulnerability_Testing_Evidence_Weeks4_6.docx", buf));
console.log("Documents successfully created in current folder.");
