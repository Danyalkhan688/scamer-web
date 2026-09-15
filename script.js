/* ==========================================================================
   TRUSTGUARD AI — Fraud, Scam & Threat Intelligence Platform
   Core Application Engine & Multi-Country Configuration
   ========================================================================== */

// --------------------------------------------------------------------------
// 1. Country Configurations & Synthetic Datasets Ledger
// --------------------------------------------------------------------------
const countrySystems = {
    pakistan: {
        code: 'PK',
        countryName: 'Pakistan',
        flag: '🇵🇰',
        currency: 'PKR',
        currencySymbol: 'Rs.',
        identityLabel: 'CNIC-style Identity Card',
        identityExample: '42101-9824102-3',
        phoneFormat: '+92 3XX XXXXXXX',
        phoneExample: '+92 300 8291042',
        accountLabel: 'Bank IBAN / Account',
        accountExample: 'PK36 FAYS 0001 2984 0192 01',
        authorityName: 'Federal Investigation Authority (Demo Simulation)',
        casePrefix: 'TG-PK-',
        searchPlaceholder: 'Search PK Phone (+92...), CNIC (42101...), IBAN, email, case ID...',
        sampleScannerValues: [
            { label: 'Suspicious PK Phone', type: 'phone', value: '+92 300 8291042' },
            { label: 'Synthetic CNIC Record', type: 'identity', value: '42101-9824102-3' },
            { label: 'Mule Account IBAN', type: 'account', value: 'PK36 FAYS 0001 2984 0192 01' },
            { label: 'Phishing URL', type: 'url', value: 'http://verify-bank-pk-sec.top/login' }
        ],
        stats: {
            threatLevel: 'CRITICAL',
            activeCases: 5,
            suspiciousEntities: 24,
            reportsToday: 18
        },
        demoCases: [
            {
                id: 'TG-PK-20491',
                threatLevel: 'CRITICAL THREAT',
                threatType: 'ACCOUNT TAKEOVER',
                confidence: '96%',
                evidenceStrength: 'STRONG',
                patternMatch: '94%',
                anomalyLevel: 'SEVERE',
                priority: 'P0 — IMMEDIATE',
                targetIdentifier: '+92 300 8291042',
                created: 'Today 08:42 AM',
                status: 'OPEN',
                radar: { identity: 92, financial: 96, device: 88, network: 78, behaviour: 90, communication: 65 },
                fingerprint: {
                    title: 'Coordinated SIM-Swap & Banking Account Takeover',
                    match: '94%',
                    tags: ['Identity Manipulation', 'Device Switch Anomaly', 'High Velocity Transfer', 'Beneficiary Addition', 'OTP Intercept Signal']
                },
                whyFlagged: [
                    {
                        title: 'Unusual Transaction Velocity',
                        severity: 'HIGH',
                        evidence: 'Rs. 450,000 transferred across 4 beneficiaries within 8 minutes.',
                        explanation: 'Transaction frequency is 12x higher than synthetic historical baseline for this profile.'
                    },
                    {
                        title: 'New Device Hardware Fingerprint',
                        severity: 'CRITICAL',
                        evidence: 'Device ID #DEV-PK-9812 logged in from Lahore via Android emulator.',
                        explanation: 'First-time authentication from an untrusted hardware ID.'
                    },
                    {
                        title: 'Connected Mule Account Network',
                        severity: 'HIGH',
                        evidence: 'Target account IBAN PK36 FAYS... linked to 3 previous scam reports.',
                        explanation: 'Graph analysis confirms multi-entity link to known fraud ledger.'
                    }
                ],
                timeline: [
                    { time: '08:42 AM', title: 'New Device Hardware Detected', desc: 'Login attempt from Android Emulator ID #DEV-PK-9812 in Lahore.', threat: 'danger' },
                    { time: '08:44 AM', title: 'Authentication Anomaly', desc: 'Multiple OTP retries via automated SMS channel.', threat: 'warn' },
                    { time: '08:47 AM', title: 'New Beneficiary Added', desc: 'IBAN PK36 FAYS 0001 2984... added to instant transfer list.', threat: 'warn' },
                    { time: '08:49 AM', title: 'High-Value Transfer Initiated', desc: 'Rs. 250,000 outbound transfer requested.', threat: 'danger' },
                    { time: '08:50 AM', title: 'Automated P0 Threat Alert Generated', desc: 'Synthetic risk engine flagged case TG-PK-20491 as Critical.', threat: 'danger' }
                ],
                graphNodes: [
                    { id: 'n1', label: 'Tariq Ahmed (Victim)', type: 'person', risk: 'low', details: 'Synthetic CNIC: 42101-9824102-3 | Karachi' },
                    { id: 'n2', label: '+92 300 8291042', type: 'phone', risk: 'critical', details: 'SIM Swap Indicator: HIGH | Carrier: Mobilink-Demo' },
                    { id: 'n3', label: 'PK36 FAYS 0001 2984', type: 'account', risk: 'critical', details: 'Mule IBAN | Branch: Faysal-Demo | Velocity: Extreme' },
                    { id: 'n4', label: 'DEV-PK-9812', type: 'device', risk: 'high', details: 'Android Emulator | Rooted: YES | IP: 103.255.4.12' },
                    { id: 'n5', label: '103.255.4.12', type: 'ip', risk: 'high', details: 'ISP: Cybernet-Demo | VPN Endpoint Detected' }
                ],
                graphEdges: [
                    { from: 'n1', to: 'n2', label: 'OWNS_PHONE' },
                    { from: 'n2', to: 'n3', label: 'INITIATED_TX' },
                    { from: 'n2', to: 'n4', label: 'USED_DEVICE' },
                    { from: 'n4', to: 'n5', label: 'ROUTED_IP' }
                ],
                recommendedActions: [
                    'Immediately place temporary administrative freeze on IBAN PK36 FAYS 0001 2984...',
                    'Contact telecom provider for SIM verification audit on +92 300 8291042.',
                    'Examine linked device hardware fingerprint DEV-PK-9812 across cross-bank database.',
                    'Escalate case file TG-PK-20491 to Cyber Incident Command Response Team.'
                ]
            },
            {
                id: 'TG-PK-10948',
                threatLevel: 'HIGH RISK',
                threatType: 'PHISHING',
                confidence: '91%',
                evidenceStrength: 'STRONG',
                patternMatch: '87%',
                anomalyLevel: 'ELEVATED',
                priority: 'P1 — URGENT',
                targetIdentifier: 'http://verify-bank-pk-sec.top',
                created: 'Yesterday 04:15 PM',
                status: 'UNDER REVIEW',
                radar: { identity: 70, financial: 65, device: 80, network: 95, behaviour: 85, communication: 90 },
                fingerprint: {
                    title: 'Bank Portal Typosquatting & SMS Phishing',
                    match: '87%',
                    tags: ['Suspicious Domain', 'SMS Broadcast Harvester', 'Brand Impersonation']
                },
                whyFlagged: [
                    { title: 'Brand Typosquatting Domain', severity: 'HIGH', evidence: 'Domain verify-bank-pk-sec.top registered 48h ago.', explanation: 'Emulates official banking URL structure.' }
                ],
                timeline: [
                    { time: '04:15 PM', title: 'Phishing URL Submitted', desc: 'Automated crawler flagged domain entropy.', threat: 'warn' }
                ],
                graphNodes: [
                    { id: 'n1', label: 'verify-bank-pk-sec.top', type: 'phone', risk: 'high', details: 'Domain Registrant: Anonymous | Host: PK-Cloud' }
                ],
                graphEdges: [],
                recommendedActions: ['Initiate synthetic domain takedown request.', 'Broadcast warning bulletin in security feed.']
            },
            {
                id: 'TG-PK-49201',
                threatLevel: 'SUSPICIOUS',
                threatType: 'MARKETPLACE SCAM',
                confidence: '84%',
                evidenceStrength: 'MEDIUM',
                patternMatch: '76%',
                anomalyLevel: 'ELEVATED',
                priority: 'P2 — INVESTIGATE',
                targetIdentifier: '+92 333 9182049',
                created: '2 days ago',
                status: 'OPEN',
                radar: { identity: 60, financial: 75, device: 50, network: 40, behaviour: 80, communication: 70 },
                fingerprint: {
                    title: 'Advance Fee E-Commerce Scam',
                    match: '76%',
                    tags: ['Non-Delivery Complaint', 'Multiple Wallet Transfers']
                },
                whyFlagged: [
                    { title: 'Repeated Buyer Complaints', severity: 'MEDIUM', evidence: '4 independent reports received for same seller phone.', explanation: 'Pattern of taking deposit and cutting communication.' }
                ],
                timeline: [
                    { time: '10:00 AM', title: 'Complaint Intake', desc: 'Buyer reported unfulfilled electronics delivery.', threat: 'warn' }
                ],
                graphNodes: [
                    { id: 'n1', label: '+92 333 9182049', type: 'phone', risk: 'suspicious', details: 'Mobile Wallet Account active' }
                ],
                graphEdges: [],
                recommendedActions: ['Flag mobile wallet for compliance review.', 'Notify reporting victims.']
            },
            {
                id: 'TG-PK-38192',
                threatLevel: 'GUARDED',
                threatType: 'INVESTMENT SCAM',
                confidence: '78%',
                evidenceStrength: 'MODERATE',
                patternMatch: '68%',
                anomalyLevel: 'MODERATE',
                priority: 'P3 — MONITOR',
                targetIdentifier: 'crypto-pk-earnings.xyz',
                created: '3 days ago',
                status: 'UNDER REVIEW',
                radar: { identity: 40, financial: 60, device: 30, network: 70, behaviour: 65, communication: 55 },
                fingerprint: {
                    title: 'High Yield Crypto Ponzi Simulation',
                    match: '68%',
                    tags: ['Unregistered Crypto Portal', 'Telegram Channel Link']
                },
                whyFlagged: [
                    { title: 'Guaranteed Return Claims', severity: 'MEDIUM', evidence: 'Guarantees 200% return in 7 days.', explanation: 'Classic Ponzi scheme text markers.' }
                ],
                timeline: [
                    { time: '02:00 PM', title: 'Social Media Alert', desc: 'Telegram link submitted by analyst.', threat: 'warn' }
                ],
                graphNodes: [
                    { id: 'n1', label: 'crypto-pk-earnings.xyz', type: 'phone', risk: 'guarded', details: 'Unregistered financial service' }
                ],
                graphEdges: [],
                recommendedActions: ['Monitor wallet addresses.', 'Add domain to guarded threat index.']
            },
            {
                id: 'TG-PK-74921',
                threatLevel: 'CRITICAL THREAT',
                threatType: 'COORDINATED FRAUD PATTERN',
                confidence: '98%',
                evidenceStrength: 'STRONG',
                patternMatch: '97%',
                anomalyLevel: 'SEVERE',
                priority: 'P0 — IMMEDIATE',
                targetIdentifier: 'PK09 HABB 0092 1049 8291 02',
                created: '4 days ago',
                status: 'ESCALATED',
                radar: { identity: 95, financial: 98, device: 90, network: 88, behaviour: 96, communication: 82 },
                fingerprint: {
                    title: 'Multi-Bank Syndicate Cash-Out Network',
                    match: '97%',
                    tags: ['Cross-Bank Mule Ring', 'Automated ATM Cash-Out', 'Device Swarm']
                },
                whyFlagged: [
                    { title: 'Syndicate Layering Sequence', severity: 'CRITICAL', evidence: 'Rs. 12,000,000 funneled through 14 interconnected accounts.', explanation: 'Multi-node velocity layering detected.' }
                ],
                timeline: [
                    { time: '11:00 AM', title: 'Syndicate Trigger', desc: '14 account nodes illuminated simultaneously.', threat: 'danger' }
                ],
                graphNodes: [
                    { id: 'n1', label: 'Syndicate Hub Account', type: 'account', risk: 'critical', details: 'IBAN PK09 HABB... | Total Volume: 12M PKR' }
                ],
                graphEdges: [],
                recommendedActions: ['Coordinate multi-bank emergency hold.', 'Transmit report to central fraud command.']
            }
        ]
    },

    uk: {
        code: 'UK',
        countryName: 'United Kingdom',
        flag: '🇬🇧',
        currency: 'GBP',
        currencySymbol: '£',
        identityLabel: 'National Insurance (NI) Number',
        identityExample: 'QQ 12 34 56 A',
        phoneFormat: '+44 7XXX XXXXXX',
        phoneExample: '+44 7700 900142',
        accountLabel: 'Sort Code & Account Number',
        accountExample: '20-45-11 / 83920194',
        authorityName: 'UK Fraud & Cyber Directorate (Demo Simulation)',
        casePrefix: 'TG-UK-',
        searchPlaceholder: 'Search UK Phone (+44...), NI Number, Sort Code, account, email, case ID...',
        sampleScannerValues: [
            { label: 'Suspicious UK Phone', type: 'phone', value: '+44 7700 900142' },
            { label: 'Synthetic NI Record', type: 'identity', value: 'QQ 12 34 56 A' },
            { label: 'Sort Code & Account', type: 'account', value: '20-45-11 / 83920194' },
            { label: 'HMRC Phishing Link', type: 'url', value: 'http://hmrc-tax-rebate-uk.top/claim' }
        ],
        stats: { threatLevel: 'CRITICAL', activeCases: 5, suspiciousEntities: 19, reportsToday: 24 },
        demoCases: [
            {
                id: 'TG-UK-58210',
                threatLevel: 'CRITICAL THREAT',
                threatType: 'ACCOUNT TAKEOVER',
                confidence: '95%',
                evidenceStrength: 'STRONG',
                patternMatch: '92%',
                anomalyLevel: 'SEVERE',
                priority: 'P0 — IMMEDIATE',
                targetIdentifier: '+44 7700 900142',
                created: 'Today 09:12 AM',
                status: 'OPEN',
                radar: { identity: 90, financial: 94, device: 86, network: 80, behaviour: 92, communication: 70 },
                fingerprint: {
                    title: 'Authorised Push Payment (APP) Fraud & SIM Swap',
                    match: '92%',
                    tags: ['HMRC Impersonation', 'Rapid Sort-Code Layering', 'New Device Hardware', 'Vulnerable Target Signal']
                },
                whyFlagged: [
                    { title: 'Rapid Outbound Faster Payments', severity: 'CRITICAL', evidence: '£48,000 transferred via Faster Payments in 3 bursts.', explanation: 'Drastic shift from historical spending behavior.' },
                    { title: 'Untrusted IP Location', severity: 'HIGH', evidence: 'Login IP 82.165.19.41 located in offshore data center.', explanation: 'VPN endpoint obfuscating location.' }
                ],
                timeline: [
                    { time: '09:12 AM', title: 'Suspicious Device Login', desc: 'Login from London IP 82.165.19.41 using Firefox Linux.', threat: 'danger' },
                    { time: '09:15 AM', title: 'High-Value APP Transfer', desc: '£20,000 sent to Sort Code 20-45-11.', threat: 'danger' }
                ],
                graphNodes: [
                    { id: 'n1', label: 'Lord Sterling (Victim)', type: 'person', risk: 'low', details: 'NI: QQ 12 34 56 A | Postcode: W1D 3BF' },
                    { id: 'n2', label: '+44 7700 900142', type: 'phone', risk: 'critical', details: 'Carrier: O2-Demo | SIM Swap FlagGED' },
                    { id: 'n3', label: '20-45-11 / 83920194', type: 'account', risk: 'critical', details: 'Barclays-Demo Mule Account' }
                ],
                graphEdges: [
                    { from: 'n1', to: 'n2', label: 'HOLDER' },
                    { from: 'n2', to: 'n3', label: 'TRANSFERRED' }
                ],
                recommendedActions: ['Issue UK Faster Payments emergency recall.', 'Notify bank fraud desk for account freezing.']
            },
            {
                id: 'TG-UK-82914',
                threatLevel: 'HIGH RISK',
                threatType: 'PHISHING',
                confidence: '90%',
                evidenceStrength: 'STRONG',
                patternMatch: '88%',
                anomalyLevel: 'ELEVATED',
                priority: 'P1 — URGENT',
                targetIdentifier: 'http://hmrc-tax-rebate-uk.top',
                created: 'Yesterday 02:20 PM',
                status: 'UNDER REVIEW',
                radar: { identity: 75, financial: 70, device: 85, network: 90, behaviour: 80, communication: 95 },
                fingerprint: { title: 'HMRC Tax Refund Impersonation', match: '88%', tags: ['Government Impersonation', 'Credential Harvesting'] },
                whyFlagged: [{ title: 'HMRC Brand Misuse', severity: 'HIGH', evidence: 'Phishing page harvesting NI numbers & passwords.', explanation: 'Fake government gateway.' }],
                timeline: [{ time: '02:20 PM', title: 'URL Ingestion', desc: 'Reported by UK citizen via intake portal.', threat: 'warn' }],
                graphNodes: [{ id: 'n1', label: 'hmrc-tax-rebate-uk.top', type: 'phone', risk: 'high', details: 'Active Phishing Site' }],
                graphEdges: [],
                recommendedActions: ['Submit URL to NCSC UK reporting channel.']
            },
            {
                id: 'TG-UK-10492',
                threatLevel: 'SUSPICIOUS',
                threatType: 'MARKETPLACE SCAM',
                confidence: '82%',
                evidenceStrength: 'MEDIUM',
                patternMatch: '74%',
                anomalyLevel: 'ELEVATED',
                priority: 'P2 — INVESTIGATE',
                targetIdentifier: '+44 7911 123456',
                created: '2 days ago',
                status: 'OPEN',
                radar: { identity: 50, financial: 70, device: 60, network: 50, behaviour: 75, communication: 65 },
                fingerprint: { title: 'Concert Ticket Advance Scam', match: '74%', tags: ['Social Media Listing', 'Bank Transfer Request'] },
                whyFlagged: [{ title: 'Multiple Ticket Scams Reported', severity: 'MEDIUM', evidence: '3 complaints regarding non-existent festival tickets.', explanation: 'Consistent seller ghosting pattern.' }],
                timeline: [{ time: '01:00 PM', title: 'Case Created', desc: 'Synthetic report intake compiled.', threat: 'warn' }],
                graphNodes: [{ id: 'n1', label: '+44 7911 123456', type: 'phone', risk: 'suspicious', details: 'Prepaid SIM' }],
                graphEdges: [],
                recommendedActions: ['Flag bank account linked to seller for review.']
            },
            {
                id: 'TG-UK-67392',
                threatLevel: 'GUARDED',
                threatType: 'INVESTMENT SCAM',
                confidence: '76%',
                evidenceStrength: 'MODERATE',
                patternMatch: '65%',
                anomalyLevel: 'MODERATE',
                priority: 'P3 — MONITOR',
                targetIdentifier: 'uk-crypto-wealth.co.uk',
                created: '3 days ago',
                status: 'UNDER REVIEW',
                radar: { identity: 40, financial: 55, device: 45, network: 75, behaviour: 60, communication: 50 },
                fingerprint: { title: 'Unregulated Forex Trading Portal', match: '65%', tags: ['FCA Warning Missing', 'High Pressure Calls'] },
                whyFlagged: [{ title: 'Unregistered Brokerage', severity: 'MEDIUM', evidence: 'No FCA registration number found.', explanation: 'Operating financial services without authorization.' }],
                timeline: [{ time: '11:30 AM', title: 'FCA Registry Lookup', desc: 'No matching regulatory record.', threat: 'warn' }],
                graphNodes: [{ id: 'n1', label: 'uk-crypto-wealth.co.uk', type: 'phone', risk: 'guarded', details: 'Offshore host' }],
                graphEdges: [],
                recommendedActions: ['Cross-reference against FCA warning list.']
            },
            {
                id: 'TG-UK-48201',
                threatLevel: 'CRITICAL THREAT',
                threatType: 'COORDINATED FRAUD PATTERN',
                confidence: '97%',
                evidenceStrength: 'STRONG',
                patternMatch: '95%',
                anomalyLevel: 'SEVERE',
                priority: 'P0 — IMMEDIATE',
                targetIdentifier: '40-02-18 / 91028401',
                created: '5 days ago',
                status: 'ESCALATED',
                radar: { identity: 92, financial: 97, device: 88, network: 90, behaviour: 94, communication: 80 },
                fingerprint: { title: 'London Financial Mule Network', match: '95%', tags: ['Multi-Account Layering', 'Crypto Exchange Cashout'] },
                whyFlagged: [{ title: 'Mass Mule Pooling', severity: 'CRITICAL', evidence: '£350,000 routed across 9 UK sort codes.', explanation: 'Layering ring detected.' }],
                timeline: [{ time: '09:00 AM', title: 'Ring Detection', desc: 'Graph engine linked 9 bank nodes.', threat: 'danger' }],
                graphNodes: [{ id: 'n1', label: 'Hub Mule 40-02-18', type: 'account', risk: 'critical', details: 'HSBC-Demo Mule Account' }],
                graphEdges: [],
                recommendedActions: ['Alert UK National Economic Crime Centre (NECC).']
            }
        ]
    },

    usa: {
        code: 'US',
        countryName: 'United States',
        flag: '🇺🇸',
        currency: 'USD',
        currencySymbol: '$',
        identityLabel: 'Social Security Number (SSN)',
        identityExample: 'XXX-XX-6719',
        phoneFormat: '+1 (555) XXX-XXXX',
        phoneExample: '+1 (555) 019-2834',
        accountLabel: 'Routing Number & Account',
        accountExample: '021000021 / 94820193',
        authorityName: 'US Financial Threat Intelligence (Demo Simulation)',
        casePrefix: 'TG-US-',
        searchPlaceholder: 'Search US Phone (+1...), SSN, Routing #, email, case ID...',
        sampleScannerValues: [
            { label: 'Suspicious US Phone', type: 'phone', value: '+1 (555) 019-2834' },
            { label: 'Synthetic SSN Record', type: 'identity', value: 'XXX-XX-6719' },
            { label: 'Routing & Account', type: 'account', value: '021000021 / 94820193' },
            { label: 'IRS Phishing Portal', type: 'url', value: 'http://irs-tax-refund-portal.info/claim' }
        ],
        stats: { threatLevel: 'CRITICAL', activeCases: 5, suspiciousEntities: 31, reportsToday: 42 },
        demoCases: [
            {
                id: 'TG-US-73192',
                threatLevel: 'CRITICAL THREAT',
                threatType: 'ACCOUNT TAKEOVER',
                confidence: '97%',
                evidenceStrength: 'STRONG',
                patternMatch: '95%',
                anomalyLevel: 'SEVERE',
                priority: 'P0 — IMMEDIATE',
                targetIdentifier: '+1 (555) 019-2834',
                created: 'Today 07:30 AM',
                status: 'OPEN',
                radar: { identity: 94, financial: 98, device: 90, network: 82, behaviour: 94, communication: 75 },
                fingerprint: {
                    title: 'Synthetic Identity Theft & Wire Transfer Fraud',
                    match: '95%',
                    tags: ['SSN Manipulation', 'Fast ACH Wire Out', 'Device Emulator', 'VPN Tunneling']
                },
                whyFlagged: [
                    { title: 'Immediate ACH Wire Outbound', severity: 'CRITICAL', evidence: '$125,000 ACH wire initiated to offshore account.', explanation: 'Unusual velocity for this consumer profile.' },
                    { title: 'SSN Verification Inconsistency', severity: 'HIGH', evidence: 'SSN XXX-XX-6719 matched to multiple synthetic addresses.', explanation: 'Identity fragmentation detected.' }
                ],
                timeline: [
                    { time: '07:30 AM', title: 'Login from New State', desc: 'IP 64.233.160.1 located in Miami data center.', threat: 'danger' },
                    { time: '07:35 AM', title: 'Wire Transfer Approved', desc: '$125,000 sent via Fedwire.', threat: 'danger' }
                ],
                graphNodes: [
                    { id: 'n1', label: 'John Doe (Synthetic Profile)', type: 'person', risk: 'high', details: 'SSN: XXX-XX-6719 | NY' },
                    { id: 'n2', label: '+1 (555) 019-2834', type: 'phone', risk: 'critical', details: 'VOIP Number | Provider: Twilio-Demo' },
                    { id: 'n3', label: '021000021 / 94820193', type: 'account', risk: 'critical', details: 'Chase-Demo Account | High Velocity' }
                ],
                graphEdges: [
                    { from: 'n1', to: 'n2', label: 'LINKED' },
                    { from: 'n2', to: 'n3', label: 'WIRED' }
                ],
                recommendedActions: ['Request immediate Fedwire recall.', 'Transmit IC3 synthetic incident report.']
            },
            {
                id: 'TG-US-91823',
                threatLevel: 'HIGH RISK',
                threatType: 'PHISHING',
                confidence: '92%',
                evidenceStrength: 'STRONG',
                patternMatch: '89%',
                anomalyLevel: 'ELEVATED',
                priority: 'P1 — URGENT',
                targetIdentifier: 'http://irs-tax-refund-portal.info',
                created: 'Yesterday 01:10 PM',
                status: 'UNDER REVIEW',
                radar: { identity: 80, financial: 75, device: 88, network: 92, behaviour: 82, communication: 94 },
                fingerprint: { title: 'IRS Impersonation Portal', match: '89%', tags: ['Tax Refund Phish', 'SSN Harvester'] },
                whyFlagged: [{ title: 'IRS Seal Misuse', severity: 'HIGH', evidence: 'Harvesting SSN, W2 forms, and bank logins.', explanation: 'Federal authority impersonation.' }],
                timeline: [{ time: '01:10 PM', title: 'Phishing Feed Detection', desc: 'Automated threat scanner flagged domain.', threat: 'warn' }],
                graphNodes: [{ id: 'n1', label: 'irs-tax-refund-portal.info', type: 'phone', risk: 'high', details: 'Suspicious Domain' }],
                graphEdges: [],
                recommendedActions: ['Notify US Cyber Threat Task Force.']
            },
            {
                id: 'TG-US-48291',
                threatLevel: 'SUSPICIOUS',
                threatType: 'PAYMENT FRAUD',
                confidence: '83%',
                evidenceStrength: 'MEDIUM',
                patternMatch: '75%',
                anomalyLevel: 'ELEVATED',
                priority: 'P2 — INVESTIGATE',
                targetIdentifier: '$scam-tag-user',
                created: '2 days ago',
                status: 'OPEN',
                radar: { identity: 55, financial: 78, device: 60, network: 50, behaviour: 80, communication: 65 },
                fingerprint: { title: 'P2P App Payment Fraud', match: '75%', tags: ['Fake Zelle Transfer', 'Seller Impersonation'] },
                whyFlagged: [{ title: 'Zelle Payment Reversal Scam', severity: 'MEDIUM', evidence: 'Fake payment confirmation screenshot sent to victim.', explanation: 'Social engineering payment manipulation.' }],
                timeline: [{ time: '10:15 AM', title: 'Victim Report Filed', desc: '$1,200 loss reported.', threat: 'warn' }],
                graphNodes: [{ id: 'n1', label: '$scam-tag-user', type: 'phone', risk: 'suspicious', details: 'P2P Wallet Handle' }],
                graphEdges: [],
                recommendedActions: ['Flag P2P handle for security hold.']
            },
            {
                id: 'TG-US-62910',
                threatLevel: 'GUARDED',
                threatType: 'MARKETPLACE SCAM',
                confidence: '75%',
                evidenceStrength: 'MODERATE',
                patternMatch: '64%',
                anomalyLevel: 'MODERATE',
                priority: 'P3 — MONITOR',
                targetIdentifier: '+1 (555) 382-9102',
                created: '4 days ago',
                status: 'UNDER REVIEW',
                radar: { identity: 45, financial: 60, device: 40, network: 55, behaviour: 65, communication: 55 },
                fingerprint: { title: 'Rental Housing Scam', match: '64%', tags: ['Fake Property Deposit', 'Wire Request'] },
                whyFlagged: [{ title: 'Duplicate Craigslist Listing', severity: 'MEDIUM', evidence: 'Listing images stolen from Zillow.', explanation: 'Uncontrolled advance deposit request.' }],
                timeline: [{ time: '03:00 PM', title: 'Listing Audit', desc: 'Identified image collision.', threat: 'warn' }],
                graphNodes: [{ id: 'n1', label: '+1 (555) 382-9102', type: 'phone', risk: 'guarded', details: 'burner phone' }],
                graphEdges: [],
                recommendedActions: ['Issue warning on local housing board.']
            },
            {
                id: 'TG-US-31049',
                threatLevel: 'CRITICAL THREAT',
                threatType: 'COORDINATED FRAUD PATTERN',
                confidence: '98%',
                evidenceStrength: 'STRONG',
                patternMatch: '96%',
                anomalyLevel: 'SEVERE',
                priority: 'P0 — IMMEDIATE',
                targetIdentifier: '121000358 / 881920491',
                created: '6 days ago',
                status: 'ESCALATED',
                radar: { identity: 96, financial: 99, device: 92, network: 90, behaviour: 96, communication: 85 },
                fingerprint: { title: 'Cross-State Crypto Cashout Ring', match: '96%', tags: ['Multi-State ACH Funnel', 'Crypto Exchange Cashout'] },
                whyFlagged: [{ title: 'Multi-Million Wire Ring', severity: 'CRITICAL', evidence: '$3.4M funneled through 18 bank accounts in 5 states.', explanation: 'Coordinated laundering ring.' }],
                timeline: [{ time: '08:00 AM', title: 'FinCEN Alert Simulation', desc: 'Synthetic SAR threshold exceeded.', threat: 'danger' }],
                graphNodes: [{ id: 'n1', label: 'US Hub Account', type: 'account', risk: 'critical', details: 'Wells Fargo-Demo Account' }],
                graphEdges: [],
                recommendedActions: ['File Emergency SAR Briefing.']
            }
        ]
    },

    uae: {
        code: 'AE',
        countryName: 'United Arab Emirates',
        flag: '🇦🇪',
        currency: 'AED',
        currencySymbol: 'AED',
        identityLabel: 'Emirates ID (EID)',
        identityExample: '784-1992-1849201-1',
        phoneFormat: '+971 5X XXX XXXX',
        phoneExample: '+971 50 829 1049',
        accountLabel: 'UAE IBAN Account',
        accountExample: 'AE07 0330 0000 1102 9384 101',
        authorityName: 'UAE Cyber Security Council (Demo Simulation)',
        casePrefix: 'TG-AE-',
        searchPlaceholder: 'Search UAE Phone (+971...), Emirates ID, IBAN, email, case ID...',
        sampleScannerValues: [
            { label: 'Suspicious UAE Phone', type: 'phone', value: '+971 50 829 1049' },
            { label: 'Synthetic Emirates ID', type: 'identity', value: '784-1992-1849201-1' },
            { label: 'UAE IBAN Account', type: 'account', value: 'AE07 0330 0000 1102 9384 101' },
            { label: 'Delivery Impersonation URL', type: 'url', value: 'http://emirates-post-tracking-ae.top' }
        ],
        stats: { threatLevel: 'CRITICAL', activeCases: 5, suspiciousEntities: 18, reportsToday: 15 },
        demoCases: [
            {
                id: 'TG-AE-41872',
                threatLevel: 'CRITICAL THREAT',
                threatType: 'ACCOUNT TAKEOVER',
                confidence: '96%',
                evidenceStrength: 'STRONG',
                patternMatch: '93%',
                anomalyLevel: 'SEVERE',
                priority: 'P0 — IMMEDIATE',
                targetIdentifier: '+971 50 829 1049',
                created: 'Today 10:05 AM',
                status: 'OPEN',
                radar: { identity: 92, financial: 95, device: 88, network: 80, behaviour: 90, communication: 70 },
                fingerprint: {
                    title: 'Emirates Post Delivery Scam & Banking Takeover',
                    match: '93%',
                    tags: ['Package Fee Scam', 'OTP Smishing', 'Emirates ID Theft', 'Unusual Cross-Border Transfer']
                },
                whyFlagged: [
                    { title: 'OTP Phishing Intercept', severity: 'CRITICAL', evidence: 'AED 180,000 sent via Instant Payment System after OTP input on fake delivery site.', explanation: 'Social engineering credential theft.' },
                    { title: 'New Device Authentication', severity: 'HIGH', evidence: 'Login from iPad Device #DEV-AE-7102 in Dubai Marina.', explanation: 'Unrecognized hardware.' }
                ],
                timeline: [
                    { time: '10:05 AM', title: 'Fake Delivery Link Clicked', desc: 'Victim navigated to emirates-post-tracking-ae.top.', threat: 'warn' },
                    { time: '10:08 AM', title: 'Banking OTP Captured', desc: 'SMS OTP submitted to attacker phish kit.', threat: 'danger' },
                    { time: '10:11 AM', title: 'AED 180,000 Transfer Executed', desc: 'Transferred to IBAN AE07 0330...', threat: 'danger' }
                ],
                graphNodes: [
                    { id: 'n1', label: 'Rashid Al-Maktoum (Victim)', type: 'person', risk: 'low', details: 'EID: 784-1992-1849201-1 | Dubai' },
                    { id: 'n2', label: '+971 50 829 1049', type: 'phone', risk: 'critical', details: 'Carrier: Etisalat-Demo | Compromised' },
                    { id: 'n3', label: 'AE07 0330 0000 1102', type: 'account', risk: 'critical', details: 'ENBD-Demo Account | Mule Node' }
                ],
                graphEdges: [
                    { from: 'n1', to: 'n2', label: 'REGISTERED' },
                    { from: 'n2', to: 'n3', label: 'TRANSFER' }
                ],
                recommendedActions: ['Freeze IBAN AE07 0330... across UAE Central Bank clearing.', 'Flag domain emirates-post-tracking-ae.top.']
            },
            {
                id: 'TG-AE-82910',
                threatLevel: 'HIGH RISK',
                threatType: 'PHISHING',
                confidence: '90%',
                evidenceStrength: 'STRONG',
                patternMatch: '86%',
                anomalyLevel: 'ELEVATED',
                priority: 'P1 — URGENT',
                targetIdentifier: 'http://emirates-post-tracking-ae.top',
                created: 'Yesterday 03:40 PM',
                status: 'UNDER REVIEW',
                radar: { identity: 78, financial: 70, device: 82, network: 90, behaviour: 80, communication: 92 },
                fingerprint: { title: 'Postal Fee Phishing Gate', match: '86%', tags: ['SMS Delivery Scam', 'Credit Card Harvester'] },
                whyFlagged: [{ title: 'Emirates Post Brand Misuse', severity: 'HIGH', evidence: 'Demanding 10 AED package delivery fee to steal card credentials.', explanation: 'Widespread postal phishing.' }],
                timeline: [{ time: '03:40 PM', title: 'Threat Intelligence Sweep', desc: 'Domain indexed by UAE scanner.', threat: 'warn' }],
                graphNodes: [{ id: 'n1', label: 'emirates-post-tracking-ae.top', type: 'phone', risk: 'high', details: 'Active Phish' }],
                graphEdges: [],
                recommendedActions: ['Request emergency ISP domain block in UAE.']
            },
            {
                id: 'TG-AE-19482',
                threatLevel: 'SUSPICIOUS',
                threatType: 'IMPERSONATION',
                confidence: '81%',
                evidenceStrength: 'MEDIUM',
                patternMatch: '73%',
                anomalyLevel: 'ELEVATED',
                priority: 'P2 — INVESTIGATE',
                targetIdentifier: '+971 52 910 2841',
                created: '2 days ago',
                status: 'OPEN',
                radar: { identity: 65, financial: 60, device: 50, network: 45, behaviour: 80, communication: 75 },
                fingerprint: { title: 'Police / Central Bank Impersonation', match: '73%', tags: ['WhatsApp Threat Message', 'EID Block Warning'] },
                whyFlagged: [{ title: 'Authority Threat Language', severity: 'MEDIUM', evidence: 'Caller claiming EID will be suspended unless fine paid.', explanation: 'Classic panic inducement.' }],
                timeline: [{ time: '11:00 AM', title: 'WhatsApp Audio Uploaded', desc: 'Victim submitted voice recording.', threat: 'warn' }],
                graphNodes: [{ id: 'n1', label: '+971 52 910 2841', type: 'phone', risk: 'suspicious', details: 'WhatsApp Account' }],
                graphEdges: [],
                recommendedActions: ['Submit WhatsApp number for suspension.']
            },
            {
                id: 'TG-AE-64920',
                threatLevel: 'GUARDED',
                threatType: 'INVESTMENT SCAM',
                confidence: '74%',
                evidenceStrength: 'MODERATE',
                patternMatch: '62%',
                anomalyLevel: 'MODERATE',
                priority: 'P3 — MONITOR',
                targetIdentifier: 'dubai-realestate-yields.com',
                created: '4 days ago',
                status: 'UNDER REVIEW',
                radar: { identity: 40, financial: 55, device: 35, network: 70, behaviour: 60, communication: 50 },
                fingerprint: { title: 'Unlicensed Off-Plan Property Scam', match: '62%', tags: ['RERA Verification Missing', 'Crypto Deposit'] },
                whyFlagged: [{ title: 'No RERA Registration', severity: 'MEDIUM', evidence: 'Project not listed in RERA database.', explanation: 'Unapproved real estate offering.' }],
                timeline: [{ time: '02:00 PM', title: 'Registry Query', desc: 'Zero RERA registration matches.', threat: 'warn' }],
                graphNodes: [{ id: 'n1', label: 'dubai-realestate-yields.com', type: 'phone', risk: 'guarded', details: 'Unregistered Portal' }],
                graphEdges: [],
                recommendedActions: ['Cross-check with Dubai Land Department.']
            },
            {
                id: 'TG-AE-38291',
                threatLevel: 'CRITICAL THREAT',
                threatType: 'COORDINATED FRAUD PATTERN',
                confidence: '97%',
                evidenceStrength: 'STRONG',
                patternMatch: '95%',
                anomalyLevel: 'SEVERE',
                priority: 'P0 — IMMEDIATE',
                targetIdentifier: 'AE44 0220 0000 9812 0492 102',
                created: '6 days ago',
                status: 'ESCALATED',
                radar: { identity: 94, financial: 98, device: 90, network: 88, behaviour: 95, communication: 82 },
                fingerprint: { title: 'Regional Crypto OTC Cashout Ring', match: '95%', tags: ['Cross-Border Layering', 'High Volume OTC Transfers'] },
                whyFlagged: [{ title: 'Multi-Million AED Cashout Ring', severity: 'CRITICAL', evidence: 'AED 4,500,000 moved through 8 UAE accounts.', explanation: 'Complex money laundering pattern.' }],
                timeline: [{ time: '09:30 AM', title: 'Anti-Money Laundering Alert', desc: 'Central Bank compliance indicator tripped.', threat: 'danger' }],
                graphNodes: [{ id: 'n1', label: 'UAE Hub IBAN', type: 'account', risk: 'critical', details: 'ADCB-Demo Account' }],
                graphEdges: [],
                recommendedActions: ['Submit report to UAE Financial Intelligence Unit (FIU).']
            }
        ]
    },

    canada: {
        code: 'CA',
        countryName: 'Canada',
        flag: '🇨🇦',
        currency: 'CAD',
        currencySymbol: 'CA$',
        identityLabel: 'Social Insurance Number (SIN)',
        identityExample: '982-104-921',
        phoneFormat: '+1 (416) XXX-XXXX',
        phoneExample: '+1 (416) 555-0192',
        accountLabel: 'Transit / Inst & Account Number',
        accountExample: '00040-004 / 8291049',
        authorityName: 'Canada Cyber Financial Intelligence (Demo Simulation)',
        casePrefix: 'TG-CA-',
        searchPlaceholder: 'Search CA Phone (+1...), SIN Number, Transit #, email, case ID...',
        sampleScannerValues: [
            { label: 'Suspicious CA Phone', type: 'phone', value: '+1 (416) 555-0192' },
            { label: 'Synthetic SIN Record', type: 'identity', value: '982-104-921' },
            { label: 'Transit & Account', type: 'account', value: '00040-004 / 8291049' },
            { label: 'CRA Refund Phish', type: 'url', value: 'http://cra-interac-e-transfer-claim.top' }
        ],
        stats: { threatLevel: 'CRITICAL', activeCases: 5, suspiciousEntities: 21, reportsToday: 29 },
        demoCases: [
            {
                id: 'TG-CA-61942',
                threatLevel: 'CRITICAL THREAT',
                threatType: 'ACCOUNT TAKEOVER',
                confidence: '95%',
                evidenceStrength: 'STRONG',
                patternMatch: '92%',
                anomalyLevel: 'SEVERE',
                priority: 'P0 — IMMEDIATE',
                targetIdentifier: '+1 (416) 555-0192',
                created: 'Today 08:15 AM',
                status: 'OPEN',
                radar: { identity: 90, financial: 96, device: 86, network: 78, behaviour: 90, communication: 72 },
                fingerprint: {
                    title: 'Interac e-Transfer Interception & Banking ATO',
                    match: '92%',
                    tags: ['CRA Tax Phishing', 'Interac Auto-Deposit Hijack', 'SIM Swap', 'Device Switch']
                },
                whyFlagged: [
                    { title: 'Interac e-Transfer Hijack', severity: 'CRITICAL', evidence: 'CA$ 35,000 funneled via Interac auto-deposit redirect.', explanation: 'Instant clearance exploitation.' },
                    { title: 'SIN Verification Discrepancy', severity: 'HIGH', evidence: 'SIN 982-104-921 flagged for multiple credit queries in 24h.', explanation: 'Identity theft signal.' }
                ],
                timeline: [
                    { time: '08:15 AM', title: 'CRA Phishing SMS Opened', desc: 'Victim clicked fake Interac link.', threat: 'warn' },
                    { time: '08:18 AM', title: 'Interac Deposit Intercepted', desc: 'CA$ 15,000 redirected to mule account.', threat: 'danger' }
                ],
                graphNodes: [
                    { id: 'n1', label: 'Jean Tremblay (Victim)', type: 'person', risk: 'low', details: 'SIN: 982-104-921 | Montreal' },
                    { id: 'n2', label: '+1 (416) 555-0192', type: 'phone', risk: 'critical', details: 'SIM Swap Flagged | Telus-Demo' },
                    { id: 'n3', label: '00040-004 / 8291049', type: 'account', risk: 'critical', details: 'RBC-Demo Mule Account' }
                ],
                graphEdges: [
                    { from: 'n1', to: 'n2', label: 'OWNER' },
                    { from: 'n2', to: 'n3', label: 'TRANSFERRED' }
                ],
                recommendedActions: ['Place Interac fraud recall request.', 'Notify Canadian Anti-Fraud Centre (CAFC).']
            },
            {
                id: 'TG-CA-10492',
                threatLevel: 'HIGH RISK',
                threatType: 'PHISHING',
                confidence: '91%',
                evidenceStrength: 'STRONG',
                patternMatch: '87%',
                anomalyLevel: 'ELEVATED',
                priority: 'P1 — URGENT',
                targetIdentifier: 'http://cra-interac-e-transfer-claim.top',
                created: 'Yesterday 04:00 PM',
                status: 'UNDER REVIEW',
                radar: { identity: 76, financial: 72, device: 84, network: 88, behaviour: 82, communication: 93 },
                fingerprint: { title: 'CRA Tax Refund Phishing', match: '87%', tags: ['Government Impersonation', 'Interac Brand Misuse'] },
                whyFlagged: [{ title: 'Fake Canada Revenue Agency Gateway', severity: 'HIGH', evidence: 'Demanding SIN number and banking login to claim refund.', explanation: 'Credential harvesting portal.' }],
                timeline: [{ time: '04:00 PM', title: 'Crawler Ingestion', desc: 'Identified CRA logos on non-gov domain.', threat: 'warn' }],
                graphNodes: [{ id: 'n1', label: 'cra-interac-e-transfer-claim.top', type: 'phone', risk: 'high', details: 'Phish Domain' }],
                graphEdges: [],
                recommendedActions: ['Issue Takedown Notice to Canadian domain registrar.']
            },
            {
                id: 'TG-CA-83920',
                threatLevel: 'SUSPICIOUS',
                threatType: 'MARKETPLACE SCAM',
                confidence: '80%',
                evidenceStrength: 'MEDIUM',
                patternMatch: '72%',
                anomalyLevel: 'ELEVATED',
                priority: 'P2 — INVESTIGATE',
                targetIdentifier: '+1 (604) 918-2049',
                created: '3 days ago',
                status: 'OPEN',
                radar: { identity: 50, financial: 65, device: 55, network: 45, behaviour: 75, communication: 65 },
                fingerprint: { title: 'Kijiji Vehicle Advance Deposit Fraud', match: '72%', tags: ['Fake Car Listing', 'Interac Transfer Request'] },
                whyFlagged: [{ title: 'Multiple Deposit Complaints', severity: 'MEDIUM', evidence: 'Seller demanding CA$ 2,000 deposit before viewing.', explanation: 'Classic non-existent item scam.' }],
                timeline: [{ time: '09:00 AM', title: 'Complaint Intake', desc: 'Buyer reported loss on Kijiji listing.', threat: 'warn' }],
                graphNodes: [{ id: 'n1', label: '+1 (604) 918-2049', type: 'phone', risk: 'suspicious', details: 'Prepaid SIM' }],
                graphEdges: [],
                recommendedActions: ['Flag phone on Canadian fraud registry.']
            },
            {
                id: 'TG-CA-49201',
                threatLevel: 'GUARDED',
                threatType: 'INVESTMENT SCAM',
                confidence: '75%',
                evidenceStrength: 'MODERATE',
                patternMatch: '63%',
                anomalyLevel: 'MODERATE',
                priority: 'P3 — MONITOR',
                targetIdentifier: 'canada-wealth-investors.ca',
                created: '4 days ago',
                status: 'UNDER REVIEW',
                radar: { identity: 40, financial: 55, device: 40, network: 70, behaviour: 60, communication: 50 },
                fingerprint: { title: 'Unregistered Crypto Advisory', match: '63%', tags: ['OSC Regulatory Missing', 'High Yield Guarantee'] },
                whyFlagged: [{ title: 'Ontario Securities Commission Warning', severity: 'MEDIUM', evidence: 'Not registered with OSC or IIROC.', explanation: 'Unlicensed investment solicitation.' }],
                timeline: [{ time: '01:00 PM', title: 'OSC Database Check', desc: 'No active license found.', threat: 'warn' }],
                graphNodes: [{ id: 'n1', label: 'canada-wealth-investors.ca', type: 'phone', risk: 'guarded', details: 'Offshore host' }],
                graphEdges: [],
                recommendedActions: ['Cross-reference against OSC Investor Warning List.']
            },
            {
                id: 'TG-CA-71029',
                threatLevel: 'CRITICAL THREAT',
                threatType: 'COORDINATED FRAUD PATTERN',
                confidence: '96%',
                evidenceStrength: 'STRONG',
                patternMatch: '94%',
                anomalyLevel: 'SEVERE',
                priority: 'P0 — IMMEDIATE',
                targetIdentifier: '00003-010 / 91820491',
                created: '6 days ago',
                status: 'ESCALATED',
                radar: { identity: 93, financial: 97, device: 88, network: 86, behaviour: 94, communication: 80 },
                fingerprint: { title: 'Cross-Provincial Money Laundering Network', match: '94%', tags: ['Interac Layering Ring', 'ATM Cash-Out Velocity'] },
                whyFlagged: [{ title: 'Multi-Bank Interac Funnel', severity: 'CRITICAL', evidence: 'CA$ 1,800,000 funneled through 11 accounts in ON & QC.', explanation: 'Layering ring detected.' }],
                timeline: [{ time: '10:00 AM', title: 'FINTRAC Indicator Alert', desc: 'Large transaction reporting threshold exceeded.', threat: 'danger' }],
                graphNodes: [{ id: 'n1', label: 'CA Hub Account', type: 'account', risk: 'critical', details: 'TD-Demo Account' }],
                graphEdges: [],
                recommendedActions: ['Prepare FINTRAC voluntary disclosure report.']
            }
        ]
    },

    australia: {
        code: 'AU',
        countryName: 'Australia',
        flag: '🇦🇺',
        currency: 'AUD',
        currencySymbol: 'A$',
        identityLabel: 'Tax File Number (TFN)',
        identityExample: '982 104 921',
        phoneFormat: '+61 4XX XXX XXX',
        phoneExample: '+61 412 890 149',
        accountLabel: 'BSB & Account Number',
        accountExample: '062-000 / 10928491',
        authorityName: 'Australian Fraud Intelligence Unit (Demo Simulation)',
        casePrefix: 'TG-AU-',
        searchPlaceholder: 'Search AU Phone (+61...), TFN, BSB #, email, case ID...',
        sampleScannerValues: [
            { label: 'Suspicious AU Phone', type: 'phone', value: '+61 412 890 149' },
            { label: 'Synthetic TFN Record', type: 'identity', value: '982 104 921' },
            { label: 'BSB & Account', type: 'account', value: '062-000 / 10928491' },
            { label: 'myGov Phishing Portal', type: 'url', value: 'http://mygov-tax-refund-au.top' }
        ],
        stats: { threatLevel: 'CRITICAL', activeCases: 5, suspiciousEntities: 22, reportsToday: 31 },
        demoCases: [
            {
                id: 'TG-AU-39081',
                threatLevel: 'CRITICAL THREAT',
                threatType: 'ACCOUNT TAKEOVER',
                confidence: '96%',
                evidenceStrength: 'STRONG',
                patternMatch: '93%',
                anomalyLevel: 'SEVERE',
                priority: 'P0 — IMMEDIATE',
                targetIdentifier: '+61 412 890 149',
                created: 'Today 09:40 AM',
                status: 'OPEN',
                radar: { identity: 91, financial: 95, device: 87, network: 79, behaviour: 91, communication: 73 },
                fingerprint: {
                    title: 'myGov Impersonation & PayID Account Hijack',
                    match: '93%',
                    tags: ['ATO Tax Phishing', 'PayID Redirection', 'SIM Swap', 'Device Switch']
                },
                whyFlagged: [
                    { title: 'PayID Instant Payment Burst', severity: 'CRITICAL', evidence: 'A$ 55,000 sent via PayID to 3 newly linked accounts within 10 minutes.', explanation: 'Unusual velocity for this consumer profile.' },
                    { title: 'TFN Identity Fragmentation', severity: 'HIGH', evidence: 'TFN 982 104 921 linked to multiple credit file checks in Sydney & Melbourne.', explanation: 'Synthetic profile exploitation.' }
                ],
                timeline: [
                    { time: '09:40 AM', title: 'myGov Phishing Link Accessed', desc: 'Victim opened fake myGov portal.', threat: 'warn' },
                    { time: '09:43 AM', title: 'PayID Transfer Initiated', desc: 'A$ 25,000 transferred to BSB 062-000.', threat: 'danger' }
                ],
                graphNodes: [
                    { id: 'n1', label: 'Liam Wilson (Victim)', type: 'person', risk: 'low', details: 'TFN: 982 104 921 | Sydney' },
                    { id: 'n2', label: '+61 412 890 149', type: 'phone', risk: 'critical', details: 'Telstra-Demo SIM | SIM Swap Flagged' },
                    { id: 'n3', label: '062-000 / 10928491', type: 'account', risk: 'critical', details: 'CBA-Demo Mule Account' }
                ],
                graphEdges: [
                    { from: 'n1', to: 'n2', label: 'OWNER' },
                    { from: 'n2', to: 'n3', label: 'TRANSFERRED' }
                ],
                recommendedActions: ['Trigger emergency PayID payment hold.', 'Report to National Anti-Scam Centre (NASC).']
            },
            {
                id: 'TG-AU-82910',
                threatLevel: 'HIGH RISK',
                threatType: 'PHISHING',
                confidence: '90%',
                evidenceStrength: 'STRONG',
                patternMatch: '86%',
                anomalyLevel: 'ELEVATED',
                priority: 'P1 — URGENT',
                targetIdentifier: 'http://mygov-tax-refund-au.top',
                created: 'Yesterday 02:50 PM',
                status: 'UNDER REVIEW',
                radar: { identity: 77, financial: 71, device: 83, network: 89, behaviour: 81, communication: 94 },
                fingerprint: { title: 'myGov ATO Refund Phishing', match: '86%', tags: ['Government Brand Misuse', 'TFN Harvester'] },
                whyFlagged: [{ title: 'myGov Brand Misuse', severity: 'HIGH', evidence: 'Harvesting myGov passwords, TFN, and banking details.', explanation: 'Credential harvesting portal.' }],
                timeline: [{ time: '02:50 PM', title: 'NASC Feed Match', desc: 'Indexed in Australian threat feed.', threat: 'warn' }],
                graphNodes: [{ id: 'n1', label: 'myGov-tax-refund-au.top', type: 'phone', risk: 'high', details: 'Active Phish Site' }],
                graphEdges: [],
                recommendedActions: ['Notify Australian Cyber Security Centre (ACSC).']
            },
            {
                id: 'TG-AU-10492',
                threatLevel: 'SUSPICIOUS',
                threatType: 'MARKETPLACE SCAM',
                confidence: '81%',
                evidenceStrength: 'MEDIUM',
                patternMatch: '73%',
                anomalyLevel: 'ELEVATED',
                priority: 'P2 — INVESTIGATE',
                targetIdentifier: '+61 400 123 456',
                created: '3 days ago',
                status: 'OPEN',
                radar: { identity: 52, financial: 67, device: 57, network: 47, behaviour: 76, communication: 67 },
                fingerprint: { title: 'Gumtree Puppy Purchase Fraud', match: '73%', tags: ['Fake Deposit Request', 'PayID Transfer'] },
                whyFlagged: [{ title: 'Non-Delivery Puppy Scam', severity: 'MEDIUM', evidence: 'Buyer deposited A$ 1,500 for non-existent pet.', explanation: 'Advance deposit scam.' }],
                timeline: [{ time: '11:20 AM', title: 'Victim Intake', desc: 'Complaint received via report tool.', threat: 'warn' }],
                graphNodes: [{ id: 'n1', label: '+61 400 123 456', type: 'phone', risk: 'suspicious', details: 'Prepaid SIM' }],
                graphEdges: [],
                recommendedActions: ['Flag PayID phone identifier.']
            },
            {
                id: 'TG-AU-74920',
                threatLevel: 'GUARDED',
                threatType: 'INVESTMENT SCAM',
                confidence: '74%',
                evidenceStrength: 'MODERATE',
                patternMatch: '64%',
                anomalyLevel: 'MODERATE',
                priority: 'P3 — MONITOR',
                targetIdentifier: 'aus-crypto-returns.com.au',
                created: '4 days ago',
                status: 'UNDER REVIEW',
                radar: { identity: 42, financial: 57, device: 42, network: 72, behaviour: 62, communication: 52 },
                fingerprint: { title: 'Unregulated Wealth Advisor', match: '64%', tags: ['ASIC AFSL Missing', 'High Yield Claim'] },
                whyFlagged: [{ title: 'No ASIC AFSL License', severity: 'MEDIUM', evidence: 'No Australian Financial Services License listed.', explanation: 'Unlicensed financial advice.' }],
                timeline: [{ time: '03:10 PM', title: 'ASIC Search', desc: 'No AFSL record found.', threat: 'warn' }],
                graphNodes: [{ id: 'n1', label: 'aus-crypto-returns.com.au', type: 'phone', risk: 'guarded', details: 'Unlicensed portal' }],
                graphEdges: [],
                recommendedActions: ['Check against ASIC scam alert register.']
            },
            {
                id: 'TG-AU-58291',
                threatLevel: 'CRITICAL THREAT',
                threatType: 'COORDINATED FRAUD PATTERN',
                confidence: '97%',
                evidenceStrength: 'STRONG',
                patternMatch: '95%',
                anomalyLevel: 'SEVERE',
                priority: 'P0 — IMMEDIATE',
                targetIdentifier: '082-001 / 88102941',
                created: '7 days ago',
                status: 'ESCALATED',
                radar: { identity: 94, financial: 98, device: 89, network: 87, behaviour: 95, communication: 81 },
                fingerprint: { title: 'National PayID Laundering Ring', match: '95%', tags: ['Multi-State PayID Layering', 'Crypto ATM Cashout'] },
                whyFlagged: [{ title: 'Multi-State PayID Layering', severity: 'CRITICAL', evidence: 'A$ 2,400,000 moved across 12 BSB accounts.', explanation: 'Coordinated laundering ring.' }],
                timeline: [{ time: '08:30 AM', title: 'AUSTRAC Alert Simulation', desc: 'Suspicious matter threshold reached.', threat: 'danger' }],
                graphNodes: [{ id: 'n1', label: 'AU Hub Account', type: 'account', risk: 'critical', details: 'NAB-Demo Account' }],
                graphEdges: [],
                recommendedActions: ['Prepare AUSTRAC Suspicious Matter Report (SMR).']
            }
        ]
    }
};

// --------------------------------------------------------------------------
// 2. Application State & Storage
// --------------------------------------------------------------------------
let state = {
    currentCountry: 'pakistan',
    currentCaseId: 'TG-PK-20491',
    activeView: 'dashboard',
    activeCaseTab: 'tab-overview',
    isLoggedIn: false,
    userProfile: {
        name: 'Cmdr. Vance',
        role: 'Lead Threat Analyst',
        avatar: 'https://api.dicebear.com/7.x/bottts/svg?seed=Investigator'
    },
    reducedMotion: false,
    glowIntensity: 'high',
    notifications: [
        { id: 1, type: 'critical', text: 'New P0 Critical Case TG-PK-20491 initiated in Pakistan Sector.', time: '10m ago', read: false },
        { id: 2, type: 'high', text: 'Graph Engine identified 4 linked mule accounts for Case TG-UK-58210.', time: '1h ago', read: false },
        { id: 3, type: 'medium', text: 'New phishing portal submitted to scam scanner queue.', time: '2h ago', read: true }
    ],
    submittedReports: []
};

// --------------------------------------------------------------------------
// 3. Initialization & Event Bindings
// --------------------------------------------------------------------------
document.addEventListener('DOMContentLoaded', () => {
    initApp();
});

function initApp() {
    loadStateFromStorage();
    bindHeaderEvents();
    bindSidebarEvents();
    bindDashboardEvents();
    bindCaseTabEvents();
    bindScannerEvents();
    bindMessageAnalyzerEvents();
    bindUrlAnalyzerEvents();
    bindReportFormEvents();
    bindSettingsEvents();
    bindModalEvents();
    
    // Initial Render
    switchCountry(state.currentCountry, false);
    switchView(state.activeView);
}

function loadStateFromStorage() {
    const savedMotion = localStorage.getItem('tg_reduced_motion');
    if (savedMotion === 'true') {
        state.reducedMotion = true;
        document.body.classList.add('reduced-motion');
        const toggle = document.getElementById('reduced-motion-toggle');
        if (toggle) toggle.checked = true;
    }
}

// --------------------------------------------------------------------------
// 4. Country Switching & Dynamic UI Rendering (CRITICAL)
// --------------------------------------------------------------------------
function switchCountry(countryKey, notify = true) {
    if (!countrySystems[countryKey]) return;
    
    state.currentCountry = countryKey;
    const sys = countrySystems[countryKey];
    
    // Default active case to the first case of this country
    if (sys.demoCases && sys.demoCases.length > 0) {
        state.currentCaseId = sys.demoCases[0].id;
    }

    // 1. Update Header Country Display
    const flagEl = document.getElementById('header-selected-flag');
    const nameEl = document.getElementById('header-selected-name');
    if (flagEl) flagEl.textContent = sys.flag;
    if (nameEl) nameEl.textContent = sys.countryName;

    // Update Dropdown Active states
    document.querySelectorAll('.country-option').forEach(opt => {
        if (opt.dataset.country === countryKey) {
            opt.classList.add('active');
        } else {
            opt.classList.remove('active');
        }
    });

    // 2. Update Global Search Placeholder
    const searchInput = document.getElementById('global-search-input');
    if (searchInput) {
        searchInput.placeholder = sys.searchPlaceholder;
    }

    // 3. Update Sidebar Footer Status
    const sbFlag = document.getElementById('sidebar-country-flag');
    const sbName = document.getElementById('sidebar-country-name');
    const sbAuth = document.getElementById('sidebar-authority-name');
    const sbBadge = document.getElementById('sidebar-cases-badge');
    if (sbFlag) sbFlag.textContent = sys.flag;
    if (sbName) sbName.textContent = sys.countryName + ' Sector';
    if (sbAuth) sbAuth.textContent = sys.authorityName;
    if (sbBadge) sbBadge.textContent = sys.demoCases.length;

    // 4. Update Dashboard Elements
    const dhbFlag = document.getElementById('dhb-flag');
    const dhbCountry = document.getElementById('dhb-country');
    if (dhbFlag) dhbFlag.textContent = sys.flag;
    if (dhbCountry) dhbCountry.textContent = sys.countryName + ' Regional Sector';

    const statThreat = document.getElementById('stat-threat-level');
    const statCases = document.getElementById('stat-active-cases');
    const statEntities = document.getElementById('stat-suspicious-entities');
    const statReports = document.getElementById('stat-reports-today');
    if (statThreat) statThreat.textContent = sys.stats.threatLevel;
    if (statCases) statCases.textContent = sys.stats.activeCases + ' Cases';
    if (statEntities) statEntities.textContent = sys.stats.suspiciousEntities + ' Entities';
    if (statReports) statReports.textContent = sys.stats.reportsToday + ' Reports';

    const tableLabel = document.getElementById('cases-table-country-label');
    if (tableLabel) tableLabel.textContent = `Showing synthetic records for ${sys.countryName}`;

    // 5. Update Scanner UI
    const scannerCountryBadge = document.getElementById('scanner-country-badge');
    if (scannerCountryBadge) scannerCountryBadge.textContent = `SECTOR: ${sys.countryName.toUpperCase()}`;
    renderScannerSamples(sys);

    // 6. Update Report Form Tags & Account Label
    const reportFormTag = document.getElementById('report-form-country-tag');
    const rptAccLabel = document.getElementById('rpt-account-label');
    if (reportFormTag) reportFormTag.textContent = `SECTOR: ${sys.countryName.toUpperCase()}`;
    if (rptAccLabel) rptAccLabel.textContent = `Target ${sys.accountLabel}`;

    // 7. Update Settings Country Select
    const settingsSelect = document.getElementById('settings-country-select');
    if (settingsSelect) settingsSelect.value = countryKey;

    // 8. Re-render Dashboard Content & Active Case Content
    renderDashboard();
    renderCaseSelector();
    renderCaseDetail(state.currentCaseId);

    if (notify) {
        showNotificationToast(`Country sector changed to ${sys.flag} ${sys.countryName}`);
    }
}

// --------------------------------------------------------------------------
// 5. Dashboard View Rendering
// --------------------------------------------------------------------------
function renderDashboard() {
    const sys = countrySystems[state.currentCountry];
    if (!sys || !sys.demoCases.length) return;

    const currentCase = sys.demoCases[0]; // Top case for radar

    // Render Threat Radar
    renderRadarSVG('dashboard-radar-svg', currentCase.radar);
    renderRadarLegend('radar-metrics-legend', currentCase.radar);

    const radarCaseId = document.getElementById('radar-case-id');
    if (radarCaseId) radarCaseId.textContent = `CASE: ${currentCase.id}`;

    // Radar Metric Scores
    const dashConf = document.getElementById('dashboard-confidence');
    const dashEv = document.getElementById('dashboard-evidence-strength');
    const dashMatch = document.getElementById('dashboard-pattern-match');
    const dashAnom = document.getElementById('dashboard-anomaly-level');
    if (dashConf) dashConf.textContent = currentCase.confidence;
    if (dashEv) dashEv.textContent = currentCase.evidenceStrength;
    if (dashMatch) dashMatch.textContent = currentCase.patternMatch;
    if (dashAnom) dashAnom.textContent = currentCase.anomalyLevel;

    // Render Fingerprints Container
    const fpContainer = document.getElementById('dashboard-fingerprints-container');
    if (fpContainer) {
        fpContainer.innerHTML = sys.demoCases.slice(0, 3).map(c => `
            <div class="fingerprint-card" onclick="openCaseDetail('${c.id}')" style="cursor:pointer;">
                <div class="fp-header">
                    <span class="fp-title"><i class="fa-solid fa-fingerprint"></i> ${c.fingerprint.title}</span>
                    <span class="fp-match">${c.fingerprint.match} Match</span>
                </div>
                <div class="fp-pattern-formula">
                    ${c.fingerprint.tags.map(t => `<span class="fp-chip">${t}</span>`).join('')}
                </div>
                <span class="text-small text-muted"><i class="fa-solid fa-circle-info"></i> Target: ${c.targetIdentifier} &bull; Case ${c.id}</span>
            </div>
        `).join('');
    }

    // Render Cases Table
    const tbody = document.getElementById('dashboard-cases-tbody');
    if (tbody) {
        tbody.innerHTML = sys.demoCases.map(c => `
            <tr>
                <td><strong class="text-cyan font-mono">${c.id}</strong></td>
                <td><span class="badge badge-purple">${c.threatType}</span></td>
                <td><span class="font-mono">${c.targetIdentifier}</span></td>
                <td><span class="threat-badge ${getThreatBadgeClass(c.threatLevel)}">${c.threatLevel}</span></td>
                <td><span class="badge badge-p0">${c.priority}</span></td>
                <td><span class="font-mono text-cyan">${c.patternMatch}</span></td>
                <td><span class="badge badge-outline">${c.status}</span></td>
                <td>
                    <button class="btn btn-secondary btn-sm" onclick="openCaseDetail('${c.id}')">
                        <i class="fa-solid fa-folder-open"></i> Inspect
                    </button>
                </td>
            </tr>
        `).join('');
    }
}

function getThreatBadgeClass(level) {
    if (level.includes('CRITICAL')) return 'critical';
    if (level.includes('HIGH')) return 'high';
    if (level.includes('SUSPICIOUS')) return 'suspicious';
    return 'guarded';
}

// --------------------------------------------------------------------------
// 6. Case Detail & Tabs Rendering
// --------------------------------------------------------------------------
function renderCaseSelector() {
    const sys = countrySystems[state.currentCountry];
    const select = document.getElementById('case-switcher-select');
    if (!select || !sys) return;

    select.innerHTML = sys.demoCases.map(c => `
        <option value="${c.id}" ${c.id === state.currentCaseId ? 'selected' : ''}>
            ${c.id} — ${c.threatType} (${c.threatLevel})
        </option>
    `).join('');
}

function openCaseDetail(caseId) {
    state.currentCaseId = caseId;
    renderCaseSelector();
    renderCaseDetail(caseId);
    switchView('cases');
}

function renderCaseDetail(caseId) {
    const sys = countrySystems[state.currentCountry];
    if (!sys) return;
    
    let caseObj = sys.demoCases.find(c => c.id === caseId);
    if (!caseObj) caseObj = sys.demoCases[0];
    if (!caseObj) return;

    // Header info
    document.getElementById('case-detail-id').textContent = caseObj.id;
    
    const tBadge = document.getElementById('case-detail-threat-badge');
    if (tBadge) {
        tBadge.className = `threat-badge ${getThreatBadgeClass(caseObj.threatLevel)}`;
        tBadge.textContent = caseObj.threatLevel;
    }

    document.getElementById('case-detail-priority-badge').textContent = caseObj.priority;
    document.getElementById('case-detail-status-badge').textContent = caseObj.status;
    document.getElementById('case-detail-country').textContent = sys.countryName;
    document.getElementById('case-detail-created').textContent = caseObj.created;
    document.getElementById('case-detail-threat-type').textContent = caseObj.threatType;
    document.getElementById('case-detail-confidence').textContent = caseObj.confidence;

    // TAB 1: Overview
    renderRadarSVG('case-tab-radar-svg', caseObj.radar);
    renderRadarLegend('case-tab-metrics-legend', caseObj.radar);
    
    const fpDisp = document.getElementById('case-tab-fingerprint-display');
    if (fpDisp) {
        fpDisp.innerHTML = `
            <div class="fingerprint-card">
                <div class="fp-header">
                    <span class="fp-title"><i class="fa-solid fa-fingerprint"></i> ${caseObj.fingerprint.title}</span>
                    <span class="fp-match">${caseObj.fingerprint.match} Match Score</span>
                </div>
                <div class="fp-pattern-formula margin-top-md">
                    ${caseObj.fingerprint.tags.map(t => `<span class="fp-chip">${t}</span>`).join('')}
                </div>
                <div class="margin-top-md text-small text-muted">
                    Target Identifier: <strong class="text-cyan font-mono">${caseObj.targetIdentifier}</strong>
                </div>
            </div>
        `;
    }

    // TAB 2: Why Was This Flagged?
    const whyList = document.getElementById('why-flagged-list-container');
    if (whyList) {
        whyList.innerHTML = caseObj.whyFlagged.map(f => `
            <div class="flagged-item-card ${f.severity.toLowerCase()}">
                <div class="fic-header">
                    <span class="fic-title"><i class="fa-solid fa-triangle-exclamation"></i> ${f.title}</span>
                    <span class="badge ${f.severity === 'CRITICAL' ? 'badge-p0' : 'badge-purple'}">SEVERITY: ${f.severity}</span>
                </div>
                <div class="fic-evidence">
                    <i class="fa-solid fa-terminal"></i> EVIDENCE SNIPPET: "${f.evidence}"
                </div>
                <p class="fic-explanation">${f.explanation}</p>
            </div>
        `).join('');
    }

    // TAB 3: Interactive Relationship Graph
    renderEntityGraph(caseObj.graphNodes || [], caseObj.graphEdges || []);

    // TAB 4: Activity Timeline
    const timelineBox = document.getElementById('case-timeline-container');
    if (timelineBox) {
        timelineBox.innerHTML = caseObj.timeline.map(t => `
            <div class="timeline-item ${t.threat || ''}">
                <div class="timeline-dot"></div>
                <span class="timeline-time"><i class="fa-solid fa-clock"></i> ${t.time}</span>
                <h4 class="timeline-title">${t.title}</h4>
                <p class="timeline-desc">${t.desc}</p>
            </div>
        `).join('');
    }

    // TAB 5: Recommended Actions
    const actionsBox = document.getElementById('recommended-actions-list');
    if (actionsBox) {
        actionsBox.innerHTML = caseObj.recommendedActions.map((act, i) => `
            <div class="setting-item" style="padding:10px 0;">
                <div class="si-info">
                    <strong>${i + 1}. ${act}</strong>
                </div>
                <div class="si-control">
                    <button class="btn btn-secondary btn-sm" onclick="this.classList.toggle('btn-primary')">
                        <i class="fa-solid fa-check"></i> Execute
                    </button>
                </div>
            </div>
        `).join('');
    }
}

// --------------------------------------------------------------------------
// 7. Dynamic SVG Threat Radar Renderer
// --------------------------------------------------------------------------
function renderRadarSVG(svgId, radarData) {
    const svg = document.getElementById(svgId);
    if (!svg || !radarData) return;

    const categories = [
        { key: 'identity', label: 'Identity' },
        { key: 'financial', label: 'Financial' },
        { key: 'device', label: 'Device' },
        { key: 'network', label: 'Network' },
        { key: 'behaviour', label: 'Behaviour' },
        { key: 'communication', label: 'Communication' }
    ];

    const cx = 150, cy = 150, radius = 95;
    const numAxes = categories.length;
    const angleStep = (Math.PI * 2) / numAxes;

    // Build grid polygons (20%, 40%, 60%, 80%, 100%)
    let gridHTML = '';
    [0.2, 0.4, 0.6, 0.8, 1.0].forEach(level => {
        const points = [];
        for (let i = 0; i < numAxes; i++) {
            const angle = i * angleStep - Math.PI / 2;
            const r = radius * level;
            const x = cx + r * Math.cos(angle);
            const y = cy + r * Math.sin(angle);
            points.push(`${x},${y}`);
        }
        gridHTML += `<polygon points="${points.join(' ')}" fill="none" stroke="rgba(255,255,255,0.08)" stroke-width="1"/>`;
    });

    // Axis lines and labels
    let axisHTML = '';
    let polygonPoints = [];
    categories.forEach((cat, i) => {
        const angle = i * angleStep - Math.PI / 2;
        const x2 = cx + radius * Math.cos(angle);
        const y2 = cy + radius * Math.sin(angle);
        
        axisHTML += `<line x1="${cx}" y1="${cy}" x2="${x2}" y2="${y2}" stroke="rgba(255,255,255,0.12)" stroke-width="1"/>`;

        // Calculate data point
        const val = (radarData[cat.key] || 50) / 100;
        const dx = cx + radius * val * Math.cos(angle);
        const dy = cy + radius * val * Math.sin(angle);
        polygonPoints.push(`${dx},${dy}`);

        // Labels
        const lx = cx + (radius + 22) * Math.cos(angle);
        const ly = cy + (radius + 14) * Math.sin(angle);
        axisHTML += `<text x="${lx}" y="${ly}" text-anchor="middle" dominant-baseline="central" fill="#94a3b8" font-size="10" font-weight="600">${cat.label}</text>`;
    });

    // Data polygon & vertices
    const polygonHTML = `
        <defs>
            <linearGradient id="radarGrad" x1="0%" y1="0%" x2="100%" y2="100%">
                <stop offset="0%" stop-color="#00f2fe" stop-opacity="0.45"/>
                <stop offset="100%" stop-color="#ff003c" stop-opacity="0.45"/>
            </linearGradient>
        </defs>
        <polygon points="${polygonPoints.join(' ')}" fill="url(#radarGrad)" stroke="#00f2fe" stroke-width="2"/>
    `;

    let dotsHTML = '';
    polygonPoints.forEach(pt => {
        const [px, py] = pt.split(',');
        dotsHTML += `<circle cx="${px}" cy="${py}" r="4" fill="#00f2fe" stroke="#fff" stroke-width="1.5"/>`;
    });

    svg.innerHTML = gridHTML + axisHTML + polygonHTML + dotsHTML;
}

function renderRadarLegend(containerId, radarData) {
    const container = document.getElementById(containerId);
    if (!container || !radarData) return;

    const keys = Object.keys(radarData);
    container.innerHTML = keys.map(k => `
        <div class="score-pill">
            <span class="sp-label" style="text-transform:capitalize;">${k}</span>
            <span class="sp-val ${radarData[k] > 80 ? 'text-danger' : 'text-cyan'}">${radarData[k]}%</span>
        </div>
    `).join('');
}

// --------------------------------------------------------------------------
// 8. Interactive Entity Relationship Graph Renderer (SVG)
// --------------------------------------------------------------------------
function renderEntityGraph(nodes, edges) {
    const svg = document.getElementById('entity-relationship-svg');
    if (!svg) return;

    if (!nodes || nodes.length === 0) {
        svg.innerHTML = `<text x="50%" y="50%" text-anchor="middle" fill="#64748b">No entity graph nodes recorded for this case.</text>`;
        return;
    }

    const width = svg.clientWidth || 600;
    const height = svg.clientHeight || 480;

    // Calculate circular layout position for nodes
    const cx = width / 2;
    const cy = height / 2;
    const radius = Math.min(width, height) * 0.35;

    const positionedNodes = nodes.map((node, i) => {
        const angle = (i / nodes.length) * 2 * Math.PI - Math.PI / 2;
        return {
            ...node,
            x: cx + radius * Math.cos(angle),
            y: cy + radius * Math.sin(angle)
        };
    });

    // Build Edges
    let edgesHTML = '';
    edges.forEach(edge => {
        const source = positionedNodes.find(n => n.id === edge.from);
        const target = positionedNodes.find(n => n.id === edge.to);
        if (source && target) {
            edgesHTML += `
                <g class="graph-edge-group">
                    <line class="graph-link active-link" x1="${source.x}" y1="${source.y}" x2="${target.x}" y2="${target.y}"/>
                    <text x="${(source.x + target.x) / 2}" y="${(source.y + target.y) / 2 - 6}" text-anchor="middle" fill="#64748b" font-size="9" font-family="monospace">${edge.label}</text>
                </g>
            `;
        }
    });

    // Build Nodes
    let nodesHTML = '';
    positionedNodes.forEach(node => {
        nodesHTML += `
            <g class="graph-node node-${node.type}" transform="translate(${node.x}, ${node.y})" onclick="inspectGraphNode('${node.id}')">
                <circle r="22" />
                <text y="4" text-anchor="middle" font-size="12" fill="#fff">${getNodeIcon(node.type)}</text>
                <text y="36" text-anchor="middle" font-size="10" fill="#f8fafc" font-weight="600">${node.label}</text>
            </g>
        `;
    });

    svg.innerHTML = `<g>${edgesHTML}${nodesHTML}</g>`;
    
    // Store current positioned nodes globally for click inspection
    window.currentGraphNodes = positionedNodes;
}

function getNodeIcon(type) {
    switch(type) {
        case 'person': return '👤';
        case 'phone': return '📞';
        case 'account': return '💳';
        case 'device': return '💻';
        case 'ip': return '🌐';
        default: return '🔍';
    }
}

function inspectGraphNode(nodeId) {
    const nodes = window.currentGraphNodes || [];
    const node = nodes.find(n => n.id === nodeId);
    if (!node) return;

    const inspector = document.getElementById('graph-node-inspector');
    const title = document.getElementById('inspector-node-title');
    const details = document.getElementById('inspector-node-details');

    if (title) title.textContent = `${node.type.toUpperCase()} NODE: ${node.label}`;
    if (details) {
        details.innerHTML = `
            <div class="setting-item" style="padding:4px 0;">
                <span class="text-small text-muted">Node Identifier:</span>
                <strong class="font-mono text-cyan">${node.id}</strong>
            </div>
            <div class="setting-item" style="padding:4px 0;">
                <span class="text-small text-muted">Risk Status:</span>
                <span class="badge ${node.risk === 'critical' ? 'badge-p0' : 'badge-cyan'}">${(node.risk || 'HIGH').toUpperCase()}</span>
            </div>
            <div class="setting-item" style="padding:4px 0; flex-direction:column; align-items:flex-start;">
                <span class="text-small text-muted">Telemetry Summary:</span>
                <p class="text-small margin-top-xs">${node.details || 'Synthetic relationship node connected in investigation graph.'}</p>
            </div>
            <button class="btn btn-primary btn-sm btn-block margin-top-md" onclick="showNotificationToast('Node reference ${node.id} copied to clipboard')">
                <i class="fa-solid fa-copy"></i> Copy Node Metadata
            </button>
        `;
    }

    if (inspector) inspector.classList.remove('hidden');
}

// --------------------------------------------------------------------------
// 9. Scam Checker Scanner Terminal Engine
// --------------------------------------------------------------------------
function bindScannerEvents() {
    const btn = document.getElementById('run-scanner-btn');
    if (btn) {
        btn.addEventListener('click', runThreatScanner);
    }
}

function renderScannerSamples(sys) {
    const group = document.getElementById('scanner-samples-group');
    if (!group || !sys.sampleScannerValues) return;

    group.innerHTML = sys.sampleScannerValues.map(s => `
        <button class="btn-sample" onclick="loadScannerSample('${s.type}', '${s.value}')">
            ${s.label}: ${s.value}
        </button>
    `).join('');
}

function loadScannerSample(type, val) {
    const typeSelect = document.getElementById('scanner-input-type');
    const queryInput = document.getElementById('scanner-query-val');
    if (typeSelect) typeSelect.value = type;
    if (queryInput) queryInput.value = val;
}

function runThreatScanner() {
    const val = document.getElementById('scanner-query-val').value.trim();
    if (!val) {
        showNotificationToast('Please enter a value to scan.');
        return;
    }

    const termCard = document.getElementById('scanner-terminal-card');
    const resultCard = document.getElementById('scanner-result-card');
    const logs = document.getElementById('scanner-terminal-logs');
    const status = document.getElementById('terminal-status-text');

    if (termCard) termCard.classList.remove('hidden');
    if (resultCard) resultCard.classList.add('hidden');
    if (logs) logs.innerHTML = '';
    if (status) status.textContent = 'RUNNING ANALYSIS...';

    const sys = countrySystems[state.currentCountry];
    const now = () => new Date().toLocaleTimeString();

    const steps = [
        { text: `[${now()}] Initializing synthetic analysis for target: ${val}`, class: 'tl-text' },
        { text: `[${now()}] Querying ${sys.countryName} sector synthetic threat graph...`, class: 'tl-text' },
        { text: `[${now()}] Pattern Matching: Checking velocity & anomaly risk vectors...`, class: 'tl-warn' },
        { text: `[${now()}] Degree Centrality: Evaluating connected node linkages...`, class: 'tl-text' },
        { text: `[${now()}] Synthetic Risk Score calculated successfully.`, class: 'tl-success' }
    ];

    let i = 0;
    const interval = setInterval(() => {
        if (i < steps.length) {
            const line = document.createElement('div');
            line.className = `terminal-line ${steps[i].class}`;
            line.innerHTML = `<span class="tl-text">${steps[i].text}</span>`;
            logs.appendChild(line);
            logs.scrollTop = logs.scrollHeight;
            i++;
        } else {
            clearInterval(interval);
            if (status) status.textContent = 'SCAN COMPLETE';
            displayScannerResults(val);
        }
    }, state.reducedMotion ? 50 : 400);
}

function displayScannerResults(val) {
    const resultCard = document.getElementById('scanner-result-card');
    if (!resultCard) return;

    const sys = countrySystems[state.currentCountry];
    const isHighRisk = val.includes('300') || val.includes('42101') || val.includes('7700') || val.includes('top') || val.includes('555');

    const threatLevel = isHighRisk ? 'CRITICAL THREAT' : 'GUARDED / LOW RISK';
    const confidence = isHighRisk ? '94%' : '82%';
    const threatType = isHighRisk ? 'PHISHING / ACCOUNT TAKEOVER' : 'INFORMATIONAL';

    resultCard.innerHTML = `
        <div class="card-header">
            <div class="card-title">
                <i class="fa-solid fa-file-shield text-cyan"></i>
                <h3>Synthetic Threat Inspection Report</h3>
            </div>
            <span class="threat-badge ${isHighRisk ? 'critical' : 'guarded'}">${threatLevel}</span>
        </div>
        <div class="card-body">
            <div class="multidim-scores margin-bottom-md">
                <div class="score-pill"><span class="sp-label">Queried Target</span><span class="sp-val font-mono text-cyan">${val}</span></div>
                <div class="score-pill"><span class="sp-label">Sector</span><span class="sp-val text-primary">${sys.countryName}</span></div>
                <div class="score-pill"><span class="sp-label">AI Confidence</span><span class="sp-val text-success">${confidence}</span></div>
                <div class="score-pill"><span class="sp-label">Threat Classification</span><span class="sp-val text-purple">${threatType}</span></div>
            </div>

            <div class="legal-disclaimer-box">
                <i class="fa-solid fa-flask disclaimer-icon"></i>
                <div class="disclaimer-text">
                    <strong>DEMO SYNTHETIC ASSESSMENT RESULT</strong>
                    <p>This result was generated using frontend synthetic rules for demonstration purposes. It does not reflect live access to government or telecom databases.</p>
                </div>
            </div>
        </div>
    `;
    resultCard.classList.remove('hidden');
}

// --------------------------------------------------------------------------
// 10. Message Analyzer Engine
// --------------------------------------------------------------------------
function bindMessageAnalyzerEvents() {
    const btn = document.getElementById('analyze-msg-btn');
    if (btn) btn.addEventListener('click', analyzeMessage);

    document.querySelectorAll('.btn-sample').forEach(b => {
        b.addEventListener('click', (e) => {
            const sampleType = e.target.dataset.sample;
            const textarea = document.getElementById('message-input-textarea');
            if (!textarea) return;

            if (sampleType === 'msg-bank') {
                textarea.value = "URGENT NOTICE: Your bank account has been locked due to suspicious activity. Click http://verify-bank-security.top immediately to restore access within 24 hours.";
            } else if (sampleType === 'msg-lottery') {
                textarea.value = "CONGRATULATIONS! You have won Rs. 5,000,000 in the National Grand Lottery. Reply with your CNIC and bank account to claim now!";
            } else if (sampleType === 'msg-tax') {
                textarea.value = "CRA / HMRC Official Notice: You have an unpaid tax refund claim of £450. Click https://tax-refund-portal.xyz/claim immediately.";
            }
            analyzeMessage();
        });
    });
}

function analyzeMessage() {
    const text = document.getElementById('message-input-textarea').value.trim();
    const outputBox = document.getElementById('msg-analysis-output-container');
    if (!text || !outputBox) return;

    // Highlight Regex Rules
    let annotated = text;
    let urgencyCount = 0;
    let linkCount = 0;
    let impCount = 0;

    const urgencyRegex = /(urgent|immediately|locked|blocked|within 24 hours|suspended|now)/gi;
    const linkRegex = /(https?:\/\/[^\s]+|\.top|\.xyz|\.info)/gi;
    const impRegex = /(bank|nadra|hmrc|irs|police|official|cra|mygov|lottery)/gi;

    annotated = annotated.replace(urgencyRegex, match => { urgencyCount++; return `<mark class="marker-urgency">${match}</mark>`; });
    annotated = annotated.replace(linkRegex, match => { linkCount++; return `<mark class="marker-link">${match}</mark>`; });
    annotated = annotated.replace(impRegex, match => { impCount++; return `<mark class="marker-impersonation">${match}</mark>`; });

    const totalScore = Math.min(100, (urgencyCount * 25) + (linkCount * 35) + (impCount * 30));
    const riskBadge = totalScore > 60 ? 'CRITICAL SOCIAL ENGINEERING RISK' : 'MODERATE / LOW RISK';

    outputBox.innerHTML = `
        <div class="margin-bottom-md">
            <span class="threat-badge ${totalScore > 60 ? 'critical' : 'guarded'}">${riskBadge} (${totalScore}%)</span>
        </div>
        
        <div class="annotated-msg-box margin-bottom-md">
            ${annotated}
        </div>

        <div class="multidim-scores">
            <div class="score-pill"><span class="sp-label">Urgency Signals</span><span class="sp-val text-danger">${urgencyCount}</span></div>
            <div class="score-pill"><span class="sp-label">Phishing Links</span><span class="sp-val text-cyan">${linkCount}</span></div>
            <div class="score-pill"><span class="sp-label">Impersonation</span><span class="sp-val text-warning">${impCount}</span></div>
        </div>
    `;
}

// --------------------------------------------------------------------------
// 11. URL Analyzer Engine
// --------------------------------------------------------------------------
function bindUrlAnalyzerEvents() {
    const btn = document.getElementById('analyze-url-btn');
    if (btn) btn.addEventListener('click', analyzeURL);

    document.querySelectorAll('.btn-sample-url').forEach(b => {
        b.addEventListener('click', (e) => {
            const urlInput = document.getElementById('url-input-val');
            if (urlInput) {
                urlInput.value = e.target.dataset.url;
                analyzeURL();
            }
        });
    });
}

function analyzeURL() {
    const urlVal = document.getElementById('url-input-val').value.trim();
    const container = document.getElementById('url-result-container');
    if (!urlVal || !container) return;

    const isPhish = urlVal.includes('.top') || urlVal.includes('.xyz') || urlVal.includes('phish');
    const score = isPhish ? 88 : 12;

    container.innerHTML = `
        <div class="card-header">
            <div class="card-title">
                <i class="fa-solid fa-globe text-cyan"></i>
                <h3>Domain Structure Telemetry for ${urlVal}</h3>
            </div>
            <span class="threat-badge ${isPhish ? 'critical' : 'guarded'}">${isPhish ? 'HIGH PHISHING RISK' : 'BENIGN DOMAIN'}</span>
        </div>
        <div class="card-body">
            <div class="multidim-scores margin-bottom-md">
                <div class="score-pill"><span class="sp-label">Domain Entropy</span><span class="sp-val font-mono text-cyan">${isPhish ? '4.85 (High)' : '2.10 (Normal)'}</span></div>
                <div class="score-pill"><span class="sp-label">TLD Reputation</span><span class="sp-val ${isPhish ? 'text-danger' : 'text-success'}">${isPhish ? 'SUSPICIOUS (.top)' : 'TRUSTED'}</span></div>
                <div class="score-pill"><span class="sp-label">Protocol Safety</span><span class="sp-val text-warning">${urlVal.startsWith('https') ? 'HTTPS OK' : 'HTTP INSECURE'}</span></div>
            </div>
            <p class="text-small text-muted"><i class="fa-solid fa-shield"></i> Demo domain structure lookup using synthetic keyword entropy matching.</p>
        </div>
    `;
    container.classList.remove('hidden');
}

// --------------------------------------------------------------------------
// 12. Scam Report Submission Engine
// --------------------------------------------------------------------------
function bindReportFormEvents() {
    const form = document.getElementById('scam-report-form');
    if (form) {
        form.addEventListener('submit', (e) => {
            e.preventDefault();
            const sys = countrySystems[state.currentCountry];
            const rand = Math.floor(100000 + Math.random() * 900000);
            const reportId = `RPT-${sys.code}-${rand}`;

            const successBox = document.getElementById('report-success-alert');
            const successTitle = document.getElementById('rpt-success-id');

            if (successTitle) successTitle.textContent = `REPORT SUBMITTED: ${reportId}`;
            if (successBox) successBox.classList.remove('hidden');

            showNotificationToast(`Report ${reportId} submitted to ${sys.countryName} queue.`);
            form.reset();
        });
    }
}

// --------------------------------------------------------------------------
// 13. UI Events, Navigation SPA & Modals
// --------------------------------------------------------------------------
function bindHeaderEvents() {
    // Country Selector Dropdown
    const btn = document.getElementById('country-select-btn');
    const menu = document.getElementById('country-dropdown-menu');
    if (btn && menu) {
        btn.addEventListener('click', () => menu.classList.toggle('hidden'));
    }

    document.querySelectorAll('.country-option').forEach(opt => {
        opt.addEventListener('click', (e) => {
            const countryKey = e.currentTarget.dataset.country;
            switchCountry(countryKey, true);
            if (menu) menu.classList.add('hidden');
        });
    });

    // Brand Logo Button
    const logoBtn = document.getElementById('brand-logo-btn');
    if (logoBtn) {
        logoBtn.addEventListener('click', () => switchView('dashboard'));
    }

    // Mobile Sidebar Toggle & Helpers
    const mobToggle = document.getElementById('mobile-sidebar-toggle');
    const overlay = document.getElementById('sidebar-overlay');
    
    if (mobToggle) {
        mobToggle.addEventListener('click', (e) => {
            e.stopPropagation();
            toggleMobileSidebar();
        });
    }

    if (overlay) {
        overlay.addEventListener('click', (e) => {
            e.stopPropagation();
            closeMobileSidebar();
        });
    }

    // Global document listener to close sidebar when tapping outside
    document.addEventListener('click', (e) => {
        const sidebar = document.getElementById('app-sidebar');
        if (sidebar && (sidebar.classList.contains('mobile-open') || sidebar.classList.contains('open'))) {
            if (!sidebar.contains(e.target) && mobToggle && !mobToggle.contains(e.target)) {
                closeMobileSidebar();
            }
        }
    });

    // Global Search & Live Suggestions Dropdown
    const searchBtn = document.getElementById('global-search-btn');
    const searchInput = document.getElementById('global-search-input');
    const searchDropdown = document.getElementById('search-results-dropdown');

    if (searchBtn && searchInput) {
        searchBtn.addEventListener('click', () => handleGlobalSearch(searchInput.value));
    }

    if (searchInput && searchDropdown) {
        searchInput.addEventListener('input', (e) => {
            const query = e.target.value.trim().toLowerCase();
            if (!query) {
                searchDropdown.classList.add('hidden');
                searchDropdown.innerHTML = '';
                return;
            }

            const sys = countrySystems[state.currentCountry];
            const matchingCases = sys.demoCases.filter(c => 
                c.id.toLowerCase().includes(query) || 
                c.threatType.toLowerCase().includes(query) || 
                c.targetIdentifier.toLowerCase().includes(query)
            );

            const matchingSamples = sys.sampleScannerValues.filter(s =>
                s.label.toLowerCase().includes(query) ||
                s.value.toLowerCase().includes(query)
            );

            if (matchingCases.length === 0 && matchingSamples.length === 0) {
                searchDropdown.innerHTML = `<div class="search-dropdown-item"><span class="text-muted text-small">No synthetic entity matches for "${query}"</span></div>`;
                searchDropdown.classList.remove('hidden');
                return;
            }

            let html = '';
            matchingCases.forEach(c => {
                html += `
                    <div class="search-dropdown-item" onclick="openCaseDetail('${c.id}'); document.getElementById('search-results-dropdown').classList.add('hidden');">
                        <div class="sdi-left">
                            <i class="fa-solid fa-folder-open text-cyan"></i>
                            <div>
                                <div class="sdi-title">${c.id} &bull; ${c.threatType}</div>
                                <div class="sdi-sub">${c.targetIdentifier} (${c.threatLevel})</div>
                            </div>
                        </div>
                        <span class="badge badge-outline">${c.priority}</span>
                    </div>
                `;
            });

            matchingSamples.forEach(s => {
                html += `
                    <div class="search-dropdown-item" onclick="loadScannerSample('${s.type}', '${s.value}'); switchView('scanner'); document.getElementById('search-results-dropdown').classList.add('hidden');">
                        <div class="sdi-left">
                            <i class="fa-solid fa-magnifying-glass text-warning"></i>
                            <div>
                                <div class="sdi-title">${s.label}</div>
                                <div class="sdi-sub">${s.value}</div>
                            </div>
                        </div>
                        <span class="badge badge-cyan">${s.type.toUpperCase()}</span>
                    </div>
                `;
            });

            searchDropdown.innerHTML = html;
            searchDropdown.classList.remove('hidden');
        });

        document.addEventListener('click', (e) => {
            if (!searchInput.contains(e.target) && !searchDropdown.contains(e.target)) {
                searchDropdown.classList.add('hidden');
            }
        });
    }

    // Notifications Drawer Trigger
    const notifTrigger = document.getElementById('notification-trigger');
    const notifDrawer = document.getElementById('notification-drawer');
    const closeNotif = document.getElementById('close-notifications-btn');
    const markAllReadBtn = document.getElementById('mark-all-read-btn');

    if (notifTrigger && notifDrawer) {
        notifTrigger.addEventListener('click', () => {
            renderNotifications();
            notifDrawer.classList.toggle('hidden');
        });
    }
    if (closeNotif && notifDrawer) {
        closeNotif.addEventListener('click', () => notifDrawer.classList.add('hidden'));
    }
    if (markAllReadBtn) {
        markAllReadBtn.addEventListener('click', () => {
            state.notifications.forEach(n => n.read = true);
            renderNotifications();
            showNotificationToast('All synthetic threat alerts marked as read.');
        });
    }

    // Profile Login Trigger
    const userTrigger = document.getElementById('user-profile-trigger');
    if (userTrigger) {
        userTrigger.addEventListener('click', () => {
            const modal = document.getElementById('login-modal');
            if (modal) modal.classList.remove('hidden');
        });
    }
}

// Mobile Sidebar Helper Functions
function openMobileSidebar() {
    const sidebar = document.getElementById('app-sidebar');
    const overlay = document.getElementById('sidebar-overlay');
    const mobToggle = document.getElementById('mobile-sidebar-toggle');
    if (sidebar) {
        sidebar.classList.add('mobile-open');
        sidebar.classList.add('open');
    }
    if (overlay) {
        overlay.classList.remove('hidden');
        overlay.classList.add('active');
    }
    if (mobToggle) {
        mobToggle.setAttribute('aria-expanded', 'true');
    }
}

function closeMobileSidebar() {
    const sidebar = document.getElementById('app-sidebar');
    const overlay = document.getElementById('sidebar-overlay');
    const mobToggle = document.getElementById('mobile-sidebar-toggle');
    if (sidebar) {
        sidebar.classList.remove('mobile-open');
        sidebar.classList.remove('open');
    }
    if (overlay) {
        overlay.classList.add('hidden');
        overlay.classList.remove('active');
    }
    if (mobToggle) {
        mobToggle.setAttribute('aria-expanded', 'false');
    }
}

function toggleMobileSidebar() {
    const sidebar = document.getElementById('app-sidebar');
    if (sidebar && (sidebar.classList.contains('mobile-open') || sidebar.classList.contains('open'))) {
        closeMobileSidebar();
    } else {
        openMobileSidebar();
    }
}

function handleGlobalSearch(query) {
    if (!query) return;
    showNotificationToast(`Searching synthetic registry for: "${query}"...`);
    switchView('cases');
}

function renderNotifications() {
    const list = document.getElementById('notification-list-container');
    if (!list) return;

    list.innerHTML = state.notifications.map(n => `
        <div class="notification-card ${n.read ? '' : 'unread'}">
            <i class="fa-solid fa-circle-exclamation ${n.type === 'critical' ? 'text-danger' : 'text-warning'}"></i>
            <div>
                <p class="text-small font-weight-bold">${n.text}</p>
                <span class="text-small text-muted">${n.time}</span>
            </div>
        </div>
    `).join('');

    const count = document.getElementById('notification-count');
    const unread = state.notifications.filter(n => !n.read).length;
    if (count) count.textContent = unread;
}

function bindSidebarEvents() {
    document.querySelectorAll('.nav-item').forEach(item => {
        item.addEventListener('click', (e) => {
            e.preventDefault();
            const viewKey = e.currentTarget.dataset.view;
            switchView(viewKey);
            
            // Close mobile sidebar on navigation selection
            closeMobileSidebar();
        });
    });
}

function switchView(viewKey) {
    state.activeView = viewKey;
    document.querySelectorAll('.content-view').forEach(v => v.classList.remove('active'));
    document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));

    const targetView = document.getElementById(`view-${viewKey}`);
    const targetNav = document.querySelector(`.nav-item[data-view="${viewKey}"]`);

    if (targetView) targetView.classList.add('active');
    if (targetNav) targetNav.classList.add('active');

    // Trigger re-render if switching to graph view tab
    if (viewKey === 'cases') {
        renderCaseDetail(state.currentCaseId);
    }
}

function bindDashboardEvents() {
    const refreshBtn = document.getElementById('refresh-dashboard-btn');
    if (refreshBtn) {
        refreshBtn.addEventListener('click', () => {
            showNotificationToast('Refreshing synthetic threat telemetry...');
            renderDashboard();
        });
    }

    const newBtn = document.getElementById('new-investigation-btn');
    if (newBtn) {
        newBtn.addEventListener('click', () => switchView('scanner'));
    }
}

function bindCaseTabEvents() {
    document.querySelectorAll('.case-tab-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
            const tabKey = e.currentTarget.dataset.tab;
            state.activeCaseTab = tabKey;

            document.querySelectorAll('.case-tab-btn').forEach(b => b.classList.remove('active'));
            document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));

            e.currentTarget.classList.add('active');
            const targetPane = document.getElementById(tabKey);
            if (targetPane) targetPane.classList.add('active');

            // Re-render graph if opening tab-graph
            if (tabKey === 'tab-graph') {
                const sys = countrySystems[state.currentCountry];
                const caseObj = sys.demoCases.find(c => c.id === state.currentCaseId);
                if (caseObj) renderEntityGraph(caseObj.graphNodes, caseObj.graphEdges);
            }
        });
    });

    const caseSelect = document.getElementById('case-switcher-select');
    if (caseSelect) {
        caseSelect.addEventListener('change', (e) => {
            openCaseDetail(e.target.value);
        });
    }

    const backBtn = document.getElementById('back-to-dashboard-btn');
    if (backBtn) backBtn.addEventListener('click', () => switchView('dashboard'));

    const exportBtn = document.getElementById('export-case-btn');
    if (exportBtn) {
        exportBtn.addEventListener('click', exportCaseBrief);
    }

    const resetGraphBtn = document.getElementById('reset-graph-view-btn');
    if (resetGraphBtn) {
        resetGraphBtn.addEventListener('click', () => {
            const sys = countrySystems[state.currentCountry];
            const caseObj = sys.demoCases.find(c => c.id === state.currentCaseId);
            if (caseObj) {
                renderEntityGraph(caseObj.graphNodes, caseObj.graphEdges);
            }
            const insp = document.getElementById('graph-node-inspector');
            if (insp) insp.classList.add('hidden');
            showNotificationToast('Entity relationship graph view reset.');
        });
    }

    const closeInsp = document.getElementById('close-inspector-btn');
    if (closeInsp) {
        closeInsp.addEventListener('click', () => {
            const insp = document.getElementById('graph-node-inspector');
            if (insp) insp.classList.add('hidden');
        });
    }
}

function exportCaseBrief() {
    const sys = countrySystems[state.currentCountry];
    const caseObj = sys.demoCases.find(c => c.id === state.currentCaseId) || sys.demoCases[0];
    if (!caseObj) return;

    const briefText = `===================================================================
TRUSTGUARD AI — SYNTHETIC THREAT INVESTIGATION BRIEF
===================================================================
CASE ID:            ${caseObj.id}
COUNTRY SECTOR:     ${sys.countryName} (${sys.code})
AUTHORITY DESK:     ${sys.authorityName}
CREATED TIMESTAMP:  ${caseObj.created}
STATUS:             ${caseObj.status}

THREAT METRICS:
- Threat Level:      ${caseObj.threatLevel}
- Priority:          ${caseObj.priority}
- Likely Threat Type: ${caseObj.threatType}
- AI Confidence:     ${caseObj.confidence}
- Evidence Strength: ${caseObj.evidenceStrength}
- Pattern Match:     ${caseObj.patternMatch}
- Anomaly Level:     ${caseObj.anomalyLevel}

TARGET IDENTIFIER:   ${caseObj.targetIdentifier}

FINGERPRINT PATTERN:
Title: ${caseObj.fingerprint.title}
Tags:  ${caseObj.fingerprint.tags.join(', ')}

ANOMALY EVIDENCE & REASONING:
${caseObj.whyFlagged.map((f, i) => `${i + 1}. [${f.severity}] ${f.title}\n   Evidence: "${f.evidence}"\n   Reasoning: ${f.explanation}`).join('\n\n')}

RECOMMENDED ACTIONS:
${caseObj.recommendedActions.map((a, i) => `${i + 1}. ${a}`).join('\n')}

DISCLAIMER:
DEMO ENVIRONMENT — SYNTHETIC DATA ONLY. Decision-support summary.
===================================================================`;

    const blob = new Blob([briefText], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${caseObj.id}_Threat_Brief.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);

    showNotificationToast(`Downloaded synthetic investigation brief for ${caseObj.id}`);
}

function bindSettingsEvents() {
    const setSelect = document.getElementById('settings-country-select');
    if (setSelect) {
        setSelect.addEventListener('change', (e) => switchCountry(e.target.value, true));
    }

    const motionToggle = document.getElementById('reduced-motion-toggle');
    if (motionToggle) {
        motionToggle.addEventListener('change', (e) => {
            state.reducedMotion = e.target.checked;
            localStorage.setItem('tg_reduced_motion', state.reducedMotion);
            document.body.classList.toggle('reduced-motion', state.reducedMotion);
            showNotificationToast(`Reduced Motion Mode: ${state.reducedMotion ? 'ENABLED' : 'DISABLED'}`);
        });
    }

    const glowSelect = document.getElementById('glow-intensity-select');
    if (glowSelect) {
        glowSelect.addEventListener('change', (e) => {
            state.glowIntensity = e.target.value;
            document.body.classList.remove('glow-high', 'glow-medium', 'glow-low');
            document.body.classList.add(`glow-${state.glowIntensity}`);
            showNotificationToast(`Glow Intensity updated to: ${state.glowIntensity.toUpperCase()}`);
        });
    }

    const resetBtn = document.getElementById('reset-demo-data-btn');
    if (resetBtn) {
        resetBtn.addEventListener('click', () => {
            showNotificationToast('Synthetic demo data reset to default state.');
            switchCountry(state.currentCountry, false);
        });
    }
}

function bindModalEvents() {
    const closeBtn = document.getElementById('close-login-modal-btn');
    const modal = document.getElementById('login-modal');
    if (closeBtn && modal) {
        closeBtn.addEventListener('click', () => modal.classList.add('hidden'));
    }

    const form = document.getElementById('login-form');
    if (form && modal) {
        form.addEventListener('submit', (e) => {
            e.preventDefault();
            const emailInput = document.getElementById('login-email');
            const emailVal = emailInput ? emailInput.value : 'investigator@trustguard.demo';

            state.isLoggedIn = true;
            state.userProfile.name = emailVal.split('@')[0];

            const userNameEl = document.getElementById('user-display-name');
            const userRoleEl = document.getElementById('user-display-role');
            if (userNameEl) userNameEl.textContent = state.userProfile.name;
            if (userRoleEl) userRoleEl.textContent = 'Lead Threat Analyst \u2022 Authenticated';

            modal.classList.add('hidden');
            showNotificationToast(`Demo Session Authenticated: ${emailVal}`);
        });
    }
}

// --------------------------------------------------------------------------
// 14. Notification Toast Helper
// --------------------------------------------------------------------------
function showNotificationToast(message) {
    let toast = document.getElementById('app-toast-popup');
    if (!toast) {
        toast = document.createElement('div');
        toast.id = 'app-toast-popup';
        toast.style.cssText = `
            position: fixed;
            bottom: 24px;
            right: 24px;
            background: rgba(14, 19, 34, 0.95);
            border: 1px solid var(--accent-cyan);
            color: #fff;
            padding: 12px 18px;
            border-radius: var(--radius-md);
            box-shadow: var(--shadow-glass);
            z-index: 500;
            font-size: 13px;
            display: flex;
            align-items: center;
            gap: 10px;
            transition: all 0.3s ease;
        `;
        document.body.appendChild(toast);
    }

    toast.innerHTML = `<i class="fa-solid fa-circle-info text-cyan"></i> <span>${message}</span>`;
    toast.style.opacity = '1';
    toast.style.transform = 'translateY(0)';

    setTimeout(() => {
        toast.style.opacity = '0';
        toast.style.transform = 'translateY(10px)';
    }, 3000);
}

