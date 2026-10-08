// Regression Corpus: Secret Detection True Positives
// These patterns represent credential-like material that Felix MUST detect.

// 1. AWS Access Key ID (Regex Detector)
const AWS_ACCESS_KEY_ID = "AKIA1234567890ABCDEF";

// 2. GitHub Personal Access Token (Regex Detector)
const GITHUB_PERSONAL_TOKEN = "ghp_1234567890abcdefghijklmnopqrstuvwxyz";

// 3. Slack Bot Token (Regex Detector)
const SLACK_BOT_TOKEN = "xoxb-123456789012-1234567890123-abcdefghijklmnopqrstuvwx";

// 4. Stripe Live Secret Key (Regex Detector)
const STRIPE_SECRET_KEY = "sk_live_51Abcdef1234567890abcdef1234567890";

// 5. High-Entropy Credential in Secret Context (Shannon Entropy Heuristic)
const API_SECRET_KEY = "4fA8bC9dE0fG1hI2jK3lM4nO5pQ6rS7tU8vW9xY0z=";

// 6. Private Key Pattern (Block Detector)
const RSA_PRIVATE_KEY = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0Y8vQ6abcdefghijklmnopqrstuvwxyz0123456789\n-----END RSA PRIVATE KEY-----";

// 7. Legitimate NexSpace Entropy Candidate Pattern (Shannon Entropy Heuristic)
const SESSION_TOKEN = "sb_p9876543210abcdefghijklmnop_ud_e";

// 8. Supabase Service Role Key (JWT Detector)
const SUPABASE_SERVICE_ROLE = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJvbGUiOiJzZXJ2aWNlX3JvbGUifQ.c2lnbmF0dXJlLWRhdGEtYnl0ZXMtaGVyZS0xMjM0NTY";
