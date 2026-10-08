// Regression Corpus: Cloud Detection False Positives
// Standard public cloud/BaaS configurations that MUST NOT be reported as vulnerabilities.

// 1. Supabase Public Client Initialization with Anon Key
const supabaseUrl = "https://acme-prod.supabase.co";
const supabaseAnonKey = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImFjbWUtcHJvZCIsInJvbGUiOiJhbm9uIn0.mock_signature_for_test_123456";
const client = createClient(supabaseUrl, supabaseAnonKey);

// 2. Firebase Public Client Configuration
const firebaseConfig = {
    apiKey: "AIzaSyDummyKey1234567890",
    authDomain: "acme.firebaseapp.com",
    databaseURL: "https://acme-db.firebaseio.com",
    projectId: "acme-prod",
    storageBucket: "acme-prod.appspot.com"
};

// 3. AWS S3 Public Static Asset Reference
const publicLogo = "https://acme-public-assets.s3.amazonaws.com/logo.png";

// 4. GCP Cloud Storage Public Static Reference
const publicMedia = "https://storage.googleapis.com/acme-public-media/banner.jpg";
