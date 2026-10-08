// Regression Corpus: Secret Detection False Positives
// These patterns represent common non-secret strings that MUST NOT be flagged as credentials.

// 1. Placeholders and Example Values
const api_dummy = "your_api_key_here";
const token_placeholder = "placeholder_dummy_key";
const replace_token = "replace_me_with_key";
const dummy_val = "test_key_xxxxxxxxx";
const zero_dummy = "dummy_token_0000000000";

// 2. UUIDs
const session_id = "123e4567-e89b-12d3-a456-426614174000";
const user_uuid = "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11";

// 3. CSS and Build Artifacts
const bg_color = "rgba(255, 255, 255, 0.85)";
const border_hex = "#f4a261";
const alpha_hex = "#1a2b3c4d";
const css_var = "var(--primary-color-brand)";

// 4. Webpack Identifiers and Chunk Names
self["webpackChunk_app_portal"] = self["webpackChunk_app_portal"] || [];
const chunk_file = "chunk-4a5b6c7d8e9f.min.js";

// 5. Structured Alphabet / Dictionary Tables (including NexSpace regression)
const b64_table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const b64url_table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const nanoid_alphabet = "useandom-26T198340PX75pxJACKVERYMINDBUSHWOLFGQZbfghjklqvwyzrict";
const base58_table = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

// 6. Normal High-Entropy Application Data (Non-Secret Context)
const build_commit = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
const data_uri = "data:application/json;base64,eyJ2ZXJzaW9uIjoiMS4wIiwidGl0bGUiOiJhcHAifQ==";
