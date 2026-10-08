// Single Page Application bundle simulating client routes and API calls

async function fetchUserProfile() {
  const res = await fetch("/api/profile", { credentials: "include" });
  return await res.json();
}

async function fetchPublicConfig() {
  const res = await fetch("/api/public");
  return await res.json();
}

async function fetchAdminPanel() {
  const res = await fetch("/api/v1/admin");
  return await res.json();
}

async function fetchSupabaseUsers() {
  const res = await fetch("/rest/v1/exposed_users");
  return await res.json();
}

async function fetchSupabaseVault() {
  const res = await fetch("/rest/v1/protected_vault");
  return await res.json();
}

async function runGraphQLQuery(query) {
  return await fetch("/graphql", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ query: query })
  });
}
