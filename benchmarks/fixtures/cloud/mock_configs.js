// Cloud provider configuration snippet fixture

const supabaseUrl = "https://mock-proj.supabase.co";
const supabaseClient = createClient(supabaseUrl, "mock-anon-key");

const firebaseApp = initializeApp({
  projectId: "mock-firebase-app",
  databaseURL: "https://mock-firebase-app.firebaseio.com"
});
