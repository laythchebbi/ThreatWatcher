// Placeholder env so `config` loads in tests. Every test file requires this first.
process.env.NODE_ENV = "test";
process.env.LOG_LEVEL = "fatal";
process.env.MONGODB_URI ||= "mongodb://127.0.0.1:27017/threatwatcher-test";
process.env.BASE_URL ||= "http://localhost:3000";
process.env.SESSION_PASSWORD ||= "test-session-password-at-least-32-chars-long";
