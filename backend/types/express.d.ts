import type { Types } from "mongoose";

// Augment Express's Request with the properties our middleware attaches.
// This is the single source of truth for `req.id`, `req.auth`, `req.user`.
declare global {
  namespace Express {
    interface Request {
      /** Per-request correlation id (set by middleware/requestId.js). */
      id?: string;
      /** Decoded WorkOS access-token claims (set by middleware/auth.js). */
      auth?: {
        sub: string;
        email?: string;
        role?: string;
        role_slug?: string;
        org_role?: string;
        org_id?: string;
        permissions?: string[];
        [key: string]: unknown;
      };
      /** Local Mongo user document (set by middleware/auth.js). */
      user?: {
        _id: Types.ObjectId;
        email: string;
        role: "analyst" | "admin";
        displayName?: string;
        monitoredDomains?: string[];
        deactivatedAt?: Date | null;
        [key: string]: unknown;
      };
    }
  }
}

export {};
