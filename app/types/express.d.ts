import type { Types } from "mongoose";

// Augment Express's Request with what our middleware attaches.
declare global {
  namespace Express {
    interface Request {
      /** Per-request correlation id (middleware/request-id.js). */
      id?: string;
      /** Local user document, or null when signed out (middleware/session.js). */
      user?: {
        _id: Types.ObjectId;
        email: string;
        sessionVersion: number;
        emailVerifiedAt?: Date | null;
        timezone?: string;
        [key: string]: unknown;
      } | null;
      /** iron-session for this request (middleware/session.js). */
      session?: {
        userId?: string;
        sv?: number;
        issuedAt?: number;
        save: () => Promise<void>;
        destroy: () => void;
        [key: string]: unknown;
      } | null;
    }
  }
}

export {};
