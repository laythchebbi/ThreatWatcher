// Augment Express's Request with the properties our session middleware attaches.
declare global {
  namespace Express {
    interface Request {
      /** Per-request correlation id. */
      id?: string;
      /** WorkOS access token pulled from the sealed session cookie. */
      token?: string | null;
      /** WorkOS user (with inlined `role`) from the sealed session. */
      user?: {
        id?: string;
        email?: string;
        role?: string | null;
        [key: string]: unknown;
      } | null;
      /** iron-session instance for the current request. */
      session?: {
        workos?: {
          user?: Record<string, unknown>;
          accessToken?: string;
          refreshToken?: string;
          organizationId?: string | null;
        };
        oauth?: { state: string; next: string };
        save: () => Promise<void>;
        destroy: () => void;
        [key: string]: unknown;
      } | null;
    }
  }
}

export {};
