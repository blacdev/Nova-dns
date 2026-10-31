/** An API error in the shared contract's shape: `{"error": {"code", "message"}}` with its status. */
export class ApiError extends Error {
  constructor(public status: number, public code: string, message: string, public headers: Record<string, string> = {}) {
    super(message);
  }
  body() {
    return { error: { code: this.code, message: this.message } };
  }
}

export const badRequest = (message: string, code = "invalid_request") => new ApiError(400, code, message);
export const unauthorized = (message = "Sign in again.", code = "invalid_token") => new ApiError(401, code, message);
export const forbidden = (message: string, code = "forbidden") => new ApiError(403, code, message);
export const notFound = (message: string, code = "not_found") => new ApiError(404, code, message);
export const tooMany = (retryAfter: number) =>
  new ApiError(429, "rate_limited", `Too many attempts; try again in ${retryAfter} seconds.`, { "Retry-After": String(retryAfter) });
