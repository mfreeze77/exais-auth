/** A request the engine refuses with an HTTP status and a plain message (malformed input, auth, routing). */
export class HttpError extends Error {
  readonly status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

export const badRequest = (message: string) => new HttpError(400, message);
