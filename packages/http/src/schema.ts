// Minimal request-body validators (replacement for the subset of Elysia's `t` that CryptoWave uses).

export interface Schema<T> {
  readonly kind: string;
  readonly optional: boolean;
  /** Returns an error description, or null when `value` is valid. */
  validate(value: unknown): string | null;
  /** Phantom field for type inference only. */
  readonly _type?: T;
}

export type Static<S> = S extends Schema<infer T> ? T : never;

function schema<T>(kind: string, validate: (v: unknown) => boolean, optional = false): Schema<T> {
  return {
    kind,
    optional,
    validate: (v) => (validate(v) ? null : `expected ${kind}`),
  };
}

type Shape = Record<string, Schema<any>>;
type ObjectStatic<P extends Shape> = {
  [K in keyof P as undefined extends Static<P[K]> ? never : K]: Static<P[K]>;
} & {
  [K in keyof P as undefined extends Static<P[K]> ? K : never]?: Static<P[K]>;
};

export const t = {
  String: () => schema<string>("string", (v) => typeof v === "string"),
  Number: () => schema<number>("number", (v) => typeof v === "number" && Number.isFinite(v)),
  File: () => schema<File>("file", (v) => typeof v === "object" && v !== null && typeof (v as File).arrayBuffer === "function"),

  Optional: <T>(inner: Schema<T>): Schema<T | undefined> => ({
    kind: inner.kind,
    optional: true,
    validate: (v) => (v === undefined ? null : inner.validate(v)),
  }),

  Union: <S extends Schema<any>[]>(options: S): Schema<Static<S[number]>> => ({
    kind: options.map((o) => o.kind).join(" | "),
    optional: false,
    validate: (v) => (options.some((o) => o.validate(v) === null) ? null : `expected ${options.map((o) => o.kind).join(" or ")}`),
  }),

  Object: <P extends Shape>(props: P): Schema<ObjectStatic<P>> => ({
    kind: "object",
    optional: false,
    validate: (v) => {
      if (typeof v !== "object" || v === null) return "expected a request body";
      for (const [key, s] of Object.entries(props)) {
        const value = (v as Record<string, unknown>)[key];
        if (value === undefined && s.optional) continue;
        if (value === undefined) return `Missing required field '${key}'`;
        const err = s.validate(value);
        if (err) return `Invalid field '${key}': ${err}`;
      }
      return null;
    },
  }),
};
