declare module "circomlibjs" {
  /** Field helper exposed on the Poseidon instance. */
  interface PoseidonField {
    /** Convert a field element (Uint8Array/internal repr) to its decimal string. */
    toString(x: unknown): string;
  }

  /** Poseidon hash function over BN254 — call signature matches circomlib's `poseidon`. */
  interface Poseidon {
    (inputs: Array<bigint | number | string>): unknown;
    F: PoseidonField;
  }

  export function buildPoseidon(): Promise<Poseidon>;
}
