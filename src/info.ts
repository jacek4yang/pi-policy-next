// pi-policy-next — stack identity and contract version.

export const STACK_INFO = {
  name: "pi-policy-next",
  contractVersion: 1,
  /** pinx contract namespace events owned by this plugin (CONTRACTS §policy). */
  events: {
    request: "pinx.policy.request",
    decision: "pinx.policy.decision",
  },
  /** Environment configuration (PINX namespace; keep small). */
  env: {
    profile: "PINX_POLICY_PROFILE", // safe | balanced | autonomous (default balanced)
    protected: "PINX_POLICY_PROTECTED", // extra protected path entries (path sep list)
    disable: "PINX_POLICY_DISABLE", // =1 disables enforcement entirely (no protection claimed)
  },
} as const;

export type PolicyProfile = "safe" | "balanced" | "autonomous";
