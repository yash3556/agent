import { z } from "zod";

const identifier = z.string().trim().min(1).max(64).regex(/^[A-Za-z0-9][A-Za-z0-9._-]*$/);

export const evaluateRequestSchema = z.object({
  agentId: identifier,
  tool: identifier,
  resource: z.string().trim().min(1).max(256),
  context: z.string().max(1000).optional(),
});

export const approvalDecisionSchema = z.object({
  decision: z.enum(["APPROVED", "REJECTED"]),
  reviewer: z.string().trim().min(1).max(64),
  note: z.string().max(500).optional(),
});

export const eventsQuerySchema = z.object({
  limit: z.coerce.number().int().min(1).max(200).default(50),
});

export const approvalsQuerySchema = z.object({
  status: z.preprocess(
    (value) => typeof value === "string" ? value.toLowerCase() : value,
    z.enum(["pending", "approved", "rejected"]).optional(),
  ),
});

export const approvalIdSchema = z.string().min(1).max(100);

export type EvaluateRequest = z.infer<typeof evaluateRequestSchema>;
export type ApprovalDecisionRequest = z.infer<typeof approvalDecisionSchema>;
