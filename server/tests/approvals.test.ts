import request from "supertest";
import { describe, expect, it, vi } from "vitest";
import { createApp } from "../src/app.js";
import { MemoryAuditStore } from "../src/config/database.js";
import { executeSyntheticTool } from "../src/services/tool-simulator.js";

async function createPendingApproval(store: MemoryAuditStore): Promise<string> {
  const response = await request(createApp(store)).post("/api/evaluate").send({
    agentId: "demo-agent",
    tool: "export_report",
    resource: "sensitive-report",
  });
  expect(response.status).toBe(200);
  expect(response.body).toMatchObject({ decision: "REQUIRE_APPROVAL", executed: false });
  return response.body.approvalId as string;
}

describe("approval workflow", () => {
  it("creates pending approvals without executing the action", async () => {
    const store = new MemoryAuditStore();
    const approvalId = await createPendingApproval(store);

    expect(approvalId).toMatch(/^apr_/);
    expect((await store.listEvents(50))[0]?.executed).toBe(false);
    expect((await request(createApp(store)).get("/api/approvals?status=Pending")).body.approvals)
      .toHaveLength(1);
  });

  it("executes the original synthetic operation once after approval", async () => {
    const store = new MemoryAuditStore();
    const approvalId = await createPendingApproval(store);
    const executeTool = vi.fn(executeSyntheticTool);

    const response = await request(createApp(store, { executeTool }))
      .post(`/api/approvals/${approvalId}/decision`).send({
      decision: "APPROVED",
      reviewer: "demo-reviewer",
    });

    expect(response.status).toBe(200);
    expect(response.body).toMatchObject({ approval: { status: "APPROVED" }, executed: true });
    expect(executeTool).toHaveBeenCalledTimes(1);
    expect(executeTool).toHaveBeenCalledWith({
      tool: "export_report",
      resource: "sensitive-report",
    });
    expect((await store.listEvents(50)).find((event) => event.type === "APPROVAL_DECISION")).toMatchObject({
      type: "APPROVAL_DECISION",
      approvalStatus: "APPROVED",
      executed: true,
    });
  });

  it("rejects without execution and returns 409 on a repeated decision", async () => {
    const store = new MemoryAuditStore();
    const approvalId = await createPendingApproval(store);
    const executeTool = vi.fn(executeSyntheticTool);
    const app = createApp(store, { executeTool });

    const rejected = await request(app).post(`/api/approvals/${approvalId}/decision`).send({
      decision: "REJECTED",
      reviewer: "sentinel.reviewer@example.test",
      note: "db=mongodb://user:sentinel-approval-password@db.example.test/app; api_key=sentinel-approval-key",
    });
    expect(rejected.status).toBe(200);
    expect(rejected.body).toMatchObject({
      approval: {
        status: "REJECTED",
        reviewer: "[REDACTED_EMAIL]",
        note: "db=[REDACTED_CONNECTION_STRING]; [REDACTED_CREDENTIAL]",
      },
      executed: false,
    });
    const persistedValues = JSON.stringify({
      body: rejected.body,
      events: await store.listEvents(50),
      approvals: await store.listApprovals(),
      eventAPI: (await request(app).get("/api/events")).body,
      approvalAPI: (await request(app).get("/api/approvals")).body,
    });
    expect(persistedValues).not.toContain("sentinel.reviewer@example.test");
    expect(persistedValues).not.toContain("sentinel-approval-password");
    expect(persistedValues).not.toContain("sentinel-approval-key");
    expect(persistedValues).toContain("[REDACTED_CONNECTION_STRING]");
    expect(persistedValues).toContain("[REDACTED_CREDENTIAL]");
    expect(executeTool).not.toHaveBeenCalled();

    const repeated = await request(app).post(`/api/approvals/${approvalId}/decision`).send({
      decision: "APPROVED",
      reviewer: "demo-reviewer",
    });
    expect(repeated.status).toBe(409);
    expect(repeated.body.error).toBe("ALREADY_DECIDED");
    expect(executeTool).not.toHaveBeenCalled();
  });

  it("redacts sensitive values in resource fields before audit persistence", async () => {
    const store = new MemoryAuditStore();
    const app = createApp(store);
    const response = await request(app).post("/api/evaluate").send({
      agentId: "demo-agent",
      tool: "export_report",
      resource: "unapproved; api_key=sentinel-resource-secret",
    });
    expect(response.status).toBe(200);
    expect(response.body.decision).toBe("BLOCK");

    const persistedValues = JSON.stringify({
      events: await store.listEvents(50),
      eventAPI: (await request(app).get("/api/events")).body,
    });
    expect(persistedValues).not.toContain("sentinel-resource-secret");
    expect(persistedValues).toContain("[REDACTED_CREDENTIAL]");
  });

  it("allows only one concurrent approval decision to execute", async () => {
    const store = new MemoryAuditStore();
    const approvalId = await createPendingApproval(store);
    const executeTool = vi.fn(executeSyntheticTool);
    const app = createApp(store, { executeTool });
    const makeDecision = () => request(app)
      .post(`/api/approvals/${approvalId}/decision`)
      .send({ decision: "APPROVED", reviewer: "demo-reviewer" });

    const results = await Promise.all([makeDecision(), makeDecision()]);
    expect(results.map((result) => result.status).sort()).toEqual([200, 409]);
    expect(executeTool).toHaveBeenCalledTimes(1);
    expect((await store.listEvents(50)).filter((event) => event.type === "APPROVAL_DECISION"))
      .toHaveLength(1);
  });

  it("records an approved operation failure without running it twice", async () => {
    const store = new MemoryAuditStore();
    const approvalId = await createPendingApproval(store);
    const executeTool = vi.fn(() => {
      throw new Error("synthetic failure");
    });
    const app = createApp(store, { executeTool });
    const failed = await request(app).post(`/api/approvals/${approvalId}/decision`).send({
      decision: "APPROVED",
      reviewer: "demo-reviewer",
    });

    expect(failed.status).toBe(500);
    expect(failed.body.error).toBe("INTERNAL_ERROR");
    expect((await store.listEvents(50)).find((event) => event.type === "APPROVAL_DECISION")).toMatchObject({
      executed: false,
      reason: expect.stringContaining("Synthetic execution failed."),
    });

    const repeated = await request(app).post(`/api/approvals/${approvalId}/decision`).send({
      decision: "APPROVED",
      reviewer: "demo-reviewer",
    });
    expect(repeated.status).toBe(409);
    expect(executeTool).toHaveBeenCalledTimes(1);
  });

  it("returns 404 for unknown approvals and validates decisions", async () => {
    const app = createApp(new MemoryAuditStore());
    const missing = await request(app).post("/api/approvals/apr_missing/decision").send({
      decision: "APPROVED",
      reviewer: "demo-reviewer",
    });
    expect(missing.status).toBe(404);
    const invalid = await request(app).post("/api/approvals/apr_missing/decision").send({
      decision: "maybe",
      reviewer: "demo-reviewer",
    });
    expect(invalid.status).toBe(400);
    expect((await request(app).get("/api/approvals?status=unknown")).status).toBe(400);
  });

  it("does not transition or execute when decision audit persistence fails", async () => {
    class EventFailureStore extends MemoryAuditStore {
      override async insertEvent(): Promise<void> {
        throw new Error("database offline");
      }
    }

    const store = new EventFailureStore();
    const executeTool = vi.fn(executeSyntheticTool);
    const app = createApp(store, { executeTool });
    const evaluated = await request(app).post("/api/evaluate").send({
      agentId: "demo-agent",
      tool: "export_report",
      resource: "sensitive-report",
    });
    expect(evaluated.status).toBe(200);
    const response = await request(app)
      .post(`/api/approvals/${evaluated.body.approvalId}/decision`)
      .send({ decision: "APPROVED", reviewer: "demo-reviewer" });
    expect(response.status).toBe(503);
    expect(response.body.error).toBe("AUDIT_UNAVAILABLE");
    expect((await store.getApproval(evaluated.body.approvalId))?.status).toBe("PENDING");
    expect(executeTool).not.toHaveBeenCalled();
  });

  it("does not execute when the approval transition fails after audit insertion", async () => {
    class TransitionFailureStore extends MemoryAuditStore {
      override async transitionApproval(): Promise<boolean> {
        throw new Error("storage unavailable");
      }
    }

    const store = new TransitionFailureStore();
    const approvalId = await createPendingApproval(store);
    const executeTool = vi.fn(executeSyntheticTool);
    const response = await request(createApp(store, { executeTool }))
      .post(`/api/approvals/${approvalId}/decision`)
      .send({ decision: "APPROVED", reviewer: "demo-reviewer" });

    expect(response.status).toBe(503);
    expect(response.body.error).toBe("AUDIT_UNAVAILABLE");
    expect((await store.getApproval(approvalId))?.status).toBe("PENDING");
    expect((await store.listEvents(50)).filter((event) => event.type === "APPROVAL_DECISION"))
      .toHaveLength(0);
    expect(executeTool).not.toHaveBeenCalled();
  });
});