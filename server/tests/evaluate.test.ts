import request from "supertest";
import { describe, expect, it, vi } from "vitest";
import { createApp } from "../src/app.js";
import { MemoryAuditStore } from "../src/config/database.js";
import { executeSyntheticTool } from "../src/services/tool-simulator.js";

describe("evaluation API", () => {
  it("reports service and storage health without exposing internals", async () => {
    const response = await request(createApp(new MemoryAuditStore())).get("/api/health");
    expect(response.status).toBe(200);
    expect(response.body).toMatchObject({
      status: "ok",
      db: "connected",
      storage: "memory",
      ai: "disabled",
    });
    expect(response.body.time).toMatch(/Z$/);
  });

  it("keeps health available when audit storage is down", async () => {
    class UnavailableStore extends MemoryAuditStore {
      override async isHealthy(): Promise<boolean> {
        return false;
      }
    }

    const response = await request(createApp(new UnavailableStore())).get("/api/health");
    expect(response.status).toBe(200);
    expect(response.body.db).toBe("error");
  });

  it("returns the canonical scenarios", async () => {
    const response = await request(createApp(new MemoryAuditStore())).get("/api/scenarios");
    expect(response.status).toBe(200);
    expect(response.body.scenarios.map((scenario: { id: string }) => scenario.id)).toEqual(["S1", "S2", "S3"]);
  });

  it("persists an allowed event before executing the synthetic operation", async () => {
    const store = new MemoryAuditStore();
    const executeTool = vi.fn(executeSyntheticTool);
    const response = await request(createApp(store, { executeTool })).post("/api/evaluate").send({
      agentId: "demo-agent",
      tool: "read_file",
      resource: "public/welcome.txt",
    });

    expect(response.status).toBe(200);
    expect(response.body).toMatchObject({ decision: "ALLOW", ruleId: "R-002", executed: true, advisory: null });
    expect((await store.listEvents(50))[0]).toMatchObject({ executed: true, type: "EVALUATION" });
    expect(executeTool).toHaveBeenCalledTimes(1);
  });

  it("blocks unsupported actions without invoking the executor", async () => {
    const store = new MemoryAuditStore();
    const executeTool = vi.fn(executeSyntheticTool);
    const response = await request(createApp(store, { executeTool })).post("/api/evaluate").send({
      agentId: "demo-agent",
      tool: "unknown_tool",
      resource: "public/welcome.txt",
    });

    expect(response.status).toBe(200);
    expect(response.body).toMatchObject({ decision: "BLOCK", ruleId: "R-999", executed: false });
    expect(executeTool).not.toHaveBeenCalled();
    expect((await store.listEvents(50))[0]?.executed).toBe(false);
  });

  it("rejects malformed payloads and strips unknown fields", async () => {
    const executeTool = vi.fn(executeSyntheticTool);
    const app = createApp(new MemoryAuditStore(), { executeTool });
    const malformed = await request(app).post("/api/evaluate").send({
      agentId: "demo-agent",
      tool: "read_file",
      resource: "public/welcome.txt",
      context: { prompt: "not a string" },
    });
    expect(malformed.status).toBe(400);
    expect(malformed.body.error).toBe("VALIDATION_ERROR");
    expect(executeTool).not.toHaveBeenCalled();

    const validWithExtra = await request(app).post("/api/evaluate").send({
      agentId: "demo-agent",
      tool: "read_file",
      resource: "public/welcome.txt",
      unexpected: "stripped",
    });
    expect(validWithExtra.status).toBe(200);
  });

  it("fails closed when audit persistence is unavailable", async () => {
    class UnavailableStore extends MemoryAuditStore {
      override async saveEvaluation(): Promise<void> {
        throw new Error("database offline");
      }
    }

    const executeTool = vi.fn(executeSyntheticTool);
    const response = await request(createApp(new UnavailableStore(), { executeTool })).post("/api/evaluate").send({
      agentId: "demo-agent",
      tool: "read_file",
      resource: "public/welcome.txt",
    });

    expect(response.status).toBe(503);
    expect(response.body.error).toBe("AUDIT_UNAVAILABLE");
    expect(executeTool).not.toHaveBeenCalled();
  });

  it("records synthetic execution failures and returns an internal error", async () => {
    const store = new MemoryAuditStore();
    const executeTool = vi.fn(() => {
      throw new Error("synthetic failure");
    });
    const response = await request(createApp(store, { executeTool })).post("/api/evaluate").send({
      agentId: "demo-agent",
      tool: "read_file",
      resource: "public/welcome.txt",
    });

    expect(response.status).toBe(500);
    expect(response.body.error).toBe("INTERNAL_ERROR");
    expect((await store.listEvents(50))[0]).toMatchObject({
      executed: false,
      reason: expect.stringContaining("Synthetic execution failed."),
    });
  });

  it("does not report AUDIT_UNAVAILABLE if persisting the post-execution outcome fails", async () => {
    class OutcomeFailureStore extends MemoryAuditStore {
      override async updateEvent(): Promise<void> {
        throw new Error("database offline");
      }
    }

    const executeTool = vi.fn(executeSyntheticTool);
    const response = await request(createApp(new OutcomeFailureStore(), { executeTool }))
      .post("/api/evaluate")
      .send({
        agentId: "demo-agent",
        tool: "read_file",
        resource: "public/welcome.txt",
      });

    expect(response.status).toBe(500);
    expect(response.body.error).toBe("INTERNAL_ERROR");
    expect(response.body.message).toContain("completed");
    expect(executeTool).toHaveBeenCalledTimes(1);
  });

  it("redacts secrets and never stores raw context", async () => {
    const store = new MemoryAuditStore();
    await request(createApp(store)).post("/api/evaluate").send({
      agentId: "demo-agent",
      tool: "read_file",
      resource: "public/welcome.txt",
      context: "api_key=sample-secret-value",
    });
    const event = (await store.listEvents(50))[0];
    expect(JSON.stringify(event)).not.toContain("sample-secret-value");
  });

  it("validates event limits and handles oversized JSON", async () => {
    const app = createApp(new MemoryAuditStore());
    expect((await request(app).get("/api/events?limit=0")).status).toBe(400);
    const oversized = await request(app).post("/api/evaluate").send({
      agentId: "demo-agent",
      tool: "read_file",
      resource: "public/welcome.txt",
      context: "x".repeat(11_000),
    });
    expect(oversized.status).toBe(413);
    expect(oversized.body.error).toBe("PAYLOAD_TOO_LARGE");
  });

  it("lists the actual persisted evaluation audit events", async () => {
    const store = new MemoryAuditStore();
    const app = createApp(store);
    await request(app).post("/api/evaluate").send({
      agentId: "demo-agent",
      tool: "read_file",
      resource: "public/welcome.txt",
    });
    const response = await request(app).get("/api/events?limit=1");
    expect(response.status).toBe(200);
    expect(response.body.events).toHaveLength(1);
    expect(response.body.events[0]).toMatchObject({
      decision: "ALLOW",
      ruleId: "R-002",
      executed: true,
    });
  });
});