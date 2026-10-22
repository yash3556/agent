import { randomUUID } from "node:crypto";
import { MongoClient } from "mongodb";
import request from "supertest";
import { afterEach, describe, expect, it, vi } from "vitest";
import { createApp } from "../src/app.js";
import { MongoAuditStore } from "../src/config/database.js";
import { executeSyntheticTool } from "../src/services/tool-simulator.js";
import type { Approval, AuditEvent, InspectionRecord } from "../src/types.js";

const uri = process.env.MONGODB_TEST_URI;
const describeWithMongo = uri ? describe : describe.skip;
const databaseNames: string[] = [];
const stores: MongoAuditStore[] = [];

function newStore(databaseName: string): MongoAuditStore {
  const store = new MongoAuditStore(uri!, databaseName);
  stores.push(store);
  return store;
}

function makeEvent(): AuditEvent {
  return {
    eventId: `evt_${randomUUID()}`,
    timestamp: new Date().toISOString(),
    agentId: "demo-agent",
    tool: "read_file",
    resource: "public/welcome.txt",
    decision: "ALLOW",
    ruleId: "R-002",
    reason: "Synthetic integration-test event.",
    executed: true,
    approvalId: null,
    advisory: null,
    type: "EVALUATION",
  };
}

async function setValidator(
  databaseName: string,
  collection: string,
  validator: Record<string, unknown>,
): Promise<void> {
  const client = new MongoClient(uri!);
  try {
    await client.connect();
    await client.db(databaseName).command({
      collMod: collection,
      validator,
      validationAction: "error",
    });
  } finally {
    await client.close();
  }
}

describeWithMongo("MongoDB integration", () => {
  afterEach(async () => {
    for (const store of stores.splice(0)) await store.close();
    for (const databaseName of databaseNames.splice(0)) {
      const client = new MongoClient(uri!);
      await client.connect();
      await client.db(databaseName).dropDatabase();
      await client.close();
    }
  });

  it("persists audit records, approvals, and expiring inspections across fresh store instances", async () => {
    const databaseName = `agentshield_test_${randomUUID().replace(/-/g, "")}`;
    databaseNames.push(databaseName);
    const inspection: InspectionRecord = {
      inspectionId: `ins_${randomUUID()}`,
      agentId: "demo-agent",
      status: "COMPLETED",
      originalName: "synthetic.txt",
      mediaType: "text/plain",
      sizeBytes: 10,
      sha256: "0".repeat(64),
      findings: [],
      summary: { totalFindings: 0, truncated: false, bySeverity: { LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 } },
      createdAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 60_000),
    };
    const event = makeEvent();
    const approval: Approval = {
      approvalId: `apr_${randomUUID()}`,
      eventId: event.eventId,
      agentId: "demo-agent",
      tool: "export_report",
      resource: "sensitive-report",
      status: "PENDING",
      createdAt: event.timestamp,
    };

    const first = newStore(databaseName);
    await first.saveInspection(inspection);
    await first.saveEvaluation(event, approval);
    await first.close();

    const second = newStore(databaseName);
    expect(await second.getInspection(inspection.inspectionId)).toMatchObject({
      inspectionId: inspection.inspectionId,
      expiresAt: expect.any(Date),
    });
    expect(await second.getApproval(approval.approvalId)).toMatchObject({ status: "PENDING" });
    expect(await second.listEvents(10)).toMatchObject([event]);
  });

  it("allows only one concurrent MongoDB approval decision to execute", async () => {
    const databaseName = `agentshield_test_${randomUUID().replace(/-/g, "")}`;
    databaseNames.push(databaseName);
    const store = new MongoAuditStore(uri!, databaseName);
    stores.push(store);
    const app = createApp(store);
    const pending = await request(app).post("/api/evaluate").send({
      agentId: "demo-agent",
      tool: "export_report",
      resource: "sensitive-report",
    });
    expect(pending.status).toBe(200);

    const executeTool = vi.fn(executeSyntheticTool);
    const appWithExecutor = createApp(store, { executeTool });
    const makeDecision = () => request(appWithExecutor)
      .post(`/api/approvals/${pending.body.approvalId}/decision`)
      .send({ decision: "APPROVED", reviewer: "integration-reviewer" });
    const results = await Promise.all([makeDecision(), makeDecision()]);

    expect(results.map((result) => result.status).sort()).toEqual([200, 409]);
    expect(executeTool).toHaveBeenCalledTimes(1);
    expect(await store.listEvents(10)).toHaveLength(2);
  });

  it("fails closed when MongoDB rejects the approval decision audit write", async () => {
    const databaseName = `agentshield_test_${randomUUID().replace(/-/g, "")}`;
    databaseNames.push(databaseName);
    const store = new MongoAuditStore(uri!, databaseName);
    stores.push(store);
    const pending = await request(createApp(store)).post("/api/evaluate").send({
      agentId: "demo-agent",
      tool: "export_report",
      resource: "sensitive-report",
    });
    expect(pending.status).toBe(200);

    await setValidator(databaseName, "audit_events", { type: "NEVER_VALID" });

    const executeTool = vi.fn(executeSyntheticTool);
    const response = await request(createApp(store, { executeTool }))
      .post(`/api/approvals/${pending.body.approvalId}/decision`)
      .send({ decision: "APPROVED", reviewer: "integration-reviewer" });
    expect(response.status).toBe(503);
    expect(response.body.error).toBe("AUDIT_UNAVAILABLE");
    expect((await store.getApproval(pending.body.approvalId))?.status).toBe("PENDING");
    expect(executeTool).not.toHaveBeenCalled();
  });

  it("fails closed when MongoDB rejects the approval state transition", async () => {
    const databaseName = `agentshield_test_${randomUUID().replace(/-/g, "")}`;
    databaseNames.push(databaseName);
    const store = new MongoAuditStore(uri!, databaseName);
    stores.push(store);
    const pending = await request(createApp(store)).post("/api/evaluate").send({
      agentId: "demo-agent",
      tool: "export_report",
      resource: "sensitive-report",
    });
    expect(pending.status).toBe(200);

    await setValidator(databaseName, "approvals", { status: "PENDING" });

    const executeTool = vi.fn(executeSyntheticTool);
    const response = await request(createApp(store, { executeTool }))
      .post(`/api/approvals/${pending.body.approvalId}/decision`)
      .send({ decision: "APPROVED", reviewer: "integration-reviewer" });
    expect(response.status).toBe(503);
    expect(response.body.error).toBe("AUDIT_UNAVAILABLE");
    expect((await store.getApproval(pending.body.approvalId))?.status).toBe("PENDING");
    expect(await store.listEvents(10)).toHaveLength(1);
    expect(executeTool).not.toHaveBeenCalled();
  });

  it("fails closed when MongoDB is unavailable during evaluation", async () => {
    const unavailable = new MongoAuditStore("mongodb://127.0.0.1:1", "agentshield_unavailable_test");
    const executeTool = vi.fn(executeSyntheticTool);
    try {
      const response = await request(createApp(unavailable, { executeTool }))
        .post("/api/evaluate")
        .send({
          agentId: "demo-agent",
          tool: "read_file",
          resource: "public/welcome.txt",
        });
      expect(response.status).toBe(503);
      expect(response.body.error).toBe("AUDIT_UNAVAILABLE");
      expect(executeTool).not.toHaveBeenCalled();
    } finally {
      await unavailable.close();
    }
  });
});
