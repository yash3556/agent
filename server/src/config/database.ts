import { MongoClient, type Collection, type Db } from "mongodb";
import type {
  Approval,
  AuditEvent,
  ApprovalStatus,
  InspectionRecord,
} from "../types.js";

export interface AuditStore {
  readonly mode: "mongodb" | "memory";
  isHealthy(): Promise<boolean>;
  saveInspection(inspection: InspectionRecord): Promise<void>;
  deleteInspection(inspectionId: string): Promise<void>;
  getInspection(inspectionId: string): Promise<InspectionRecord | null>;
  saveEvaluation(event: AuditEvent, approval?: Approval): Promise<void>;
  insertEvent(event: AuditEvent): Promise<void>;
  updateEvent(event: AuditEvent): Promise<void>;
  deleteEvent(eventId: string): Promise<void>;
  getApproval(approvalId: string): Promise<Approval | null>;
  transitionApproval(
    approvalId: string,
    status: Exclude<ApprovalStatus, "PENDING">,
    decidedAt: string,
    reviewer: string,
    note?: string,
  ): Promise<boolean>;
  listEvents(limit: number): Promise<AuditEvent[]>;
  listApprovals(status?: ApprovalStatus): Promise<Approval[]>;
}

export class MemoryAuditStore implements AuditStore {
  readonly mode = "memory" as const;
  private readonly events = new Map<string, AuditEvent>();
  private readonly approvals = new Map<string, Approval>();
  private readonly inspections = new Map<string, InspectionRecord>();

  async isHealthy(): Promise<boolean> {
    return true;
  }

  async saveInspection(inspection: InspectionRecord): Promise<void> {
    this.inspections.set(inspection.inspectionId, structuredClone(inspection));
  }

  async deleteInspection(inspectionId: string): Promise<void> {
    this.inspections.delete(inspectionId);
  }

  async getInspection(inspectionId: string): Promise<InspectionRecord | null> {
    const inspection = this.inspections.get(inspectionId);
    if (!inspection || inspection.expiresAt.getTime() <= Date.now()) {
      this.inspections.delete(inspectionId);
      return null;
    }
    return structuredClone(inspection);
  }

  async saveEvaluation(event: AuditEvent, approval?: Approval): Promise<void> {
    this.events.set(event.eventId, structuredClone(event));
    if (approval) this.approvals.set(approval.approvalId, structuredClone(approval));
  }

  async insertEvent(event: AuditEvent): Promise<void> {
    this.events.set(event.eventId, structuredClone(event));
  }

  async updateEvent(event: AuditEvent): Promise<void> {
    if (!this.events.has(event.eventId)) throw new Error("Audit event does not exist.");
    this.events.set(event.eventId, structuredClone(event));
  }

  async deleteEvent(eventId: string): Promise<void> {
    this.events.delete(eventId);
  }

  async getApproval(approvalId: string): Promise<Approval | null> {
    const approval = this.approvals.get(approvalId);
    return approval ? structuredClone(approval) : null;
  }

  async transitionApproval(
    approvalId: string,
    status: Exclude<ApprovalStatus, "PENDING">,
    decidedAt: string,
    reviewer: string,
    note?: string,
  ): Promise<boolean> {
    const approval = this.approvals.get(approvalId);
    if (!approval || approval.status !== "PENDING") return false;
    approval.status = status;
    approval.decidedAt = decidedAt;
    approval.reviewer = reviewer;
    if (note !== undefined) approval.note = note;
    return true;
  }

  async listEvents(limit: number): Promise<AuditEvent[]> {
    return [...this.events.values()]
      .sort((left, right) => right.timestamp.localeCompare(left.timestamp))
      .slice(0, limit)
      .map((event) => structuredClone(event));
  }

  async listApprovals(status?: ApprovalStatus): Promise<Approval[]> {
    return [...this.approvals.values()]
      .filter((approval) => status === undefined || approval.status === status)
      .sort((left, right) => right.createdAt.localeCompare(left.createdAt))
      .map((approval) => structuredClone(approval));
  }
}

export class MongoAuditStore implements AuditStore {
  readonly mode = "mongodb" as const;
  private connected = false;
  private readonly client: MongoClient;
  private readonly database: Db;
  private readonly eventCollection: Collection<AuditEvent>;
  private readonly approvalCollection: Collection<Approval>;
  private readonly inspectionCollection: Collection<InspectionRecord>;
  private indexPromise: Promise<void> | undefined;

  constructor(uri: string, databaseName: string) {
    this.client = new MongoClient(uri, { serverSelectionTimeoutMS: 1500 });
    this.database = this.client.db(databaseName);
    this.eventCollection = this.database.collection<AuditEvent>("audit_events");
    this.approvalCollection = this.database.collection<Approval>("approvals");
    this.inspectionCollection = this.database.collection<InspectionRecord>("inspections");
  }

  async close(): Promise<void> {
    await this.client.close();
    this.connected = false;
    this.indexPromise = undefined;
  }

  private async ensureConnected(): Promise<void> {
    try {
      await this.client.connect();
      await this.database.command({ ping: 1 });
      this.indexPromise ??= this.inspectionCollection.createIndex(
        { expiresAt: 1 },
        { expireAfterSeconds: 0, name: "inspection_expiry_ttl" },
      ).then(() => undefined);
      await this.indexPromise;
      this.connected = true;
    } catch (error) {
      this.connected = false;
      this.indexPromise = undefined;
      throw error;
    }
  }

  async saveInspection(inspection: InspectionRecord): Promise<void> {
    await this.ensureConnected();
    await this.inspectionCollection.insertOne({ ...inspection });
  }

  async deleteInspection(inspectionId: string): Promise<void> {
    await this.ensureConnected();
    await this.inspectionCollection.deleteOne({ inspectionId });
  }

  async getInspection(inspectionId: string): Promise<InspectionRecord | null> {
    await this.ensureConnected();
    const inspection = await this.inspectionCollection.findOne(
      { inspectionId },
      { projection: { _id: 0 } },
    );
    if (!inspection || inspection.expiresAt.getTime() <= Date.now()) return null;
    return inspection;
  }

  async isHealthy(): Promise<boolean> {
    try {
      await this.ensureConnected();
      return true;
    } catch {
      return false;
    }
  }

  async saveEvaluation(event: AuditEvent, approval?: Approval): Promise<void> {
    await this.ensureConnected();
    await this.eventCollection.insertOne({ ...event });
    if (approval) {
      try {
        await this.approvalCollection.insertOne({ ...approval });
      } catch (error) {
        await this.eventCollection.deleteOne({ eventId: event.eventId });
        throw error;
      }
    }
  }

  async insertEvent(event: AuditEvent): Promise<void> {
    await this.ensureConnected();
    await this.eventCollection.insertOne({ ...event });
  }

  async updateEvent(event: AuditEvent): Promise<void> {
    await this.ensureConnected();
    const result = await this.eventCollection.replaceOne({ eventId: event.eventId }, event);
    if (result.matchedCount !== 1) throw new Error("Audit event does not exist.");
  }

  async deleteEvent(eventId: string): Promise<void> {
    await this.ensureConnected();
    await this.eventCollection.deleteOne({ eventId });
  }

  async getApproval(approvalId: string): Promise<Approval | null> {
    await this.ensureConnected();
    return this.approvalCollection.findOne({ approvalId }, { projection: { _id: 0 } });
  }

  async transitionApproval(
    approvalId: string,
    status: Exclude<ApprovalStatus, "PENDING">,
    decidedAt: string,
    reviewer: string,
    note?: string,
  ): Promise<boolean> {
    await this.ensureConnected();
    const result = await this.approvalCollection.updateOne(
      { approvalId, status: "PENDING" },
      {
        $set: {
          status,
          decidedAt,
          reviewer,
          ...(note === undefined ? {} : { note }),
        },
      },
    );
    return result.modifiedCount === 1;
  }

  async listEvents(limit: number): Promise<AuditEvent[]> {
    await this.ensureConnected();
    return this.eventCollection
      .find({}, { projection: { _id: 0 } })
      .sort({ timestamp: -1 })
      .limit(limit)
      .toArray();
  }

  async listApprovals(status?: ApprovalStatus): Promise<Approval[]> {
    await this.ensureConnected();
    return this.approvalCollection
      .find(status === undefined ? {} : { status }, { projection: { _id: 0 } })
      .sort({ createdAt: -1 })
      .toArray();
  }
}

export function createAuditStore(): AuditStore {
  if (process.env.STORAGE_MODE === "memory") return new MemoryAuditStore();
  if (process.env.STORAGE_MODE !== "mongodb") {
    throw new Error("Set STORAGE_MODE to 'mongodb' or explicitly opt into 'memory'.");
  }
  const uri = process.env.MONGODB_URI;
  if (!uri) throw new Error("MONGODB_URI is required when STORAGE_MODE=mongodb.");
  return new MongoAuditStore(uri, process.env.MONGODB_DATABASE || "agentshield");
}
