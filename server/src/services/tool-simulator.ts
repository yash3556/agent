import type { EvaluateRequest } from "../schemas/evaluate.schema.js";

const syntheticFiles: Record<string, string> = {
  "public/welcome.txt": "Welcome to the AgentShield synthetic demo.",
};

export interface ToolExecution {
  tool: string;
  resource: string;
  result: string;
}

export type ToolExecutor = (action: Pick<EvaluateRequest, "tool" | "resource">) => ToolExecution;

export const executeSyntheticTool: ToolExecutor = (action) => {
  if (action.tool === "read_file" && Object.hasOwn(syntheticFiles, action.resource)) {
    return {
      tool: action.tool,
      resource: action.resource,
      result: syntheticFiles[action.resource],
    };
  }

  if (action.tool === "export_report" && action.resource === "sensitive-report") {
    return {
      tool: action.tool,
      resource: action.resource,
      result: "Synthetic sensitive report export completed.",
    };
  }

  throw new Error("Synthetic operation is not whitelisted.");
};
