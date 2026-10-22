import "dotenv/config";
import { createApp } from "./app.js";
import { createAuditStore } from "./config/database.js";

const port = Number(process.env.PORT || 3001);
const store = createAuditStore();
const app = createApp(store);

app.listen(port, () => {
  console.info(`AgentShield API listening on port ${port}.`);
});
