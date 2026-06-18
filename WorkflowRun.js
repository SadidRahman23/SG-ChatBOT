// models/WorkflowRun.js
// One document per workflow execution — gives users (and the AI) a history to inspect.
import mongoose from "mongoose";

const workflowRunSchema = new mongoose.Schema({
  workflowId:  { type: mongoose.Schema.Types.ObjectId, ref: "Workflow", required: true, index: true },
  userId:      { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true, index: true },
  status:      { type: String, enum: ["success", "failed", "partial"], default: "success" },
  triggeredBy: { type: String, enum: ["event", "schedule", "manual"], default: "event" },
  results:     { type: mongoose.Schema.Types.Mixed, default: [] },
  error:       { type: String, default: "" },
}, { timestamps: true });

workflowRunSchema.index({ userId: 1, createdAt: -1 });

export default mongoose.models.WorkflowRun || mongoose.model("WorkflowRun", workflowRunSchema);
