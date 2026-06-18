// models/Workflow.js
// A user-owned automation: one trigger (event OR schedule) + one or more actions.
import mongoose from "mongoose";

const ALLOWED_EVENTS = ["goal_created", "goal_completed", "note_created", "task_created", "task_completed", "habit_completed"];
const ALLOWED_ACTIONS = ["create_note", "create_task", "create_goal", "send_email_summary", "ai_generate_summary"];

// NOTE: `trigger` is defined as its own mongoose.Schema rather than a plain nested object.
// A plain `trigger: { type: {...}, event: {...}, cron: {...} }` would hit a well-known Mongoose
// ambiguity: when a path's own descriptor object has a `type` key whose value is itself another
// descriptor object (not a direct String/Number/etc. constructor), Mongoose misinterprets the
// WHOLE path as that inner descriptor rather than as a nested object with sibling fields. Wrapping
// it as an explicit sub-schema is Mongoose's own documented fix for this.
const triggerSchema = new mongoose.Schema({
  type:  { type: String, enum: ["event", "schedule"], required: true },
  event: { type: String, enum: ALLOWED_EVENTS, default: null },
  cron:  { type: String, default: null }, // standard 5-field cron expression, e.g. "0 8 * * *"
}, { _id: false });

const workflowSchema = new mongoose.Schema({
  userId:      { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true, index: true },
  name:        { type: String, required: true, maxlength: 200 },
  description: { type: String, default: "", maxlength: 500 },
  active:      { type: Boolean, default: true },
  trigger:     { type: triggerSchema, required: true },
  actions: [{
    type:   { type: String, enum: ALLOWED_ACTIONS, required: true }, // safe here: this descriptor's `.type` resolves directly to String
    params: { type: mongoose.Schema.Types.Mixed, default: {} },
  }],
  lastRunAt:  { type: Date, default: null },
  nextRunAt:  { type: Date, default: null, index: true }, // only used for schedule-type triggers
  runCount:   { type: Number, default: 0 },
}, { timestamps: true });

workflowSchema.index({ userId: 1, active: 1 });
workflowSchema.index({ "trigger.type": 1, active: 1, nextRunAt: 1 });

export const ALLOWED_EVENT_TYPES = ALLOWED_EVENTS;
export const ALLOWED_ACTION_TYPES = ALLOWED_ACTIONS;
export default mongoose.models.Workflow || mongoose.model("Workflow", workflowSchema);
