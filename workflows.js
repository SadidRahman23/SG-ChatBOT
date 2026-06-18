// routes/workflows.js
// Mounted at /workflows in server.js. Exported as a factory function that takes the existing
// auth/checkBlocked/apiLimiter/sanitize from server.js as dependencies, rather than re-implementing
// JWT verification or input sanitizing here — reusing exactly the same middleware server.js's other
// routes use, with zero duplicated logic.
import express from "express";
import fetch from "node-fetch";
import Workflow, { ALLOWED_EVENT_TYPES, ALLOWED_ACTION_TYPES } from "../models/Workflow.js";
import WorkflowRun from "../models/WorkflowRun.js";
import { runWorkflow } from "../services/workflowEngine.js";
import { computeNextRun, isValidCron } from "../services/scheduler.js";

function validateTriggerAndActions(trigger, actions) {
  if (!trigger || !["event", "schedule"].includes(trigger.type)) return "trigger.type must be 'event' or 'schedule'";
  if (trigger.type === "event" && !ALLOWED_EVENT_TYPES.includes(trigger.event)) return `trigger.event must be one of: ${ALLOWED_EVENT_TYPES.join(", ")}`;
  if (trigger.type === "schedule" && !isValidCron(trigger.cron)) return "trigger.cron must be a valid 5-field cron expression";
  if (!Array.isArray(actions) || !actions.length) return "actions must be a non-empty array";
  if (actions.length > 10) return "A workflow can have at most 10 actions";
  for (const a of actions) if (!ALLOWED_ACTION_TYPES.includes(a?.type)) return `Unknown action type: ${a?.type}`;
  return null;
}

export default function createWorkflowRouter({ auth, checkBlocked, apiLimiter, sanitize }) {
  const router = express.Router();

  router.get("/", auth, checkBlocked, apiLimiter, async (req, res) => {
    try {
      const workflows = await Workflow.find({ userId: req.user.id }).sort({ updatedAt: -1 });
      res.json(workflows);
    } catch { res.status(500).json({ message: "Error" }); }
  });

  router.post("/", auth, checkBlocked, apiLimiter, async (req, res) => {
    try {
      const { name, description, trigger, actions } = req.body;
      if (!name) return res.status(400).json({ message: "name is required" });
      const validationError = validateTriggerAndActions(trigger, actions);
      if (validationError) return res.status(400).json({ message: validationError });
      const wf = await Workflow.create({
        userId: req.user.id,
        name: sanitize(name).slice(0, 200),
        description: sanitize(description || "").slice(0, 500),
        trigger,
        actions: actions.slice(0, 10),
        nextRunAt: trigger.type === "schedule" ? computeNextRun(trigger.cron) : null,
      });
      res.json(wf);
    } catch { res.status(500).json({ message: "Error creating workflow" }); }
  });

  router.put("/:id", auth, checkBlocked, apiLimiter, async (req, res) => {
    try {
      const wf = await Workflow.findOne({ _id: req.params.id, userId: req.user.id });
      if (!wf) return res.status(404).json({ message: "Not found" });
      const nextTrigger = req.body.trigger !== undefined ? req.body.trigger : wf.trigger;
      const nextActions = req.body.actions !== undefined ? req.body.actions : wf.actions;
      if (req.body.trigger !== undefined || req.body.actions !== undefined) {
        const validationError = validateTriggerAndActions(nextTrigger, nextActions);
        if (validationError) return res.status(400).json({ message: validationError });
      }
      if (req.body.name !== undefined) wf.name = sanitize(req.body.name).slice(0, 200);
      if (req.body.description !== undefined) wf.description = sanitize(req.body.description).slice(0, 500);
      if (req.body.active !== undefined) wf.active = !!req.body.active;
      if (req.body.trigger !== undefined) wf.trigger = req.body.trigger;
      if (req.body.actions !== undefined) wf.actions = req.body.actions.slice(0, 10);
      wf.nextRunAt = wf.trigger.type === "schedule" ? computeNextRun(wf.trigger.cron) : null;
      await wf.save();
      res.json(wf);
    } catch { res.status(500).json({ message: "Error" }); }
  });

  router.delete("/:id", auth, checkBlocked, apiLimiter, async (req, res) => {
    try {
      await Workflow.findOneAndDelete({ _id: req.params.id, userId: req.user.id });
      await WorkflowRun.deleteMany({ workflowId: req.params.id, userId: req.user.id });
      res.json({ message: "Deleted" });
    } catch { res.status(500).json({ message: "Error" }); }
  });

  router.post("/:id/run", auth, checkBlocked, apiLimiter, async (req, res) => {
    try {
      const wf = await Workflow.findOne({ _id: req.params.id, userId: req.user.id });
      if (!wf) return res.status(404).json({ message: "Not found" });
      const result = await runWorkflow(wf, { manual: true, triggeredAt: new Date().toISOString() }, "manual");
      res.json(result);
    } catch { res.status(500).json({ message: "Run failed" }); }
  });

  router.get("/:id/history", auth, checkBlocked, apiLimiter, async (req, res) => {
    try {
      const runs = await WorkflowRun.find({ workflowId: req.params.id, userId: req.user.id }).sort({ createdAt: -1 }).limit(50);
      res.json(runs);
    } catch { res.status(500).json({ message: "Error" }); }
  });

  // Turns a plain-English request (e.g. "every day remind me to study") into a ready-to-save
  // workflow JSON. Returns a *suggestion* only — the frontend still calls POST / to actually save it.
  router.post("/ai-suggest", auth, checkBlocked, apiLimiter, async (req, res) => {
    try {
      const { description } = req.body;
      if (!description || typeof description !== "string") return res.status(400).json({ message: "description is required" });
      if (!process.env.OPENROUTER_KEY) return res.status(503).json({ message: "AI suggestions are not configured on this server." });

      const prompt = `Convert this automation request into a single JSON workflow object.
Allowed trigger.type: "event" or "schedule".
If "event": trigger.event must be one of: ${ALLOWED_EVENT_TYPES.join(", ")}.
If "schedule": trigger.cron must be a standard 5-field cron expression (minute hour day month weekday), e.g. "0 8 * * *" for daily at 8am, or "0 9 * * 1" for every Monday at 9am.
Allowed action types: ${ALLOWED_ACTION_TYPES.join(", ")}.
Return ONLY raw JSON (no markdown fences, no commentary) matching exactly:
{"name":string,"description":string,"trigger":{"type":"event"|"schedule","event":string|null,"cron":string|null},"actions":[{"type":string,"params":object}]}
Request: "${sanitize(description).slice(0, 300)}"`;

      const r = await fetch("https://openrouter.ai/api/v1/chat/completions", {
        method: "POST",
        headers: { Authorization: `Bearer ${process.env.OPENROUTER_KEY}`, "Content-Type": "application/json" },
        body: JSON.stringify({ model: "google/gemini-2.5-flash:free", messages: [{ role: "user", content: prompt }], max_tokens: 500 }),
        signal: AbortSignal.timeout(20000),
      });
      const d = await r.json();
      let raw = d?.choices?.[0]?.message?.content || "{}";
      raw = raw.replace(/```json|```/g, "").trim();
      const suggestion = JSON.parse(raw);

      const validationError = validateTriggerAndActions(suggestion.trigger, suggestion.actions);
      if (validationError) return res.status(502).json({ message: `AI suggestion failed validation: ${validationError}`, raw: suggestion });

      res.json({ suggestion });
    } catch {
      res.status(500).json({ message: "Could not generate a suggestion. Try rephrasing your request." });
    }
  });

  return router;
}
