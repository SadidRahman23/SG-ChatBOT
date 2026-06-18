// services/workflowEngine.js
// The Action Engine: executes a workflow's action list, and is the single place that knows how
// to fire an "event" trigger from anywhere else in the app.
//
// Design note: rather than importing the Note/Task/Goal/User models or sendEmail() directly (which
// would mean either duplicating their schemas here or creating a circular import with server.js,
// since those are defined inline in server.js), this module is given the models it needs via
// registerModels() once, at boot. This keeps server.js as the single source of truth for the
// existing schemas — nothing about them is duplicated or redefined.
import fetch from "node-fetch";
import Workflow from "../models/Workflow.js";
import WorkflowRun from "../models/WorkflowRun.js";

let registry = null; // { Note, Task, Goal, User, sendEmail }

export function registerModels(models) {
  registry = models;
}

async function runAction(action, userId, context) {
  if (!registry) throw new Error("workflowEngine.registerModels() was not called before runAction()");
  const { Note, Task, Goal, User, sendEmail } = registry;

  switch (action.type) {
    case "create_note": {
      const note = await Note.create({
        userId,
        title: String(action.params?.title || "Workflow note").slice(0, 200),
        content: String(action.params?.content || `Auto-created by a workflow.\n\nTrigger data: ${JSON.stringify(context).slice(0, 800)}`).slice(0, 50000),
        tags: ["workflow"],
      });
      return { type: "create_note", noteId: note._id };
    }
    case "create_task": {
      const task = await Task.create({
        userId,
        title: String(action.params?.title || "Workflow task").slice(0, 300),
        description: String(action.params?.description || "").slice(0, 2000),
        priority: action.params?.priority || "medium",
        dueDate: action.params?.dueInDays ? new Date(Date.now() + Number(action.params.dueInDays) * 86400000) : null,
      });
      return { type: "create_task", taskId: task._id };
    }
    case "create_goal": {
      const goal = await Goal.create({
        userId,
        title: String(action.params?.title || "Workflow goal").slice(0, 200),
        description: String(action.params?.description || "").slice(0, 2000),
      });
      return { type: "create_goal", goalId: goal._id };
    }
    case "send_email_summary": {
      const user = await User.findById(userId).select("email");
      if (!user) return { type: "send_email_summary", sent: false, reason: "user not found" };
      const safeBody = JSON.stringify(context, null, 2).slice(0, 3000).replace(/</g, "&lt;");
      const html = `<div style="font-family:sans-serif;max-width:520px;margin:0 auto;background:#0b0f17;color:#e4ecf7;padding:24px;border-radius:12px"><h2 style="margin-top:0">${String(action.params?.subject || "Workflow Summary").replace(/</g,"&lt;")}</h2><pre style="white-space:pre-wrap;font-size:13px;color:#8a9bb5">${safeBody}</pre></div>`;
      const ok = await sendEmail(user.email, action.params?.subject || "Your SG ChatBOT summary", html);
      return { type: "send_email_summary", sent: !!ok };
    }
    case "ai_generate_summary": {
      if (!process.env.OPENROUTER_KEY) return { type: "ai_generate_summary", error: "AI key not configured" };
      const prompt = action.params?.prompt || `Summarize this data for the user in 3-4 short, friendly sentences:\n${JSON.stringify(context).slice(0, 2000)}`;
      const r = await fetch("https://openrouter.ai/api/v1/chat/completions", {
        method: "POST",
        headers: { Authorization: `Bearer ${process.env.OPENROUTER_KEY}`, "Content-Type": "application/json" },
        body: JSON.stringify({ model: "google/gemini-2.5-flash:free", messages: [{ role: "user", content: prompt }], max_tokens: 400 }),
        signal: AbortSignal.timeout(20000),
      });
      const d = await r.json();
      const text = d?.choices?.[0]?.message?.content || "";
      return { type: "ai_generate_summary", summary: text };
    }
    default:
      return { type: action.type, error: "Unknown action type" };
  }
}

export async function runWorkflow(workflow, context = {}, triggeredBy = "event") {
  const results = [];
  let status = "success";
  for (const action of workflow.actions || []) {
    try {
      results.push(await runAction(action, workflow.userId, context));
    } catch (e) {
      status = "partial";
      results.push({ type: action.type, error: e.message });
    }
  }
  workflow.lastRunAt = new Date();
  workflow.runCount = (workflow.runCount || 0) + 1;
  await workflow.save().catch(() => {});
  await WorkflowRun.create({ workflowId: workflow._id, userId: workflow.userId, status, triggeredBy, results }).catch(() => {});
  return { status, results };
}

// Called from existing routes (goals/notes/tasks/habits) right after a record is created/completed.
// This is always invoked with .catch(()=>{}) by the caller — a workflow failure must never break
// the original request that triggered it.
export async function fireEvent(userId, eventName, payload = {}) {
  try {
    const workflows = await Workflow.find({ userId, active: true, "trigger.type": "event", "trigger.event": eventName }).limit(20);
    for (const wf of workflows) {
      await runWorkflow(wf, { event: eventName, data: payload }, "event").catch(() => {});
    }
  } catch (e) {
    console.error("fireEvent error:", e.message);
  }
}
