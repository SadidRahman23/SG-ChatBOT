// services/scheduler.js
// Drives "schedule"-type workflow triggers (e.g. "every day at 8am", "every Monday at 9am").
//
// Design note: instead of registering one `node-cron` job per workflow (which lives only in
// memory and would silently vanish on every restart/redeploy — a real risk on Render, which
// restarts free-tier instances often), we register a SINGLE cron job that ticks every minute and
// asks MongoDB which workflows are due (`nextRunAt <= now`). `nextRunAt` is persisted on the
// Workflow document itself, so scheduling survives restarts with no extra infrastructure.
import cron from "node-cron";
import Workflow from "../models/Workflow.js";
import { runWorkflow } from "./workflowEngine.js";

let started = false;

// Minimal "next run" calculator covering the common patterns (daily at HH:MM, weekly on a given
// day at HH:MM, which is what the AI-suggestion endpoint generates). It intentionally does not
// support full cron range/step syntax — workflows using more exotic expressions will still be
// *validated* (see isValidCron) but should be tested after creation to confirm nextRunAt looks right.
export function computeNextRun(cronExpr, from = new Date()) {
  const fields = String(cronExpr || "0 8 * * *").trim().split(/\s+/);
  const [minStr, hourStr, , , dowStr] = fields;
  const min = parseInt(minStr, 10);
  const hour = parseInt(hourStr, 10);
  const next = new Date(from);
  next.setSeconds(0, 0);
  next.setHours(Number.isNaN(hour) ? 8 : hour, Number.isNaN(min) ? 0 : min, 0, 0);

  if (dowStr && dowStr !== "*") {
    const targetDow = parseInt(dowStr, 10);
    if (!Number.isNaN(targetDow)) {
      let diffDays = (targetDow - next.getDay() + 7) % 7;
      if (diffDays === 0 && next <= from) diffDays = 7;
      next.setDate(next.getDate() + diffDays);
      return next;
    }
  }
  if (next <= from) next.setDate(next.getDate() + 1);
  return next;
}

export function isValidCron(expr) {
  return typeof expr === "string" && cron.validate(expr.trim());
}

export function startScheduler() {
  if (started) return; // guard against double-start if this module is ever imported twice
  started = true;
  cron.schedule("* * * * *", async () => {
    try {
      const due = await Workflow.find({ active: true, "trigger.type": "schedule", nextRunAt: { $lte: new Date() } }).limit(50);
      for (const wf of due) {
        await runWorkflow(wf, { scheduledAt: new Date().toISOString() }, "schedule").catch(() => {});
        wf.nextRunAt = computeNextRun(wf.trigger.cron);
        await wf.save().catch(() => {});
      }
    } catch (e) {
      console.error("Scheduler tick error:", e.message);
    }
  });
  console.log("⏰ Workflow scheduler started (checking every minute)");
}
