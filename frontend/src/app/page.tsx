"use client";

import { useCallback, useEffect, useRef, useState, type ReactNode } from "react";

const API = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

type Json = Record<string, unknown>;
type Result = { ok: boolean; status: number; body: Json };
type Tone = "green" | "red" | "yellow" | "neutral";
type Accent =
  | "identity" | "message" | "key" | "device" | "resilience" | "detection"
  | "result" | "route" | "alerts" | "state" | "integrity" | "raw";
type StepId =
  | "bootstrap" | "operator" | "admin" | "recipient" | "message" | "read"
  | "login-proof" | "recovery" | "enrol-proof" | "revoke" | "re-enrol"
  | "resilience" | "detection";

const STEPS: { id: StepId; label: string }[] = [
  { id: "bootstrap", label: "Fresh state" },
  { id: "operator", label: "Operator session" },
  { id: "admin", label: "Admin session" },
  { id: "recipient", label: "Recipient session" },
  { id: "message", label: "Message sent" },
  { id: "read", label: "Message read" },
  { id: "login-proof", label: "Recovery proof" },
  { id: "recovery", label: "Recovery session" },
  { id: "enrol-proof", label: "Re-enrol proof" },
  { id: "revoke", label: "Device revoked" },
  { id: "re-enrol", label: "Device re-enrolled" },
  { id: "resilience", label: "Resilience checks" },
  { id: "detection", label: "Detector run" },
];

// Never rendered and never stored in state. Opaque handles and secrets only.
const REDACTED_KEYS = new Set([
  "reference", "token", "recovery_proof", "proof", "private_key",
  "dsa_sk", "kem_sk", "session_key", "resumption_secret",
]);

async function api(path: string, options: {
  method?: string;
  body?: Json;
  token?: string;
} = {}): Promise<Result> {
  try {
    const headers: Record<string, string> = { "Content-Type": "application/json" };
    if (options.token) headers.Authorization = `Bearer ${options.token}`;
    const response = await fetch(`${API}${path}`, {
      method: options.method || "GET",
      headers,
      body: options.body ? JSON.stringify(options.body) : undefined,
    });
    const raw = await response.text();
    let parsed: unknown = null;
    try {
      parsed = raw ? JSON.parse(raw) : null;
    } catch {
      parsed = null;
    }
    const body: Json = parsed && typeof parsed === "object" && !Array.isArray(parsed)
      ? (parsed as Json)
      : { error: "invalid_request", note: "non_json_response" };
    return { ok: response.ok, status: response.status, body };
  } catch {
    return {
      ok: false,
      status: 0,
      body: { error: "invalid_request", note: "network_failure" },
    };
  }
}

function asRecord(value: unknown): Json {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Json)
    : {};
}

function items(value: unknown): Json[] {
  return Array.isArray(value) ? value.map(asRecord) : [];
}

function strings(value: unknown): string[] {
  return Array.isArray(value)
    ? value.map((entry) => text(entry, "")).filter(Boolean)
    : [];
}

function clip(value: string, max = 120): string {
  return value.length > max ? `${value.slice(0, max)}…` : value;
}

function text(value: unknown, fallback = "—"): string {
  if (value === null || value === undefined || value === "") return fallback;
  if (typeof value === "string") return clip(value);
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  if (Array.isArray(value)) {
    return clip(value.map((entry) => text(entry, "")).filter(Boolean).join(", ") || fallback);
  }
  try {
    return clip(JSON.stringify(value));
  } catch {
    return fallback;
  }
}

function redact(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(redact);
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Json)
        .filter(([key]) => !REDACTED_KEYS.has(key.toLowerCase()))
        .map(([key, nested]) => [key, redact(nested)]),
    );
  }
  return value;
}

function redactRecord(value: Json): Json {
  return redact(value) as Json;
}

function verdict(body: Json): { label: string; tone: Tone } {
  const error = text(body.error, "");
  if (error) {
    if (error === "revoked") return { label: "REVOKED", tone: "red" };
    if (error === "backup_corrupt" || error === "log_tampered") {
      return { label: "TAMPERED", tone: "red" };
    }
    if (error === "key_expired") return { label: "FAILED", tone: "yellow" };
    return { label: "DENIED", tone: "red" };
  }
  const integrity = text(body.integrity_status, "").toLowerCase();
  if (integrity === "verified") return { label: "VERIFIED", tone: "green" };
  if (integrity === "tampered") return { label: "TAMPERED", tone: "red" };
  const decision = text(body.decision, "").toLowerCase();
  if (decision === "allow") {
    if (body.grace_applies === true || text(body.outcome, "").toLowerCase() === "grace") {
      return { label: "ALLOWED (grace)", tone: "yellow" };
    }
    return { label: "ALLOWED", tone: "green" };
  }
  if (decision === "deny") return { label: "DENIED", tone: "red" };
  const status = text(body.status, "").toLowerCase();
  if (status === "verified") return { label: "VERIFIED", tone: "green" };
  if (status === "pending" || status === "uncertain") {
    return { label: "PENDING", tone: "yellow" };
  }
  if (Object.keys(body).length === 0 || (Object.keys(body).length === 1 && "note" in body)) {
    return { label: "NO RESULT YET", tone: "neutral" };
  }
  return { label: "COMPLETED", tone: "green" };
}

function explain(body: Json): string {
  if (Object.keys(body).length === 0) return "No action yet. Start with Reset demo state.";
  const action = text(body.action, "Action");
  const error = text(body.error, "");
  if (error === "invalid_message") {
    return `${action} was refused: the Message ID is unknown, belongs to another recipient, or was already read. Send a new message; each envelope can be read once.`;
  }
  if (error) return `${action} was refused by the engine: ${error}.`;
  const reason = text(body.reason ?? body.status, "");
  if (reason !== "—") return `${action}: ${reason}.`;
  return `${action} completed with HTTP ${text(body.http_status, "unknown")}.`;
}

const TONE_CLASS: Record<Tone, string> = {
  green: "border-emerald-700 bg-emerald-100 text-emerald-950",
  red: "border-rose-700 bg-rose-100 text-rose-950",
  yellow: "border-amber-700 bg-amber-100 text-amber-950",
  neutral: "border-stone-300 bg-stone-100 text-stone-700",
};

const ACCENT_CLASS: Record<Accent, string> = {
  identity: "border-amber-300 bg-amber-100 text-amber-950",
  message: "border-sky-300 bg-sky-100 text-sky-950",
  key: "border-emerald-300 bg-emerald-100 text-emerald-950",
  device: "border-violet-300 bg-violet-100 text-violet-950",
  resilience: "border-teal-300 bg-teal-100 text-teal-950",
  detection: "border-rose-300 bg-rose-100 text-rose-950",
  result: "border-stone-300 bg-stone-100 text-stone-900",
  route: "border-sky-300 bg-sky-50 text-sky-950",
  alerts: "border-rose-300 bg-rose-50 text-rose-950",
  state: "border-emerald-300 bg-emerald-50 text-emerald-950",
  integrity: "border-violet-300 bg-violet-50 text-violet-950",
  raw: "border-stone-300 bg-stone-50 text-stone-900",
};

function Card({ title, accent, note, children }: {
  title: string;
  accent: Accent;
  note?: string;
  children: ReactNode;
}) {
  return (
    <section className="min-w-0 rounded-sm border-2 border-stone-800 bg-[#fffdf8] p-2.5 shadow-[2px_2px_0px_#d8cdb8]">
      <h2 className={`mb-1.5 border-b-2 px-1.5 py-1 text-[11px] font-bold uppercase tracking-wide ${ACCENT_CLASS[accent]}`}>
        {title}
      </h2>
      {note && <p className="mb-1.5 text-[10px] leading-tight text-stone-600">{note}</p>}
      <div className="min-w-0 space-y-1.5">{children}</div>
    </section>
  );
}

function Field({ label, value, onChange, secret = false, mono = false }: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  secret?: boolean;
  mono?: boolean;
}) {
  return (
    <label className="block min-w-0 text-[11px]">
      <span className="mb-0.5 block font-semibold leading-tight text-stone-600">{label}</span>
      <input
        className={`w-full min-w-0 rounded-sm border border-stone-700 bg-white px-1.5 py-1 text-xs focus:outline-none focus:ring-1 focus:ring-amber-400 ${mono ? "font-mono text-[10px]" : ""}`}
        type={secret ? "password" : "text"}
        autoComplete="off"
        spellCheck={false}
        value={value}
        onChange={(event) => onChange(event.target.value)}
      />
    </label>
  );
}

type Variant = "light" | "primary" | "danger";

function Button({ children, onClick, disabled = false, variant = "light" }: {
  children: ReactNode;
  onClick: () => unknown;
  disabled?: boolean;
  variant?: Variant;
}) {
  const tone = variant === "primary"
    ? "border-stone-900 bg-stone-900 text-white hover:bg-stone-700"
    : variant === "danger"
      ? "border-rose-700 bg-white text-rose-700 hover:bg-rose-100"
      : "border-stone-800 bg-white text-stone-900 hover:border-amber-700 hover:bg-amber-100";
  return (
    <button
      type="button"
      disabled={disabled}
      onClick={() => void onClick()}
      className={`cursor-pointer rounded-sm border px-2 py-1 text-[11px] font-semibold focus:outline-none focus:ring-1 focus:ring-amber-400 disabled:cursor-not-allowed disabled:opacity-40 ${tone}`}
    >
      {children}
    </button>
  );
}

function Row({ label, value, mono = true }: { label: string; value: unknown; mono?: boolean }) {
  return (
    <div className="flex min-w-0 items-start justify-between gap-2 border-b border-stone-200 py-0.5 text-[11px] last:border-b-0">
      <span className="shrink-0 text-stone-600">{label}</span>
      <span className={`min-w-0 break-words text-right ${mono ? "font-mono text-[10px]" : ""}`}>
        {text(value)}
      </span>
    </div>
  );
}

function Rows({ children }: { children: ReactNode }) {
  return <div className="min-w-0">{children}</div>;
}

function StepStrip({ completed, next, busy, canRun, onRun }: {
  completed: StepId[];
  next?: { id: StepId; label: string };
  busy: string;
  canRun: (id: StepId) => boolean;
  onRun: (id: StepId) => void;
}) {
  return (
    <div className="border border-stone-300 bg-white p-1.5 text-[10px]">
      <div className="flex justify-between gap-2 font-semibold">
        <span>Progress: {completed.length}/{STEPS.length}</span>
        <span className="truncate text-right text-stone-600">
          Next: {next ? next.label : "all done"}
        </span>
      </div>
      <div className="mt-1 flex flex-wrap items-center gap-1">
        {STEPS.map((step) => {
          const done = completed.includes(step.id);
          const ready = canRun(step.id);
          return (
            <button
              key={step.id}
              type="button"
              disabled={done || Boolean(busy) || !ready}
              onClick={() => void onRun(step.id)}
              aria-label={done ? `${step.label} already completed` : `Run ${step.label}`}
              className={`border px-1 py-0.5 text-left ${done
                ? "border-emerald-700 bg-emerald-100 text-emerald-950"
                : ready && !busy
                  ? "cursor-pointer border-stone-400 bg-white text-stone-800 hover:border-amber-700 hover:bg-amber-50 focus:outline-none focus:ring-1 focus:ring-amber-400"
                  : "border-stone-300 bg-stone-50 text-stone-400"}`}
            >
              {done ? "done" : "todo"} · {step.label}
            </button>
          );
        })}
        <Button
          disabled={!next || Boolean(busy) || !canRun(next.id)}
          onClick={() => { if (next) void onRun(next.id); }}
        >
          Run next
        </Button>
      </div>
    </div>
  );
}

export default function Home() {
  // Opaque handles only. They stay in memory and are never rendered.
  const [reference, setReference] = useState("");
  const [adminReference, setAdminReference] = useState("");
  const [recipientReference, setRecipientReference] = useState("");
  const [recoveryReference, setRecoveryReference] = useState("");
  const [completed, setCompleted] = useState<StepId[]>([]);

  const [username, setUsername] = useState("user-alex");
  const [deviceId, setDeviceId] = useState("device-alex");
  const [recoveryUsername, setRecoveryUsername] = useState("recovery-user-blair");
  const [recoveryProof, setRecoveryProof] = useState("");
  const [sender, setSender] = useState("user-alex");
  const [recipient, setRecipient] = useState("user-blair");
  const [plaintext, setPlaintext] = useState("");
  const [messageId, setMessageId] = useState("");
  const [targetUser, setTargetUser] = useState("user-blair");
  const [targetDevice, setTargetDevice] = useState("device-blair");
  const [newDevice, setNewDevice] = useState("device-blair-replacement");
  const [enrolProof, setEnrolProof] = useState("");

  const [status, setStatus] = useState<Json>({});
  const [alerts, setAlerts] = useState<Json>({});
  const [latest, setLatest] = useState<Json>({ note: "No action yet. Start with Reset demo state." });
  const [message, setMessage] = useState<Json>({});
  const [integrity, setIntegrity] = useState<Json>({});
  const [busy, setBusy] = useState("");
  const busyRef = useRef(false);

  const mark = useCallback((id: StepId) => {
    setCompleted((previous) =>
      previous.includes(id) ? previous : [...previous, id]);
  }, []);

  const noteAction = useCallback((label: string, path: string, result: Result) => {
    const body: Json = redactRecord({
      ...result.body,
      action: label,
      endpoint: path,
      http_status: result.status,
      http_ok: result.ok,
    });
    setLatest(body);
    if ("route" in body || "policy_decisions" in body) setMessage(body);
    if ("integrity_status" in body) {
      setIntegrity((previous) => ({ ...previous, audit: body }));
    }
    if ("backup_created" in body || "detection" in body) {
      setIntegrity((previous) => ({ ...previous, backup: body }));
    }
    if ("mutation_type" in body) {
      setIntegrity((previous) => ({ ...previous, log: body }));
    }
  }, []);

  const refresh = useCallback(async () => {
    const [statusResult, alertsResult, auditResult] = await Promise.all([
      api("/api/status"),
      api("/api/detector/alerts"),
      api("/api/audit/verify"),
    ]);
    setStatus(statusResult.body);
    setAlerts(alertsResult.body);
    setIntegrity((previous) => ({ ...previous, audit: auditResult.body }));
    if (statusResult.ok && items(statusResult.body.users).length > 0) mark("bootstrap");
  }, [mark]);

  useEffect(() => {
    let active = true;
    queueMicrotask(() => {
      if (active) void refresh();
    });
    return () => { active = false; };
  }, [refresh]);

  // A ref lock prevents a double click from starting two engine operations.
  const act = useCallback(async (
    label: string,
    fn: () => Promise<Result | void>,
    step?: StepId,
  ) => {
    if (busyRef.current) return;
    busyRef.current = true;
    setBusy(label);
    try {
      const result = await fn();
      if (result && result.ok && step) mark(step);
      await refresh();
    } finally {
      busyRef.current = false;
      setBusy("");
    }
  }, [mark, refresh]);

  const call = useCallback((
    label: string,
    path: string,
    body: Json = {},
    token = "",
    step?: StepId,
  ) => act(label, async () => {
    const result = await api(path, { method: "POST", body, token });
    noteAction(label, path, result);
    return result;
  }, step), [act, noteAction]);

  const login = useCallback((
    label: string,
    user: string,
    device: string,
    onRef: (value: string) => void,
    step: StepId,
  ) => act(label, async () => {
    const result = await api("/api/login", {
      method: "POST",
      body: { username: user, device_id: device },
    });
    if (typeof result.body.reference === "string") onRef(result.body.reference);
    noteAction(label, "/api/login", result);
    return result;
  }, step), [act, noteAction]);

  const sendMessage = useCallback(() => act("Send encrypted message", async () => {
    const result = await api("/api/messages/send", {
      method: "POST",
      body: { token: reference, sender, recipient, plaintext },
      token: reference,
    });
    if (result.body.message_id !== undefined) {
      setMessageId(String(result.body.message_id));
    }
    noteAction("Send encrypted message", "/api/messages/send", result);
    return result;
  }, "message"), [act, noteAction, reference, sender, recipient, plaintext]);

  const resetDemo = () => act("Reset demo state", async () => {
    const result = await api("/api/demo/reset", { method: "POST", body: {} });
    if (result.ok) {
      setReference("");
      setAdminReference("");
      setRecipientReference("");
      setRecoveryReference("");
      setRecoveryProof("");
      setEnrolProof("");
      setMessageId("");
      setMessage({});
      setCompleted([]);
    }
    noteAction("Reset demo state", "/api/demo/reset", result);
    return result;
  }, "bootstrap");

  const demoLoginProof = () => act("Generate demo login proof", async () => {
    const result = await api("/api/demo/recovery-proof", {
      method: "POST",
      body: { purpose: "login", recovery_username: recoveryUsername },
    });
    if (typeof result.body.proof === "string") setRecoveryProof(result.body.proof);
    noteAction("Generate demo login proof", "/api/demo/recovery-proof", result);
    return result;
  }, "login-proof");

  const demoEnrolProof = () => act("Generate demo re-enrol proof", async () => {
    const result = await api("/api/demo/recovery-proof", {
      method: "POST",
      body: { purpose: "enrol", target_user: targetUser, new_device: newDevice },
    });
    if (typeof result.body.proof === "string") setEnrolProof(result.body.proof);
    noteAction("Generate demo re-enrol proof", "/api/demo/recovery-proof", result);
    return result;
  }, "enrol-proof");

  const recoveryLogin = () => act("Authenticate recovery identity", async () => {
    const result = await api("/api/login", {
      method: "POST",
      body: { username: recoveryUsername, recovery_proof: recoveryProof },
    });
    if (typeof result.body.reference === "string") setRecoveryReference(result.body.reference);
    if (result.ok) setRecoveryProof("");
    noteAction("Authenticate recovery identity", "/api/login", result);
    return result;
  }, "recovery");

  const reEnrol = () => act("Re-enrol replacement device", async () => {
    const result = await api("/api/recovery/enroll-device", {
      method: "POST",
      body: {
        token: recoveryReference,
        target_user: targetUser,
        new_device: newDevice,
        recovery_proof: enrolProof,
      },
    });
    if (result.ok) setEnrolProof("");
    noteAction("Re-enrol replacement device", "/api/recovery/enroll-device", result);
    return result;
  }, "re-enrol");

  const read = () => act("Read message as recipient", async () => {
    const path = `/api/messages/${encodeURIComponent(messageId)}?recipient=${encodeURIComponent(recipient)}`;
    const result = await api(path, { token: recipientReference });
    noteAction("Read message as recipient", path, result);
    return result;
  }, "read");

  const verifyAudit = () => act("Verify audit log", async () => {
    const result = await api("/api/audit/verify");
    noteAction("Verify audit log", "/api/audit/verify", result);
    return result;
  });

  const refreshAlerts = () => act("Refresh alerts", async () => {
    const result = await api("/api/detector/alerts");
    setAlerts(result.body);
    noteAction("Refresh alerts", "/api/detector/alerts", result);
    return result;
  });

  const canRunStep = (id: StepId): boolean => {
    switch (id) {
      case "message": return Boolean(reference && plaintext);
      case "read": return Boolean(recipientReference && messageId);
      case "recovery": return Boolean(recoveryProof);
      case "revoke":
      case "resilience": return Boolean(adminReference);
      case "re-enrol": return Boolean(recoveryReference && enrolProof);
      default: return true;
    }
  };

  const runStep = (id: StepId) => {
    switch (id) {
      case "bootstrap": return resetDemo();
      case "operator": return login(
        "Authenticate operator", username, deviceId, setReference, "operator");
      case "admin": return login(
        "Authenticate admin", "user-admin", "device-admin", setAdminReference, "admin");
      case "recipient": return login(
        "Authenticate recipient", "user-blair", "device-blair", setRecipientReference, "recipient");
      case "message": return sendMessage();
      case "read": return read();
      case "login-proof": return demoLoginProof();
      case "recovery": return recoveryLogin();
      case "enrol-proof": return demoEnrolProof();
      case "revoke": return call("Revoke device", "/api/admin/revoke-device", {
        token: adminReference, target_user: targetUser, target_device: targetDevice,
      }, adminReference, "revoke");
      case "re-enrol": return reEnrol();
      case "resilience": return call("Crash-recovery test", "/api/admin/crash-recovery-test", {
        token: adminReference, target_device: targetDevice,
      }, adminReference, "resilience");
      case "detection": return call("Run detector", "/api/detector/run", {}, "", "detection");
    }
  };

  const nextStep = STEPS.find((step) => !completed.includes(step.id));
  const current = verdict(latest);
  const keyState = asRecord(status.key_versions);
  const revocationState = asRecord(status.revocations);
  const auditState = asRecord(integrity.audit);
  const backupState = asRecord(integrity.backup);
  const logState = asRecord(integrity.log);
  const policyDecisions = items(message.policy_decisions);
  const alertRows = items(alerts.alerts);
  const revokedDevices = strings(revocationState.devices);
  const recipientRevoked = revokedDevices.some((device) => device.includes("device-blair"));
  const rawPreview = clip(JSON.stringify(redact(latest), null, 2), 1200);

  return (
    <main className="mx-auto max-w-7xl p-6">
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-[3fr_1fr]">
        <section className="space-y-6">
          <div className="grid gap-3 lg:grid-cols-2">
            <Card
              title="Identity"
              accent="identity"
              note="Proves: the engine authenticates each identity and returns an opaque handle; no keys or proofs are shown."
            >
              {recipientRevoked && (
                <div className="border border-rose-300 bg-rose-50 p-1.5 text-[10px] text-rose-950">
                  <p className="font-bold">Stale demo state: device-blair is revoked.</p>
                  <p>Recipient sign-in will return HTTP 403 / revoked until you reset.</p>
                  <div className="mt-1"><Button variant="danger" onClick={resetDemo}>Reset demo state</Button></div>
                </div>
              )}
              <div className="grid gap-1.5 sm:grid-cols-2">
                <Field label="Username" value={username} onChange={setUsername} mono />
                <Field label="Device ID" value={deviceId} onChange={setDeviceId} mono />
                <Field label="Recovery username" value={recoveryUsername}
                       onChange={setRecoveryUsername} mono />
                <Field label="Recovery proof" value={recoveryProof}
                       onChange={setRecoveryProof} secret mono />
              </div>
              <div className="flex flex-wrap gap-1">
                <Button variant="primary" onClick={() => login(
                  "Authenticate operator", username, deviceId, setReference, "operator")}>
                  Authenticate operator
                </Button>
                <Button onClick={() => login(
                  "Authenticate admin", "user-admin", "device-admin",
                  setAdminReference, "admin")}>
                  Authenticate admin
                </Button>
                <Button onClick={() => login(
                  "Authenticate recipient", "user-blair", "device-blair",
                  setRecipientReference, "recipient")}>
                  Authenticate recipient
                </Button>
                <Button onClick={() => call("Initialise demo state", "/api/demo/setup", {}, "", "bootstrap")}>
                  Setup
                </Button>
                <Button variant="danger" onClick={resetDemo}>Reset demo state</Button>
                <Button onClick={demoLoginProof}>Login proof</Button>
                <Button variant="primary" disabled={!recoveryProof} onClick={recoveryLogin}>
                  Recovery
                </Button>
              </div>
              <p className="text-[10px] text-stone-600">
                Operator: {reference ? "active" : "none"} · Admin: {adminReference ? "active" : "none"}
                {" "}· Recipient: {recipientReference ? "active" : "none"} · Recovery: {recoveryReference ? "active" : "none"}
              </p>
            </Card>

            <Card
              title="Secure message"
              accent="message"
              note="Proves: an encrypted envelope passes node-a/b/c policy checks; only the bound recipient can read it."
            >
              <div className="grid gap-1.5 sm:grid-cols-2">
                <Field label="Sender" value={sender} onChange={setSender} mono />
                <Field label="Recipient" value={recipient} onChange={setRecipient} mono />
                <Field label="Message text" value={plaintext} onChange={setPlaintext} />
                <Field label="Message ID for read" value={messageId}
                       onChange={setMessageId} mono />
              </div>
              <div className="flex flex-wrap gap-1">
                <Button variant="primary" disabled={!reference || !plaintext} onClick={sendMessage}>
                  Send encrypted message
                </Button>
                <Button disabled={!recipientReference || !messageId} onClick={read}>
                  Read as recipient
                </Button>
              </div>
              <p className="text-[10px] text-stone-600">
                The Message ID is filled in automatically after sending. Authenticate Recipient,
                then read once; a second read is refused as a replay.
              </p>
            </Card>

            <Card
              title="Key lifecycle"
              accent="key"
              note="Proves: rotation creates a new active key version and a grace window for the old key."
            >
              <div className="flex flex-wrap items-end gap-2">
                <div className="min-w-[9rem] flex-1">
                  <Field label="Target user" value={targetUser} onChange={setTargetUser} mono />
                </div>
                <Button disabled={!adminReference} onClick={() =>
                  call("Rotate key", "/api/admin/rotate-key", {
                    token: adminReference, target_user: targetUser,
                  }, adminReference)}>
                  Rotate key
                </Button>
              </div>
              <Rows>
                <Row label="Active version" value={keyState.active} />
                <Row label="Grace deadline" value={keyState.grace_until} />
                <Row label="Old-key cutoff" value={keyState.old_key_cutoff} />
              </Rows>
            </Card>

            <Card
              title="Device lifecycle"
              accent="device"
              note="Proves: revocation is enforced on every node; re-enrol needs recovery proof, not the lost key."
            >
              <div className="grid gap-1.5 sm:grid-cols-3">
                <Field label="Target user" value={targetUser} onChange={setTargetUser} mono />
                <Field label="Target device" value={targetDevice} onChange={setTargetDevice} mono />
                <Field label="Replacement" value={newDevice} onChange={setNewDevice} mono />
              </div>
              <Field label="Re-enrol proof" value={enrolProof} onChange={setEnrolProof} secret mono />
              <div className="flex flex-wrap gap-1">
                <Button onClick={demoEnrolProof}>Enrol proof</Button>
                <Button variant="danger" disabled={!adminReference} onClick={() =>
                  call("Revoke device", "/api/admin/revoke-device", {
                    token: adminReference, target_user: targetUser,
                    target_device: targetDevice,
                  }, adminReference, "revoke")}>
                  Revoke device
                </Button>
                <Button variant="primary" disabled={!recoveryReference || !enrolProof} onClick={reEnrol}>
                  Re-enrol
                </Button>
              </div>
              <p className="text-[10px] text-stone-600">
                Order: enrol proof → revoke device → re-enrol with recovery session.
              </p>
            </Card>

            <Card
              title="Resilience checks"
              accent="resilience"
              note="Proves: interrupted rotation, damaged backup and tampered log are detected and fail closed."
            >
              <div className="flex flex-wrap gap-1">
                <Button disabled={!adminReference} onClick={() =>
                  call("Crash-recovery test", "/api/admin/crash-recovery-test", {
                    token: adminReference, target_device: targetDevice,
                  }, adminReference, "resilience")}>
                  Crash recovery
                </Button>
                <Button disabled={!adminReference} onClick={() =>
                  call("Backup-integrity test", "/api/admin/backup-integrity-test", {
                    token: adminReference,
                  }, adminReference, "resilience")}>
                  Backup integrity
                </Button>
                <Button disabled={!adminReference} onClick={() =>
                  call("Log-integrity test", "/api/admin/log-integrity-test", {
                    token: adminReference,
                  }, adminReference, "resilience")}>
                  Log integrity
                </Button>
                <Button onClick={verifyAudit}>Verify audit</Button>
              </div>
            </Card>

            <Card
              title="Detection"
              accent="detection"
              note="Proves: live audit events produce alerts; the labelled practice set produces measured metrics."
            >
              <div className="flex flex-wrap gap-1">
                <Button variant="primary" onClick={() =>
                  call("Run detector", "/api/detector/run", {}, "", "detection")}>
                  Run detector
                </Button>
                <Button onClick={refreshAlerts}>Refresh alerts</Button>
              </div>
              <Rows>
                <Row label="Alert count" value={text(alerts.count ?? alertRows.length)} />
                <Row label="Dataset size" value={asRecord(status.detector_metrics).dataset_size} />
              </Rows>
            </Card>
          </div>
        </section>

        <aside className="space-y-4">
          <Card
            title="Latest result"
            accent="result"
            note="Engine response from the last click. Green = allowed, red = engine refused."
          >
            <div className={`border-2 px-2 py-1.5 text-lg font-black tracking-tight ${TONE_CLASS[current.tone]}`}>
              {current.label}
            </div>
            {busy && <p className="text-[10px] font-semibold text-amber-800">Working: {busy}</p>}
            <p className="border border-stone-300 bg-white px-1.5 py-1 text-[10px] text-stone-700">
              {explain(latest)}
            </p>
            <Rows>
              <Row label="Action" value={latest.action || "initial page load"} mono={false} />
              <Row label="Endpoint" value={latest.endpoint} />
              <Row label="HTTP" value={latest.http_status} />
              <Row label="Reason" value={latest.reason || latest.status} />
              <Row label="Safe error" value={latest.error} />
              <Row label="Identity" value={latest.identity} />
              <Row label="Device" value={latest.device} />
            </Rows>
            <StepStrip
              completed={completed}
              next={nextStep}
              busy={busy}
              canRun={canRunStep}
              onRun={runStep}
            />
          </Card>

          <Card
            title="Message route"
            accent="route"
            note="Produced by the engine; envelope bytes and keys are never shown."
          >
            <Rows>
              <Row label="Message ID" value={message.message_id} />
              <Row label="Route" value={strings(message.route).join(" → ")} mono />
              <Row label="Delivery" value={message.status || message.delivery_status} />
              <Row label="Replay" value={message.replay_result} />
              <Row label="Recipient binding" value={message.recipient_binding_result} />
              <Row label="Policy" value={policyDecisions.map((decision) =>
                `${text(decision.node)}=${text(decision.decision)}`).join(", ")} />
            </Rows>
          </Card>

          <Card
            title="Alerts"
            accent="alerts"
            note="Live detector alerts from the engine's audit log."
          >
            <p className="text-[10px]">
              <span className="font-semibold">Count:</span> {text(alerts.count ?? alertRows.length)}
            </p>
            {alertRows.length === 0 ? (
              <p className="text-[10px] text-stone-600">No alerts yet.</p>
            ) : alertRows.slice(0, 3).map((alert, index) => (
              <p key={`alert-${index}`} className="border-b border-stone-200 py-0.5 text-[10px] last:border-b-0">
                <span className="font-semibold">{text(alert.alert)}</span>
                {" — "}{text(alert.explanation)}
              </p>
            ))}
          </Card>

          <Card
            title="Key / revocation state"
            accent="state"
            note="Read-only projection from the engine's status operation."
          >
            <Rows>
              <Row label="Active key" value={keyState.active} />
              <Row label="Epoch" value={revocationState.epoch} />
              <Row label="Revoked" value={revokedDevices} />
              <Row label="Nodes" value={items(status.nodes).map((node) =>
                `${text(node.node)}=${text(node.last_enforced_revocation)}s`).join(", ")} />
            </Rows>
          </Card>

          <Card
            title="Integrity"
            accent="integrity"
            note="Audit, backup and log verifiers are all engine operations."
          >
            <Rows>
              <Row label="Audit" value={auditState.integrity_status || text(auditState.valid)} />
              <Row label="Events" value={auditState.event_count} />
              <Row label="Backup" value={backupState.detection ||
                (backupState.restore_rejected === true ? "verified" : undefined)} />
              <Row label="Log mutation" value={logState.mutation_type} />
            </Rows>
          </Card>

          <details className="rounded-sm border-2 border-stone-300 bg-white p-2">
            <summary className="cursor-pointer text-[11px] font-bold uppercase text-stone-700 focus:outline-none focus:ring-1 focus:ring-amber-400">
              Raw API response
            </summary>
            <pre className="mt-1 whitespace-pre-wrap break-words font-mono text-[9px] text-stone-700">
              {rawPreview}
            </pre>
          </details>
        </aside>
      </div>
    </main>
  );
}
