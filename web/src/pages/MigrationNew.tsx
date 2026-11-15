import { useEffect, useRef, useState, type FormEvent } from "react";
import { ArrowRight, Loader2, OctagonAlert, RefreshCw, Server as ServerIcon, ShieldCheck } from "lucide-react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { useTranslation } from "react-i18next";
import { useApprove, useBuildPlan, usePreflight, useServers } from "@/api/hooks";
import { ApiError, type MigrationPlan, type PlanAction } from "@/api/types";
import { PageHeader } from "@/components/PageHeader";
import { ErrorState } from "@/components/States";
import { CopyButton } from "@/components/form/CopyButton";
import { Field } from "@/components/form/Field";
import { CodeBlock } from "@/components/migration/CodeBlock";
import { GroupedFindings } from "@/components/migration/FindingList";
import { Stepper } from "@/components/wizard/Stepper";
import { Button } from "@/components/ui/button";
import { Callout } from "@/components/ui/callout";
import { Input } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";

const STEPS = ["choose", "preflight", "plan", "approve"] as const;
const [S_CHOOSE, S_PREFLIGHT, S_PLAN, S_APPROVE] = [0, 1, 2, 3];

export default function MigrationNew() {
  const { t } = useTranslation("migration");
  const navigate = useNavigate();
  const [params, setParams] = useSearchParams();
  const servers = useServers();
  const preflight = usePreflight();
  const buildPlan = useBuildPlan();
  const approve = useApprove();

  const sourceId = params.get("source") ?? "";
  const targetId = params.get("target") ?? "";
  const [step, setStep] = useState(S_CHOOSE);
  const [confirmation, setConfirmation] = useState("");

  const heading = useRef<HTMLHeadingElement>(null);
  const first = useRef(true);
  useEffect(() => {
    if (first.current) {
      first.current = false;
      return;
    }
    heading.current?.focus();
  }, [step]);

  const list = servers.data ?? [];
  const source = list.find((s) => s.id === sourceId);
  const target = list.find((s) => s.id === targetId);
  const mysqlInvolved = source?.engine === "mysql" || target?.engine === "mysql";
  const same = sourceId !== "" && sourceId === targetId;
  const chooseValid = Boolean(source && target) && !same && !mysqlInvolved;

  const report = preflight.data;
  const blockers = report?.findings.filter((f) => f.severity === "blocker").length ?? 0;
  const warnings = report?.findings.filter((f) => f.severity === "warning").length ?? 0;
  const plan = buildPlan.data;

  function choose(which: "source" | "target", id: string) {
    const next = new URLSearchParams(params);
    if (id) next.set(which, id);
    else next.delete(which);
    setParams(next, { replace: true });
    // A different pair means different findings and a different plan hash: start over.
    preflight.reset();
    buildPlan.reset();
    approve.reset();
    setConfirmation("");
  }

  function runPreflight() {
    preflight.mutate({ sourceId, targetId });
  }
  function runPlan() {
    buildPlan.mutate({ sourceId, targetId });
  }

  function onNext(e: FormEvent) {
    e.preventDefault();
    if (step === S_CHOOSE && chooseValid) {
      runPreflight();
      setStep(S_PREFLIGHT);
    } else if (step === S_PREFLIGHT && report && blockers === 0) {
      runPlan();
      setStep(S_PLAN);
    } else if (step === S_PLAN && plan) {
      setStep(S_APPROVE);
    }
  }

  function submitApprove(e: FormEvent) {
    e.preventDefault();
    if (!plan || confirmation.trim() !== plan.confirmationPhrase) return;
    approve.mutate(
      { sourceId, targetId, planHash: plan.hash, confirmation },
      { onSuccess: (m) => void navigate(`/migrations/${m.id}`) },
    );
  }

  function reviewNewPlan() {
    approve.reset();
    setConfirmation("");
    runPlan();
    setStep(S_PLAN);
  }

  const approveError = approve.error instanceof ApiError ? approve.error : null;
  const canNext =
    (step === S_CHOOSE && chooseValid) || (step === S_PREFLIGHT && Boolean(report) && blockers === 0 && !preflight.isPending) || (step === S_PLAN && Boolean(plan) && !buildPlan.isPending);
  const phraseMatches = Boolean(plan) && confirmation.trim() === plan?.confirmationPhrase;

  return (
    <>
      <PageHeader title={t("new.title")} description={t("new.subtitle")} />
      <Stepper
        steps={STEPS.map((s) => t(`new.steps.${s}`))}
        current={step}
        ariaLabel={t("new.stepsLabel")}
        stepOfText={t("new.stepOf", { current: step + 1, total: STEPS.length })}
        completedLabel={t("new.stepDone")}
      />

      <form noValidate onSubmit={step === S_APPROVE ? submitApprove : onNext} className="max-w-3xl space-y-5">
        <h2 ref={heading} tabIndex={-1} className="text-lg font-semibold outline-none">
          {t(`new.${STEPS[step]}.heading`)}
        </h2>

        {/* ---- 1. Choose ---------------------------------------------------------------- */}
        {step === S_CHOOSE ? (
          <div className="space-y-5">
            <Callout tone="info">{t("new.choose.rolesNote")}</Callout>
            {servers.isError ? <ErrorState onRetry={() => void servers.refetch()} /> : null}
            <div className="grid gap-5 sm:grid-cols-2">
              <Field id="m-source" label={t("new.choose.source")} required hint={t("new.choose.sourceHint")}>
                {(p) => (
                  <Select {...p} value={sourceId} onChange={(e) => choose("source", e.target.value)} disabled={servers.isPending}>
                    <option value="">{t("new.choose.placeholder")}</option>
                    {list.map((s) => (
                      <option key={s.id} value={s.id}>
                        {s.name} · {t(`engine.${s.engine}`, { ns: "common" })}
                      </option>
                    ))}
                  </Select>
                )}
              </Field>
              <Field id="m-target" label={t("new.choose.target")} required hint={t("new.choose.targetHint")} error={same ? t("new.choose.sameServer") : undefined}>
                {(p) => (
                  <Select {...p} value={targetId} onChange={(e) => choose("target", e.target.value)} disabled={servers.isPending}>
                    <option value="">{t("new.choose.placeholder")}</option>
                    {list.map((s) => (
                      <option key={s.id} value={s.id}>
                        {s.name} · {t(`engine.${s.engine}`, { ns: "common" })}
                      </option>
                    ))}
                  </Select>
                )}
              </Field>
            </div>
            {mysqlInvolved ? (
              <Callout tone="danger" role="alert" title={t("new.choose.mysqlTitle")}>
                {t("new.choose.mysqlBody")}
              </Callout>
            ) : null}
            {!chooseValid && !mysqlInvolved && !same ? <p className="text-sm text-muted-foreground">{t("new.choose.pickBoth")}</p> : null}
          </div>
        ) : null}

        {/* ---- 2. Pre-flight --------------------------------------------------------------- */}
        {step === S_PREFLIGHT ? (
          <div className="space-y-5">
            <Callout tone="ok" title={t("new.preflight.readOnlyTitle")}>
              {t("new.preflight.readOnlyBody", { source: sourceId, target: targetId })}
            </Callout>
            {preflight.isPending ? (
              <div role="status" className="space-y-3">
                <p className="flex items-center gap-2 text-sm text-muted-foreground">
                  <Loader2 aria-hidden="true" className="size-4 animate-spin" />
                  {t("new.preflight.running")}
                </p>
                <Skeleton className="h-24" />
              </div>
            ) : null}
            {preflight.isError ? <ErrorState message={t("new.preflight.failed")} onRetry={runPreflight} /> : null}
            {report ? (
              <>
                <p className="tnum text-sm font-medium" role="status">
                  {t("new.preflight.summary", { blockers, warnings, info: report.findings.length - blockers - warnings })}
                </p>
                {blockers > 0 ? (
                  <Callout tone="danger" role="alert" title={t("new.preflight.blockedTitle", { count: blockers })}>
                    {t("new.preflight.blockedBody")}
                  </Callout>
                ) : (
                  <Callout tone={warnings > 0 ? "warning" : "ok"}>{warnings > 0 ? t("new.preflight.warningsBody") : t("new.preflight.cleanBody")}</Callout>
                )}
                <GroupedFindings findings={report.findings} />
                <Button variant="outline" onClick={runPreflight} disabled={preflight.isPending}>
                  <RefreshCw aria-hidden="true" />
                  {t("new.preflight.rerun")}
                </Button>
              </>
            ) : null}
          </div>
        ) : null}

        {/* ---- 3. Plan ------------------------------------------------------------------- */}
        {step === S_PLAN ? (
          <div className="space-y-5">
            {buildPlan.isPending ? (
              <div role="status" className="space-y-3">
                <p className="flex items-center gap-2 text-sm text-muted-foreground">
                  <Loader2 aria-hidden="true" className="size-4 animate-spin" />
                  {t("new.plan.building")}
                </p>
                <Skeleton className="h-40" />
              </div>
            ) : null}
            {buildPlan.isError ? <ErrorState message={t("new.plan.failed")} onRetry={runPlan} /> : null}
            {plan ? <PlanView plan={plan} /> : null}
          </div>
        ) : null}

        {/* ---- 4. Approve ---------------------------------------------------------------- */}
        {step === S_APPROVE && plan ? (
          <div className="space-y-5">
            <Callout tone="danger" title={t("new.approve.warnTitle")}>
              {t("new.approve.warnBody", { source: plan.sourceId, target: plan.targetId })}
            </Callout>

            {approveError?.code === "plan_hash_mismatch" ? (
              <Callout tone="danger" role="alert" title={t("new.approve.errors.plan_hash_mismatch.title")}>
                <p>{t("new.approve.errors.plan_hash_mismatch.body")}</p>
                <div className="mt-2">
                  <Button variant="outline" size="sm" onClick={reviewNewPlan}>
                    <RefreshCw aria-hidden="true" />
                    {t("new.approve.reviewNewPlan")}
                  </Button>
                </div>
              </Callout>
            ) : null}
            {approve.isError && !approveError ? <ErrorState message={t("new.approve.failed")} /> : null}

            <div className="space-y-2">
              <p className="text-sm">{t("new.approve.typeThis")}</p>
              <div className="flex flex-wrap items-center gap-2 rounded-md border bg-muted p-3">
                <code className="wrap-anywhere font-mono text-sm font-medium">{plan.confirmationPhrase}</code>
              </div>
            </div>

            <Field
              id="m-confirm"
              label={t("new.approve.label")}
              required
              hint={t("new.approve.hint")}
              error={approveError?.code === "confirmation_mismatch" ? t("new.approve.errors.confirmation_mismatch.body") : undefined}
            >
              {(p) => (
                <Input
                  {...p}
                  value={confirmation}
                  onChange={(e) => {
                    setConfirmation(e.target.value);
                    if (approveError?.code === "confirmation_mismatch") approve.reset();
                  }}
                  autoComplete="off"
                  autoCapitalize="none"
                  spellCheck={false}
                  className="font-mono"
                />
              )}
            </Field>

            <Callout tone="info" title={t("new.approve.auditTitle")}>
              {t("new.approve.auditBody")}
            </Callout>
          </div>
        ) : null}

        <div className="flex flex-wrap items-center justify-between gap-3 border-t pt-4">
          {step > S_CHOOSE ? (
            <Button variant="outline" onClick={() => setStep(step - 1)}>
              {t("common:back")}
            </Button>
          ) : (
            <Button variant="ghost" asChild>
              <Link to="/migrations">{t("common:cancel")}</Link>
            </Button>
          )}
          {step === S_APPROVE ? (
            <Button type="submit" variant="destructive" disabled={!phraseMatches || approve.isPending}>
              {approve.isPending ? <Loader2 aria-hidden="true" className="animate-spin" /> : <ShieldCheck aria-hidden="true" />}
              {approve.isPending ? t("new.approve.approving") : t("new.approve.button")}
            </Button>
          ) : (
            <div className="flex flex-wrap items-center gap-3">
              {step === S_PREFLIGHT && blockers > 0 ? <p className="text-sm text-muted-foreground">{t("new.preflight.cannotContinue")}</p> : null}
              <Button type="submit" disabled={!canNext}>
                {t("common:next")}
              </Button>
            </div>
          )}
        </div>
      </form>
    </>
  );
}

function ActionItem({ action }: { action: PlanAction }) {
  const { t } = useTranslation("migration");
  const code = action.sql ?? action.command;
  return (
    <li className="space-y-2 py-3">
      <p className="font-medium">{action.title}</p>
      {code ? <CodeBlock code={code} copyLabel={t("new.plan.copyCode")} failedLabel={t("copyFailed")} /> : null}
      {action.notice ? <p className="text-sm text-muted-foreground">{action.notice}</p> : null}
    </li>
  );
}

function PlanView({ plan }: { plan: MigrationPlan }) {
  const { t } = useTranslation("migration");
  const sourceActions = plan.actions.filter((a) => a.mutatesSource || a.side === "source");
  const targetActions = plan.actions.filter((a) => !(a.mutatesSource || a.side === "source"));
  return (
    <div className="space-y-6">
      <p className="text-sm">
        <span className="wrap-anywhere font-mono font-medium">
          {plan.sourceId} <ArrowRight aria-hidden="true" className="inline size-3.5" /> {plan.targetId}
        </span>
        {" · "}
        {t("new.plan.databases", { count: plan.databases.length })}: <span className="wrap-anywhere font-mono">{plan.databases.join(", ")}</span>
      </p>

      <div className="space-y-2">
        <p className="text-sm font-medium">{t("new.plan.hash")}</p>
        <div className="flex flex-wrap items-center gap-2 rounded-md border bg-muted p-3">
          <code className="wrap-anywhere min-w-0 flex-1 font-mono text-xs">{plan.hash}</code>
          <CopyButton text={plan.hash} label={t("new.plan.copyHash")} failedLabel={t("copyFailed")} />
        </div>
        <p className="text-sm text-muted-foreground">{t("new.plan.hashHint")}</p>
      </div>

      {plan.notices.map((n) => (
        <Callout key={n} tone="warning">
          {n}
        </Callout>
      ))}

      <section aria-labelledby="plan-src" className="rounded-xl border-2 border-crit/60 bg-crit-soft/30 p-4">
        <h3 id="plan-src" className="flex items-center gap-2 text-base font-semibold text-crit">
          <OctagonAlert aria-hidden="true" className="size-5 shrink-0" />
          {t("new.plan.sourceHeading")}
        </h3>
        <p className="mt-1 text-sm">{t("new.plan.sourceHint")}</p>
        <ul className="mt-2 divide-y divide-crit/20">
          {sourceActions.map((a) => (
            <ActionItem key={a.id} action={a} />
          ))}
        </ul>
      </section>

      <section aria-labelledby="plan-tgt" className="rounded-xl border p-4">
        <h3 id="plan-tgt" className="flex items-center gap-2 text-base font-semibold">
          <ServerIcon aria-hidden="true" className="size-5 shrink-0 text-muted-foreground" />
          {t("new.plan.targetHeading")}
        </h3>
        <p className="mt-1 text-sm text-muted-foreground">{t("new.plan.targetHint")}</p>
        <ul className="mt-2 divide-y">
          {targetActions.map((a) => (
            <ActionItem key={a.id} action={a} />
          ))}
        </ul>
      </section>
    </div>
  );
}
