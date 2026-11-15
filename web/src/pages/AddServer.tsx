import { useEffect, useRef, useState, type FormEvent } from "react";
import { Check, Eye, EyeOff, Loader2, OctagonAlert, ShieldCheck } from "lucide-react";
import { Link, useNavigate } from "react-router-dom";
import { useTranslation } from "react-i18next";
import { useCreateServer, useTestConnection } from "@/api/hooks";
import { ApiError, type ConnectionTestResult, type Engine, type NewServerInput, type TlsMode } from "@/api/types";
import { formatBytes } from "@/lib/format";
import { cn } from "@/lib/utils";
import { PageHeader } from "@/components/PageHeader";
import { ErrorState } from "@/components/States";
import { ErrorSummary } from "@/components/form/ErrorSummary";
import { Field } from "@/components/form/Field";
import { CodeBlock } from "@/components/migration/CodeBlock";
import { FindingList } from "@/components/migration/FindingList";
import { Stepper } from "@/components/wizard/Stepper";
import { Button } from "@/components/ui/button";
import { Callout } from "@/components/ui/callout";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";

const STEPS = ["engine", "endpoint", "credentials", "test", "review"] as const;
const STEP_ENGINE = 0;
const STEP_ENDPOINT = 1;
const STEP_CREDENTIALS = 2;
const STEP_TEST = 3;
const STEP_REVIEW = 4;

const DEFAULT_PORT: Record<Engine, string> = { postgres: "5432", mysql: "3306" };
const DEFAULT_DB: Record<Engine, string> = { postgres: "postgres", mysql: "" };
const TLS_MODES: TlsMode[] = ["verify-full", "verify-ca", "require", "disable"];

// Least-privilege account for each engine (README). The SQL is code, not translated text.
const ROLE_SQL: Record<Engine, string> = {
  postgres: "CREATE ROLE lockkeeper LOGIN PASSWORD '<password>';\nGRANT pg_monitor TO lockkeeper;",
  mysql:
    "CREATE USER 'lockkeeper'@'<host>' IDENTIFIED BY '<password>' REQUIRE SSL;\nGRANT PROCESS, REPLICATION CLIENT ON *.* TO 'lockkeeper'@'<host>';",
};

interface Values {
  engine: Engine;
  name: string;
  host: string;
  port: string;
  database: string;
  tls: TlsMode;
  caPem: string;
  user: string;
  /** Write-only: kept in memory for the test and the save, never rendered after the credentials step. */
  password: string;
}

const INITIAL: Values = { engine: "postgres", name: "", host: "", port: DEFAULT_PORT.postgres, database: DEFAULT_DB.postgres, tls: "verify-full", caPem: "", user: "", password: "" };

type Errors = Partial<Record<"name" | "host" | "port" | "database" | "user" | "password", string>>;
type TFn = (key: string) => string;

function validateEndpoint(v: Values, t: TFn): Errors {
  const e: Errors = {};
  const name = v.name.trim();
  if (!name) e.name = t("errors.nameRequired");
  else if (!/^[a-z0-9][a-z0-9_-]{0,62}$/i.test(name)) e.name = t("errors.nameFormat");
  const host = v.host.trim();
  if (!host) e.host = t("errors.hostRequired");
  else if (/\s/.test(host) || host.includes("://") || /[/@]/.test(host)) e.host = t("errors.hostFormat");
  const port = Number(v.port);
  if (!/^\d+$/.test(v.port.trim()) || port < 1 || port > 65535) e.port = t("errors.portInvalid");
  if (v.engine === "postgres" && !v.database.trim()) e.database = t("errors.databaseRequired");
  return e;
}

function validateCredentials(v: Values, draft: string, t: TFn): Errors {
  const e: Errors = {};
  if (!v.user.trim()) e.user = t("errors.userRequired");
  if (!draft && !v.password) e.password = t("errors.passwordRequired");
  return e;
}

export default function AddServer() {
  const { t, i18n } = useTranslation("wizard");
  const lang = i18n.language;
  const navigate = useNavigate();
  const testMutation = useTestConnection();
  const createMutation = useCreateServer();

  const [step, setStep] = useState(STEP_ENGINE);
  const [values, setValues] = useState<Values>(INITIAL);
  const [pwDraft, setPwDraft] = useState("");
  const [showPw, setShowPw] = useState(false);
  const [errors, setErrors] = useState<Errors>({});
  const [focusKey, setFocusKey] = useState(0);
  const [submitted, setSubmitted] = useState(false); // the summary only appears after a failed submit
  const [testResult, setTestResult] = useState<ConnectionTestResult | null>(null);
  const [staleTest, setStaleTest] = useState(false);

  // Move focus to the step heading after a step change (not on first render).
  const heading = useRef<HTMLHeadingElement>(null);
  const firstRender = useRef(true);
  useEffect(() => {
    if (firstRender.current) {
      firstRender.current = false;
      return;
    }
    heading.current?.focus();
  }, [step]);

  const tf: TFn = (k) => t(k);

  function invalidateTest() {
    if (testResult) setStaleTest(true);
    setTestResult(null);
    testMutation.reset();
  }

  function update<K extends keyof Values>(field: K, value: Values[K]) {
    const next = { ...values, [field]: value };
    setValues(next);
    invalidateTest();
    if (field in errors) {
      const all = step === STEP_ENDPOINT ? validateEndpoint(next, tf) : validateCredentials(next, pwDraft, tf);
      setErrors((prev) => {
        const copy = { ...prev };
        const msg = (all as Record<string, string | undefined>)[field];
        if (msg) (copy as Record<string, string>)[field] = msg;
        else delete (copy as Record<string, string | undefined>)[field];
        return copy;
      });
    }
  }

  function selectEngine(engine: Engine) {
    setValues((v) => ({
      ...v,
      engine,
      port: v.port === DEFAULT_PORT[v.engine] ? DEFAULT_PORT[engine] : v.port,
      database: v.database === DEFAULT_DB[v.engine] ? DEFAULT_DB[engine] : v.database,
    }));
    invalidateTest();
  }

  function blurField(field: keyof Errors) {
    const all = step === STEP_ENDPOINT ? validateEndpoint(values, tf) : validateCredentials(values, pwDraft, tf);
    setErrors((prev) => {
      const copy = { ...prev };
      if (all[field]) copy[field] = all[field];
      else delete copy[field];
      return copy;
    });
  }

  /** The password draft lives only while the credentials step is on screen. */
  function commitPassword() {
    if (pwDraft) {
      setValues((v) => ({ ...v, password: pwDraft }));
      invalidateTest();
    }
    setPwDraft("");
    setShowPw(false);
  }

  function goTo(next: number) {
    if (step === STEP_CREDENTIALS) commitPassword();
    setErrors({});
    setSubmitted(false);
    setStep(next);
  }

  function onNext(e: FormEvent) {
    e.preventDefault();
    let errs: Errors = {};
    if (step === STEP_ENDPOINT) errs = validateEndpoint(values, tf);
    if (step === STEP_CREDENTIALS) errs = validateCredentials(values, pwDraft, tf);
    if (Object.keys(errs).length > 0) {
      setErrors(errs);
      setSubmitted(true);
      setFocusKey((k) => k + 1);
      return;
    }
    if (step === STEP_TEST && !testResult?.ok) return;
    goTo(step + 1);
  }

  function toInput(): NewServerInput {
    return {
      name: values.name.trim(),
      engine: values.engine,
      host: values.host.trim(),
      port: Number(values.port),
      database: values.database.trim(),
      user: values.user.trim(),
      password: values.password,
      tls: values.tls,
      caPem: values.caPem.trim() || undefined,
    };
  }

  function runTest() {
    setStaleTest(false);
    setTestResult(null);
    testMutation.mutate(toInput(), { onSuccess: (r) => setTestResult(r) });
  }

  function save() {
    createMutation.mutate(toInput(), {
      onSuccess: (created) => {
        setValues((v) => ({ ...v, password: "" })); // never keep the secret once it is stored
        void navigate(`/servers/${created.id}`);
      },
    });
  }

  const summaryItems = submitted
    ? (Object.entries(errors) as Array<[string, string | undefined]>).filter((e): e is [string, string] => Boolean(e[1])).map(([field, message]) => ({ id: `f-${field}`, message }))
    : [];
  const stepLabels = STEPS.map((s) => t(`steps.${s}`));
  const tlsWeak = values.tls !== "verify-full";
  const saveError = createMutation.error;

  return (
    <>
      <PageHeader title={t("title")} description={t("subtitle")} />
      <Stepper
        steps={stepLabels}
        current={step}
        ariaLabel={t("stepsLabel")}
        stepOfText={t("stepOf", { current: step + 1, total: STEPS.length })}
        completedLabel={t("stepDone")}
      />

      <form noValidate onSubmit={step === STEP_REVIEW ? (e) => { e.preventDefault(); save(); } : onNext} className="max-w-2xl space-y-5">
        <h2 ref={heading} tabIndex={-1} className="text-lg font-semibold outline-none">
          {t(`${STEPS[step]}.heading`)}
        </h2>

        {step === STEP_ENDPOINT || step === STEP_CREDENTIALS ? (
          <>
            <p className="text-sm text-muted-foreground">{t("requiredNote")}</p>
            <ErrorSummary title={t("errorSummaryTitle", { count: summaryItems.length })} items={summaryItems} focusKey={focusKey} />
          </>
        ) : null}

        {step === STEP_ENGINE ? (
          <fieldset className="space-y-3">
            <legend className="mb-2 text-sm text-muted-foreground">{t("engine.hint")}</legend>
            <div className="grid gap-3 sm:grid-cols-2">
              {(["postgres", "mysql"] as const).map((eng) => {
                const selected = values.engine === eng;
                return (
                  <label key={eng} className="block">
                    <input type="radio" name="engine" value={eng} checked={selected} onChange={() => selectEngine(eng)} className="peer sr-only" />
                    <Card className={cn("h-full p-4 transition-colors peer-focus-visible:outline-2 peer-focus-visible:outline-offset-2 peer-focus-visible:outline-ring", selected ? "border-primary ring-2 ring-primary/40" : "hover:border-input")}>
                      <div className="flex items-start justify-between gap-2">
                        <span className="text-base font-semibold">{t(`engine.${eng}.name`)}</span>
                        {selected ? (
                          <span className="inline-flex items-center gap-1 text-xs font-medium text-primary">
                            <Check aria-hidden="true" className="size-4" />
                            {t("engine.selected")}
                          </span>
                        ) : null}
                      </div>
                      <p className="mt-1 text-sm text-muted-foreground">{t(`engine.${eng}.description`)}</p>
                    </Card>
                  </label>
                );
              })}
            </div>
          </fieldset>
        ) : null}

        {step === STEP_ENDPOINT ? (
          <div className="space-y-5">
            <Field id="f-name" label={t("endpoint.name")} required hint={t("endpoint.nameHint")} error={errors.name}>
              {(p) => <Input {...p} value={values.name} onChange={(e) => update("name", e.target.value)} onBlur={() => blurField("name")} autoComplete="off" autoCapitalize="none" spellCheck={false} />}
            </Field>
            <div className="grid gap-5 sm:grid-cols-[1fr_8rem]">
              <Field id="f-host" label={t("endpoint.host")} required hint={t("endpoint.hostHint")} error={errors.host}>
                {(p) => <Input {...p} value={values.host} onChange={(e) => update("host", e.target.value)} onBlur={() => blurField("host")} autoComplete="off" autoCapitalize="none" spellCheck={false} inputMode="url" />}
              </Field>
              <Field id="f-port" label={t("endpoint.port")} required error={errors.port}>
                {(p) => <Input {...p} value={values.port} onChange={(e) => update("port", e.target.value)} onBlur={() => blurField("port")} autoComplete="off" inputMode="numeric" className="tnum font-mono" />}
              </Field>
            </div>
            <Field
              id="f-database"
              label={t("endpoint.database")}
              required={values.engine === "postgres"}
              hint={values.engine === "postgres" ? t("endpoint.databaseHint") : t("endpoint.databaseHintMysql")}
              error={errors.database}
            >
              {(p) => <Input {...p} value={values.database} onChange={(e) => update("database", e.target.value)} onBlur={() => blurField("database")} autoComplete="off" autoCapitalize="none" spellCheck={false} />}
            </Field>
            <Field id="f-tls" label={t("endpoint.tls")} required hint={t(`endpoint.tlsHint.${values.tls}`)}>
              {(p) => (
                <Select {...p} value={values.tls} onChange={(e) => update("tls", e.target.value as TlsMode)}>
                  {TLS_MODES.map((m) => (
                    <option key={m} value={m}>
                      {t(`endpoint.tlsOptions.${m}`)}
                    </option>
                  ))}
                </Select>
              )}
            </Field>
            {tlsWeak ? (
              <Callout tone="warning" title={t("endpoint.tlsWarningTitle")}>
                {t(`endpoint.tlsWarning.${values.tls as Exclude<TlsMode, "verify-full">}`)}
              </Callout>
            ) : null}
            <Field id="f-caPem" label={t("endpoint.caPem")} hint={t("endpoint.caPemHint")}>
              {(p) => <Textarea {...p} value={values.caPem} onChange={(e) => update("caPem", e.target.value)} spellCheck={false} autoComplete="off" className="font-mono text-xs" placeholder="-----BEGIN CERTIFICATE-----" />}
            </Field>
          </div>
        ) : null}

        {step === STEP_CREDENTIALS ? (
          <div className="space-y-5">
            <p className="text-sm text-muted-foreground">{t("credentials.intro")}</p>
            <Field id="f-user" label={t("credentials.user")} required error={errors.user}>
              {(p) => <Input {...p} value={values.user} onChange={(e) => update("user", e.target.value)} onBlur={() => blurField("user")} autoComplete="username" autoCapitalize="none" spellCheck={false} />}
            </Field>
            <Field
              id="f-password"
              label={t("credentials.password")}
              required={!values.password}
              hint={values.password ? t("credentials.passwordSetHint") : t("credentials.passwordHint")}
              error={errors.password}
            >
              {(p) => (
                <div className="flex gap-2">
                  <Input
                    {...p}
                    type={showPw ? "text" : "password"}
                    value={pwDraft}
                    onChange={(e) => {
                      setPwDraft(e.target.value);
                      if (errors.password && e.target.value) setErrors((prev) => ({ ...prev, password: undefined }));
                    }}
                    onBlur={() => blurField("password")}
                    autoComplete="current-password"
                    spellCheck={false}
                  />
                  <Button variant="outline" size="icon" onClick={() => setShowPw((s) => !s)} aria-pressed={showPw} aria-label={showPw ? t("credentials.hide") : t("credentials.show")}>
                    {showPw ? <EyeOff aria-hidden="true" /> : <Eye aria-hidden="true" />}
                  </Button>
                </div>
              )}
            </Field>
            <section aria-labelledby="role-h" className="space-y-2">
              <h3 id="role-h" className="text-base font-semibold">
                {t("credentials.roleHeading")}
              </h3>
              <p className="text-sm text-muted-foreground">{t(`credentials.roleHint.${values.engine}`)}</p>
              <CodeBlock code={ROLE_SQL[values.engine]} copyLabel={t("credentials.copyRole")} failedLabel={t("copyFailed")} />
            </section>
          </div>
        ) : null}

        {step === STEP_TEST ? (
          <div className="space-y-5">
            <p className="text-sm text-muted-foreground">{t("test.intro")}</p>
            {staleTest ? <Callout tone="warning">{t("test.staleNote")}</Callout> : null}
            <div className="flex flex-wrap items-center gap-3">
              <Button onClick={runTest} disabled={testMutation.isPending}>
                {testMutation.isPending ? <Loader2 aria-hidden="true" className="animate-spin" /> : <ShieldCheck aria-hidden="true" />}
                {testResult || testMutation.isError ? t("test.rerun") : t("test.run")}
              </Button>
              {testMutation.isPending ? (
                <p role="status" className="text-sm text-muted-foreground">
                  {t("test.running")}
                </p>
              ) : null}
            </div>

            {testMutation.isError ? <ErrorState message={t("test.errorGeneric")} onRetry={runTest} /> : null}

            {testResult && !testResult.ok && testResult.error ? (
              <Callout tone="danger" role="alert" title={t(`test.errors.${testResult.error.code}.title`)}>
                <p className="wrap-anywhere">{testResult.error.message}</p>
                <p className="mt-1 font-medium">{t(`test.errors.${testResult.error.code}.recovery`)}</p>
                <div className="mt-2">
                  <Button variant="outline" size="sm" onClick={() => goTo(testResult.error?.code === "auth" ? STEP_CREDENTIALS : STEP_ENDPOINT)}>
                    {testResult.error.code === "auth" ? t("test.fix.credentials") : t("test.fix.endpoint")}
                  </Button>
                </div>
              </Callout>
            ) : null}

            {testResult?.ok ? <TestSuccess result={testResult} lang={lang} /> : null}

            {!testResult?.ok ? <p className="text-sm text-muted-foreground">{t("test.needsTest")}</p> : null}
          </div>
        ) : null}

        {step === STEP_REVIEW ? (
          <div className="space-y-5">
            <p className="text-sm text-muted-foreground">{t("review.intro")}</p>
            <Card>
              <CardContent className="p-4 sm:p-5">
                <dl className="grid gap-x-6 gap-y-3 sm:grid-cols-[10rem_1fr]">
                  <Row label={t("review.engine")} value={t(`engine.${values.engine}.name`)} />
                  <Row label={t("review.name")} value={values.name.trim()} mono />
                  <Row label={t("review.address")} value={`${values.host.trim()}:${values.port}`} mono />
                  <Row label={t("review.session")} value={values.database.trim() || "–"} mono />
                  <Row label={t("review.tls")} value={t(`endpoint.tlsOptions.${values.tls}`)} />
                  <Row label={t("review.user")} value={values.user.trim()} mono />
                  <Row label={t("review.password")} value={t("review.passwordSet")} />
                  {testResult?.ok ? <Row label={t("review.databases")} value={String(testResult.discovered.length)} /> : null}
                </dl>
              </CardContent>
            </Card>
            {saveError ? (
              <Callout tone="danger" role="alert" title={t("review.saveFailed")}>
                <p>{saveError instanceof ApiError ? saveError.message : t("test.errorGeneric")}</p>
                {saveError instanceof ApiError && saveError.code === "invalid" ? (
                  <div className="mt-2">
                    <Button variant="outline" size="sm" onClick={() => { createMutation.reset(); goTo(STEP_ENDPOINT); }}>
                      {t("review.changeName")}
                    </Button>
                  </div>
                ) : null}
              </Callout>
            ) : null}
          </div>
        ) : null}

        <div className="flex flex-wrap items-center justify-between gap-3 border-t pt-4">
          <div className="flex gap-2">
            {step > STEP_ENGINE ? (
              <Button variant="outline" onClick={() => goTo(step - 1)}>
                {t("common:back")}
              </Button>
            ) : (
              <Button variant="ghost" asChild>
                <Link to="/servers">{t("common:cancel")}</Link>
              </Button>
            )}
          </div>
          {step === STEP_REVIEW ? (
            <Button type="submit" disabled={createMutation.isPending}>
              {createMutation.isPending ? <Loader2 aria-hidden="true" className="animate-spin" /> : <Check aria-hidden="true" />}
              {createMutation.isPending ? t("review.saving") : t("review.save")}
            </Button>
          ) : (
            <Button type="submit" disabled={step === STEP_TEST && !testResult?.ok}>
              {t("common:next")}
            </Button>
          )}
        </div>
      </form>
    </>
  );
}

function Row({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <>
      <dt className="text-sm text-muted-foreground">{label}</dt>
      <dd className={cn("wrap-anywhere text-sm", mono && "font-mono")}>{value}</dd>
    </>
  );
}

function TestSuccess({ result, lang }: { result: ConnectionTestResult; lang: string }) {
  const { t } = useTranslation("wizard");
  const priv = result.privileges;
  const privRows = priv
    ? ([
        ["superuser", priv.superuser, true],
        ["replication", priv.replication, true],
        ["monitor", priv.monitor, false],
        ["readOnlySession", priv.readOnlySession, false],
      ] as const)
    : [];
  return (
    <div className="space-y-5">
      <Callout tone="ok" role="status" title={t("test.passed")}>
        <dl className="mt-1 grid gap-x-6 gap-y-1 sm:grid-cols-[10rem_1fr]">
          <Row label={t("test.version")} value={result.version ?? "–"} />
          <Row label={t("test.tls")} value={result.tls?.verified ? t("test.tlsVerified") : t("test.tlsNotVerified")} />
          {result.managed ? <Row label={t("test.managed")} value={t(`managed.${result.managed}`, { ns: "common" })} /> : null}
        </dl>
      </Callout>

      {priv ? (
        <section aria-labelledby="priv-h" className="space-y-2">
          <h3 id="priv-h" className="text-base font-semibold">
            {t("test.privileges")}
          </h3>
          <ul className="grid gap-2 sm:grid-cols-2">
            {privRows.map(([key, value, riskyWhenTrue]) => {
              const risky = riskyWhenTrue && value;
              return (
                <li key={key} className="flex items-center justify-between gap-2 rounded-md border px-3 py-2 text-sm">
                  <span>{t(`test.priv.${key}`)}</span>
                  <span className={cn("inline-flex items-center gap-1.5 font-medium", risky ? "text-warn" : "")}>
                    {risky ? <OctagonAlert aria-hidden="true" className="size-4" /> : <Check aria-hidden="true" className="size-4 text-ok" />}
                    {value ? t("test.yes") : t("test.no")}
                  </span>
                </li>
              );
            })}
          </ul>
        </section>
      ) : null}

      {result.findings.length > 0 ? (
        <section aria-labelledby="find-h" className="space-y-1">
          <h3 id="find-h" className="text-base font-semibold">
            {t("test.findings")}
          </h3>
          <FindingList findings={[...result.findings].sort((a, b) => order(a.severity) - order(b.severity))} />
        </section>
      ) : null}

      <section aria-labelledby="disc-h" className="space-y-2">
        <h3 id="disc-h" className="text-base font-semibold">
          {t("test.discovered", { count: result.discovered.length })}
        </h3>
        <p className="text-sm text-muted-foreground">{t("test.discoveredHint")}</p>
        <div className="overflow-x-auto rounded-lg border">
          <table className="w-full text-sm">
            <caption className="sr-only">{t("test.discovered", { count: result.discovered.length })}</caption>
            <thead className="border-b bg-muted/50">
              <tr>
                <th scope="col" className="px-3 py-2 text-left text-xs font-medium uppercase tracking-wide text-muted-foreground">{t("test.dbName")}</th>
                <th scope="col" className="px-3 py-2 text-right text-xs font-medium uppercase tracking-wide text-muted-foreground">{t("test.dbSize")}</th>
              </tr>
            </thead>
            <tbody className="divide-y">
              {result.discovered.map((d) => (
                <tr key={d.name}>
                  <th scope="row" className="px-3 py-2 text-left font-mono font-normal">{d.name}</th>
                  <td className="tnum px-3 py-2 text-right font-mono">{formatBytes(d.sizeBytes, lang)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}

const order = (s: "blocker" | "warning" | "info") => ({ blocker: 0, warning: 1, info: 2 })[s];
