import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { useTranslation } from "react-i18next";
import * as Tabs from "@radix-ui/react-tabs";
import {
    Activity,
    AlertTriangle,
    CheckCircle2,
    CircleSlash,
    Info,
    LayoutDashboard,
    ListChecks,
    RefreshCw,
    RotateCcw,
    Route,
    ShieldCheck,
    ShieldOff,
    Stethoscope,
} from "lucide-react";
import { Networks as NetworksSvc, SplitTunnel } from "@bindings/services";
import type { Network } from "@bindings/services/models.js";
import type {
    SplitTunnelApplication,
    SplitTunnelConfig,
    SplitTunnelRule,
    SplitTunnelRules,
    SplitTunnelStatus,
} from "@bindings/services/models.js";
import { Badge } from "@/components/Badge";
import { Button } from "@/components/buttons/Button";
import { Select } from "@/components/inputs/Select";
import FancyToggleSwitch from "@/components/switches/FancyToggleSwitch";
import { HelpText } from "@/components/typography/HelpText";
import { Label } from "@/components/typography/Label";
import { useConfirm } from "@/contexts/DialogContext";
import { isExitNode } from "@/contexts/NetworksContext";
import { useStatus } from "@/contexts/StatusContext";
import { cn } from "@/lib/cn";
import { errorCode, errorField, formatErrorMessage } from "@/lib/errors";
import {
    ActivityPanel,
    DiagnosticsLayout,
    DNSPanel,
    StatisticsPanel,
    SupportBundlePanel,
    TroubleshootingPanel,
} from "@/modules/split-tunnel/DiagnosticsPanels";
import { RuleEditor } from "@/modules/split-tunnel/RuleEditor";
import {
    cloneDraft,
    DEFAULT_ACTIONS,
    defaultActionFrom,
    draftFromConfig,
    draftsEqual,
    isUnavailableCode,
    KILL_SWITCHES,
    killSwitchFrom,
    MODES,
    modeFrom,
    type DefaultAction,
    type Draft,
    type KillSwitch,
    type Mode,
    type RevisionSnapshot,
    type RuleDraft,
    ruleToInput,
    type Translate,
    validateRule,
} from "@/modules/split-tunnel/splitTunnelDraft";
import { SectionGroup } from "@/modules/settings/SettingsSection";

type ServiceError = { code: string; message: string; field?: string };

type ExitNodeSelection = { key: string; label: string; exitNodeId: string };

export const SplitTunnelScreen = () => {
    const { t } = useTranslation();
    const confirm = useConfirm();
    const { status: daemonStatus } = useStatus();

    const [status, setStatus] = useState<SplitTunnelStatus | null>(null);
    const [config, setConfig] = useState<SplitTunnelConfig | null>(null);
    const [rulesResult, setRulesResult] = useState<SplitTunnelRules | null>(null);
    const [apps, setApps] = useState<SplitTunnelApplication[]>([]);
    const [appsRedacted, setAppsRedacted] = useState(false);
    const [exitNodes, setExitNodes] = useState<Network[]>([]);
    const [draft, setDraft] = useState<Draft | null>(null);
    const [initial, setInitial] = useState<Draft | null>(null);
    const [revisionHistory, setRevisionHistory] = useState<RevisionSnapshot[]>([]);
    const [loading, setLoading] = useState(true);
    const [saving, setSaving] = useState(false);
    const [rollingBack, setRollingBack] = useState(false);
    const [loadError, setLoadError] = useState<ServiceError | null>(null);
    const [saveError, setSaveError] = useState<ServiceError | null>(null);
    const [rulesError, setRulesError] = useState<ServiceError | null>(null);
    const [appsError, setAppsError] = useState<ServiceError | null>(null);
    const [applied, setApplied] = useState(false);

    const dirtyRef = useRef(false);
    const translate = useCallback<Translate>((key, options) => t(key, options), [t]);

    const loadRules = useCallback(async () => {
        setRulesError(null);
        try {
            const result = await SplitTunnel.ListRules();
            setRulesResult(result);
        } catch (e) {
            setRulesResult(null);
            setRulesError({ code: errorCode(e), message: formatErrorMessage(e) });
        }
    }, []);

    const loadApplications = useCallback(async () => {
        setAppsError(null);
        try {
            const result = await SplitTunnel.ListApplications("");
            setApps(result.applications ?? []);
            setAppsRedacted(result.executableRedacted || result.sourceRedacted);
        } catch (e) {
            setApps([]);
            setAppsRedacted(false);
            setAppsError({ code: errorCode(e), message: formatErrorMessage(e) });
        }
    }, []);

    const load = useCallback(async () => {
        setLoading(true);
        setLoadError(null);
        try {
            const [nextStatus, nextConfig] = await Promise.all([
                SplitTunnel.GetStatus(),
                SplitTunnel.GetConfig(),
            ]);
            setStatus(nextStatus);
            setConfig(nextConfig);
            if (!dirtyRef.current) {
                const nextDraft = draftFromConfig(nextConfig);
                setInitial(nextDraft);
                setDraft(nextDraft);
            }
            if (nextConfig.exists && nextConfig.revision > 0) {
                const snapshot: RevisionSnapshot = {
                    revision: nextConfig.revision,
                    mode: modeFrom(nextConfig.mode),
                    ruleCount: nextConfig.ruleCount,
                    at: new Date().toISOString(),
                };
                setRevisionHistory((current) =>
                    current.some((item) => item.revision === snapshot.revision)
                        ? current
                        : [snapshot, ...current].slice(0, 20),
                );
            }
        } catch (e) {
            setLoadError({ code: errorCode(e), message: formatErrorMessage(e) });
        } finally {
            setLoading(false);
        }
        void loadRules();
        void loadApplications();
    }, [loadApplications, loadRules]);

    useEffect(() => {
        void load();
    }, [load]);

    useEffect(() => {
        if (!daemonStatus?.status) return;
        void load();
    }, [daemonStatus?.status, load]);

    useEffect(() => {
        const onVisible = () => {
            if (document.visibilityState === "visible") void load();
        };
        document.addEventListener("visibilitychange", onVisible);
        return () => document.removeEventListener("visibilitychange", onVisible);
    }, [load]);

    const networksRevision = daemonStatus?.networksRevision;
    useEffect(() => {
        let cancelled = false;
        NetworksSvc.List()
            .then((list) => {
                if (!cancelled) setExitNodes(list.filter((network) => isExitNode(network.range)));
            })
            .catch((e: unknown) => console.warn("[SplitTunnelScreen] exit node read failed", e));
        return () => {
            cancelled = true;
        };
    }, [networksRevision]);

    const dirty = useMemo(
        () => draft !== null && initial !== null && !draftsEqual(draft, initial),
        [draft, initial],
    );

    useEffect(() => {
        dirtyRef.current = dirty;
    }, [dirty]);

    useEffect(() => {
        if (!dirty) return;
        const onBeforeUnload = (event: BeforeUnloadEvent) => {
            event.preventDefault();
            event.returnValue = "";
        };
        window.addEventListener("beforeunload", onBeforeUnload);
        return () => window.removeEventListener("beforeunload", onBeforeUnload);
    }, [dirty]);

    const validation = useMemo(() => {
        const issues: Record<string, string[]> = {};
        if (!draft) return issues;
        for (const rule of draft.rules) {
            issues[rule.key] = validateRule(rule, draft.mode, translate);
        }
        return issues;
    }, [draft, translate]);

    const validationCount = useMemo(
        () =>
            Object.values(validation).reduce(
                (total: number, issues: string[]) => total + issues.length,
                0,
            ),
        [validation],
    );

    const isLoading = loading && !config;
    const unavailable = loadError !== null && isUnavailableCode(loadError.code);
    const canEdit = config !== null && !unavailable;
    const disabled = !canEdit || saving || rollingBack;

    const unsupportedRules = useMemo(
        () => (config?.rules ?? []).filter((rule: SplitTunnelRule) => !rule.supported),
        [config],
    );
    const conflicts = rulesResult?.conflicts ?? [];
    const rulesUnavailable = rulesError !== null && isUnavailableCode(rulesError.code);

    const exitNodeOptions = useMemo(() => {
        const ids = new Map<string, string>();
        for (const node of exitNodes) ids.set(node.id, node.id);
        for (const rule of draft?.rules ?? []) {
            if (rule.exitNodeId) ids.set(rule.exitNodeId, rule.exitNodeId);
        }
        return [...ids.entries()].map(([value, label]) => ({ value, label }));
    }, [draft, exitNodes]);

    const exitNodeRules = useMemo<ExitNodeSelection[]>(
        () =>
            (draft?.rules ?? [])
                .filter((rule) => rule.action === "exit_node")
                .map((rule) => ({
                    key: rule.key,
                    label: rule.name || rule.id || t("splitTunnel.rules.unnamed"),
                    exitNodeId: rule.exitNodeId,
                })),
        [draft, t],
    );

    const exitNodeSummary = useMemo(() => {
        const ids = new Set<string>();
        for (const rule of draft?.rules ?? []) {
            if (rule.action === "exit_node" && rule.exitNodeId) ids.add(rule.exitNodeId);
        }
        return ids.size > 0 ? [...ids].join(", ") : "";
    }, [draft]);

    const backendDegraded = useMemo(
        () =>
            status?.degradedChecks.some((check) =>
                ["backend_unavailable", "backend_degraded", "backend_error"].includes(check.code),
            ) ?? false,
        [status],
    );

    const updateDraft = (change: (current: Draft) => Draft) => {
        setDraft((current) => (current ? change(current) : current));
        setSaveError(null);
        setApplied(false);
    };

    const handleMode = (mode: Mode) => {
        updateDraft((current) => ({
            ...current,
            mode,
            defaultAction:
                mode === "custom"
                    ? current.defaultAction || "vpn"
                    : defaultActionFrom(current.defaultAction),
        }));
    };

    const handleExitNode = (key: string, exitNodeId: string) => {
        updateDraft((current) => ({
            ...current,
            rules: current.rules.map((rule) => (rule.key === key ? { ...rule, exitNodeId } : rule)),
        }));
    };

    const handleDiscard = () => {
        if (!initial) return;
        setDraft(cloneDraft(initial));
        setSaveError(null);
        setApplied(false);
    };

    const confirmDestructiveChange = async (): Promise<boolean> => {
        if (!config || !draft) return false;
        const disabling = config.enabled && !draft.enabled;
        const switchingToStandard = config.enabled && draft.mode === "standard";
        const removingKillSwitch =
            killSwitchFrom(config.killSwitch) !== "disabled" && draft.killSwitch === "disabled";
        const blockingDefault =
            draft.mode === "custom" &&
            draft.defaultAction === "block" &&
            defaultActionFrom(config.defaultAction) !== "block";
        if (!disabling && !switchingToStandard && !removingKillSwitch && !blockingDefault) {
            return true;
        }

        const description = disabling
            ? t("splitTunnel.confirm.disable")
            : switchingToStandard
              ? t("splitTunnel.confirm.standard")
              : removingKillSwitch
                ? t("splitTunnel.confirm.killSwitch")
                : t("splitTunnel.confirm.blockDefault");

        return confirm({
            title: t("splitTunnel.confirm.title"),
            description,
            confirmLabel: t("splitTunnel.confirm.action"),
            cancelLabel: t("common.cancel"),
            danger: true,
        });
    };

    const confirmRuleDelete = async (rule: RuleDraft): Promise<boolean> => {
        if (!rule.id) return true;
        return confirm({
            title: t("splitTunnel.confirm.ruleDeleteTitle"),
            description: t("splitTunnel.confirm.ruleDelete", {
                rule: rule.name || rule.id,
            }),
            confirmLabel: t("splitTunnel.confirm.delete"),
            cancelLabel: t("common.cancel"),
            danger: true,
        });
    };

    const handleApply = async () => {
        if (!config || !draft || saving) return;
        if (validationCount > 0) {
            setSaveError({
                code: "split_tunnel_invalid_config",
                message: t("splitTunnel.rules.fixBeforeSave", { count: validationCount }),
            });
            return;
        }
        if (!(await confirmDestructiveChange())) return;

        setSaving(true);
        setSaveError(null);
        setApplied(false);
        try {
            await SplitTunnel.Apply({
                expectedRevision: config.revision,
                enabled: draft.enabled,
                mode: draft.mode,
                defaultAction: draft.defaultAction,
                killSwitch: draft.killSwitch,
                exitNodes: [],
                rulesChanged: true,
                rules: draft.rules.map(ruleToInput),
            });
            dirtyRef.current = false;
            setApplied(true);
            await load();
        } catch (e) {
            const code = errorCode(e);
            setSaveError({
                code,
                message: formatErrorMessage(e),
                field: errorField(e),
            });
            // A conflict leaves the local edits in place; the notice offers an
            // explicit reload so nothing is discarded behind the user's back.
        } finally {
            setSaving(false);
        }
    };

    const handleRollback = async (snapshot: RevisionSnapshot) => {
        if (!config || rollingBack) return;
        const restore = await confirm({
            title: t("splitTunnel.recovery.confirmTitle"),
            description: t("splitTunnel.recovery.confirm", {
                revision: snapshot.revision,
                mode: t(`splitTunnel.mode.${snapshot.mode}`),
            }),
            confirmLabel: t("splitTunnel.recovery.restore"),
            cancelLabel: t("common.cancel"),
            danger: true,
        });
        if (!restore) return;

        setRollingBack(true);
        setSaveError(null);
        try {
            await SplitTunnel.Rollback({
                expectedRevision: config.revision,
                revision: snapshot.revision,
            });
            dirtyRef.current = false;
            await load();
        } catch (e) {
            setSaveError({
                code: errorCode(e),
                message: formatErrorMessage(e),
                field: errorField(e),
            });
        } finally {
            setRollingBack(false);
        }
    };

    const retry = () => {
        void load();
    };

    const reloadDiscard = () => {
        dirtyRef.current = false;
        setSaveError(null);
        setApplied(false);
        void load();
    };

    const olderRevisions = revisionHistory.filter(
        (snapshot) => snapshot.revision !== config?.revision,
    );

    return (
        <div className={"flex flex-col gap-6"} aria-busy={isLoading || saving || rollingBack}>
            <div className={"flex flex-wrap items-start justify-between gap-3"}>
                <div className={"min-w-0"}>
                    <h1 className={"text-lg font-semibold text-nb-gray-50"}>
                        {t("splitTunnel.title")}
                    </h1>
                    <HelpText margin={false}>{t("splitTunnel.description")}</HelpText>
                </div>
                <div className={"flex flex-wrap items-center gap-2"}>
                    {dirty && <Badge variant={"warning"}>{t("splitTunnel.unsaved")}</Badge>}
                    {status?.restartRequired && (
                        <Badge variant={"warning"}>{t("splitTunnel.restart.badge")}</Badge>
                    )}
                    <Button
                        variant={"secondary"}
                        size={"sm"}
                        onClick={retry}
                        loading={loading}
                        disabled={saving || rollingBack}
                    >
                        <RefreshCw size={14} aria-hidden={"true"} />
                        {t("common.refresh")}
                    </Button>
                </div>
            </div>

            {loadError && unavailable && (
                <InlineNotice
                    tone={"warning"}
                    icon={Info}
                    title={t("splitTunnel.unavailable.title")}
                    action={
                        <Button variant={"secondary"} size={"sm"} onClick={retry}>
                            {t("splitTunnel.unavailable.retry")}
                        </Button>
                    }
                >
                    <p>{t("splitTunnel.unavailable.description")}</p>
                    <p className={"mt-1 font-mono text-xs break-all text-nb-gray-300"}>
                        {loadError.message}
                    </p>
                </InlineNotice>
            )}

            {loadError && !unavailable && (
                <InlineNotice
                    tone={"danger"}
                    icon={AlertTriangle}
                    title={t("splitTunnel.error.loadTitle")}
                    action={
                        <Button variant={"secondary"} size={"sm"} onClick={retry}>
                            {t("common.refresh")}
                        </Button>
                    }
                >
                    <p className={"break-words"}>{loadError.message}</p>
                </InlineNotice>
            )}

            {isLoading && !loadError && (
                <div
                    role={"status"}
                    aria-live={"polite"}
                    className={"flex items-center gap-2 text-sm text-nb-gray-300"}
                >
                    <RefreshCw size={14} className={"animate-spin"} aria-hidden={"true"} />
                    {t("common.loading")}
                </div>
            )}

            {status?.restartRequired && (
                <InlineNotice
                    tone={"warning"}
                    icon={AlertTriangle}
                    title={t("splitTunnel.restart.title")}
                >
                    <p>{t("splitTunnel.restart.description")}</p>
                </InlineNotice>
            )}

            {config && !config.exists && (
                <InlineNotice tone={"info"} icon={Info} title={t("splitTunnel.firstRun.title")}>
                    <p>{t("splitTunnel.firstRun.description")}</p>
                </InlineNotice>
            )}

            <Tabs.Root defaultValue={"overview"} className={"flex flex-col gap-4"}>
                <Tabs.List
                    aria-label={t("splitTunnel.tabs.label")}
                    className={
                        "flex flex-wrap gap-1 rounded-lg border border-nb-gray-850 bg-nb-gray-935 p-1"
                    }
                >
                    <TabTrigger
                        value={"overview"}
                        icon={LayoutDashboard}
                        label={t("splitTunnel.tabs.overview")}
                    />
                    <TabTrigger
                        value={"rules"}
                        icon={ListChecks}
                        label={t("splitTunnel.tabs.rules")}
                    />
                    <TabTrigger
                        value={"activity"}
                        icon={Activity}
                        label={t("splitTunnel.tabs.activity")}
                    />
                    <TabTrigger
                        value={"diagnostics"}
                        icon={Stethoscope}
                        label={t("splitTunnel.tabs.diagnostics")}
                    />
                </Tabs.List>

                <Tabs.Content value={"overview"} className={"flex flex-col gap-5 outline-hidden"}>
                    {status && (
                        <SectionGroup title={t("splitTunnel.overview.title")}>
                            <div className={"grid grid-cols-1 gap-3 sm:grid-cols-2"}>
                                <StatusTile
                                    icon={
                                        daemonStatus?.status === "Connected"
                                            ? CheckCircle2
                                            : CircleSlash
                                    }
                                    label={t("splitTunnel.overview.connection")}
                                    value={
                                        daemonStatus?.status === "Connected"
                                            ? t("connect.status.connected")
                                            : daemonStatus?.status === "Connecting"
                                              ? t("connect.status.connecting")
                                              : t("connect.status.disconnected")
                                    }
                                />
                                <StatusTile
                                    icon={status.running ? CheckCircle2 : CircleSlash}
                                    label={t("splitTunnel.overview.engine")}
                                    value={
                                        status.running
                                            ? t("splitTunnel.state.running")
                                            : status.enabled
                                              ? t("splitTunnel.state.enabledNotRunning")
                                              : t("splitTunnel.state.stopped")
                                    }
                                    badge={
                                        status.running
                                            ? t("splitTunnel.badge.running")
                                            : status.enabled
                                              ? t("splitTunnel.badge.degraded")
                                              : t("splitTunnel.badge.stopped")
                                    }
                                    tone={
                                        status.running
                                            ? "success"
                                            : status.enabled
                                              ? "warning"
                                              : "neutral"
                                    }
                                />
                                <StatusTile
                                    icon={Route}
                                    label={t("splitTunnel.overview.mode")}
                                    value={t(`splitTunnel.mode.${modeFrom(status.mode)}`)}
                                />
                                <StatusTile
                                    icon={Route}
                                    label={t("splitTunnel.overview.exitNode")}
                                    value={
                                        exitNodeSummary || t("splitTunnel.exitNodes.noneSelected")
                                    }
                                />
                                <StatusTile
                                    icon={
                                        (draft?.killSwitch ?? "disabled") === "disabled"
                                            ? ShieldOff
                                            : ShieldCheck
                                    }
                                    label={t("splitTunnel.overview.killSwitch")}
                                    value={t(
                                        `splitTunnel.killSwitch.${killSwitchFrom(draft?.killSwitch ?? "")}`,
                                    )}
                                    badge={
                                        killSwitchFrom(draft?.killSwitch ?? "") === "disabled"
                                            ? t("splitTunnel.badge.off")
                                            : t("splitTunnel.badge.on")
                                    }
                                    tone={
                                        killSwitchFrom(draft?.killSwitch ?? "") === "disabled"
                                            ? "neutral"
                                            : "success"
                                    }
                                />
                                <StatusTile
                                    icon={backendDegraded ? AlertTriangle : CheckCircle2}
                                    label={t("splitTunnel.overview.backend")}
                                    value={
                                        status.backend || t("splitTunnel.state.backendUnavailable")
                                    }
                                    badge={
                                        backendDegraded
                                            ? t("splitTunnel.badge.degraded")
                                            : t("splitTunnel.badge.healthy")
                                    }
                                    tone={backendDegraded ? "warning" : "success"}
                                />
                            </div>

                            {status.degraded && <DegradedNotice checks={status.degradedChecks} />}
                        </SectionGroup>
                    )}

                    {config && draft && canEdit && (
                        <SectionGroup title={t("splitTunnel.settings.title")}>
                            <FancyToggleSwitch
                                value={draft.enabled}
                                onChange={(enabled) =>
                                    updateDraft((current) => ({ ...current, enabled }))
                                }
                                disabled={draft.mode === "standard" || disabled}
                                label={t("splitTunnel.settings.enabled.label")}
                                helpText={
                                    draft.mode === "standard"
                                        ? t("splitTunnel.settings.enabled.chooseMode")
                                        : t("splitTunnel.settings.enabled.help")
                                }
                            />

                            <div>
                                <Label as={"div"}>{t("splitTunnel.settings.mode.label")}</Label>
                                <HelpText>{t("splitTunnel.settings.mode.help")}</HelpText>
                                <Select
                                    value={draft.mode}
                                    ariaLabel={t("splitTunnel.settings.mode.label")}
                                    disabled={disabled}
                                    onChange={(mode) => handleMode(mode as Mode)}
                                    options={MODES.map((mode) => ({
                                        value: mode,
                                        label: t(`splitTunnel.mode.${mode}`),
                                    }))}
                                />
                            </div>

                            {draft.mode === "custom" && (
                                <div>
                                    <Label as={"div"}>
                                        {t("splitTunnel.settings.defaultAction.label")}
                                    </Label>
                                    <HelpText>
                                        {t("splitTunnel.settings.defaultAction.help")}
                                    </HelpText>
                                    <Select
                                        value={draft.defaultAction}
                                        ariaLabel={t("splitTunnel.settings.defaultAction.label")}
                                        disabled={disabled}
                                        onChange={(defaultAction) =>
                                            updateDraft((current) => ({
                                                ...current,
                                                defaultAction: defaultAction as DefaultAction,
                                            }))
                                        }
                                        options={DEFAULT_ACTIONS.map((action) => ({
                                            value: action,
                                            label: t(`splitTunnel.defaultAction.${action}`),
                                        }))}
                                    />
                                </div>
                            )}

                            <div>
                                <Label as={"div"}>
                                    {t("splitTunnel.settings.killSwitch.label")}
                                </Label>
                                <HelpText>{t("splitTunnel.settings.killSwitch.help")}</HelpText>
                                <Select
                                    value={draft.killSwitch}
                                    ariaLabel={t("splitTunnel.settings.killSwitch.label")}
                                    disabled={disabled}
                                    onChange={(killSwitch) =>
                                        updateDraft((current) => ({
                                            ...current,
                                            killSwitch: killSwitch as KillSwitch,
                                        }))
                                    }
                                    options={KILL_SWITCHES.map((killSwitch) => ({
                                        value: killSwitch,
                                        label: t(`splitTunnel.killSwitch.${killSwitch}`),
                                    }))}
                                />
                                {draft.killSwitch !== "disabled" && !draft.enabled && (
                                    <HelpText
                                        className={"mt-2 text-yellow-700 dark:text-yellow-300"}
                                    >
                                        {t("splitTunnel.settings.killSwitch.inactive")}
                                    </HelpText>
                                )}
                            </div>

                            <div>
                                <Label as={"div"}>{t("splitTunnel.exitNodes.label")}</Label>
                                <HelpText>{t("splitTunnel.exitNodes.help")}</HelpText>
                                {exitNodeRules.length === 0 ? (
                                    <div
                                        className={
                                            "rounded-lg border border-dashed border-nb-gray-700 px-4 py-3 text-sm text-nb-gray-300"
                                        }
                                    >
                                        {t("splitTunnel.exitNodes.noRules")}
                                    </div>
                                ) : (
                                    <div className={"flex flex-col gap-3"}>
                                        {exitNodeRules.map((rule) => {
                                            const current = rule.exitNodeId;
                                            const options = current
                                                ? exitNodeOptions.some(
                                                      (option) => option.value === current,
                                                  )
                                                    ? exitNodeOptions
                                                    : [
                                                          { value: current, label: current },
                                                          ...exitNodeOptions,
                                                      ]
                                                : exitNodeOptions;
                                            return (
                                                <div
                                                    key={rule.key}
                                                    className={
                                                        "flex flex-col gap-2 rounded-lg border border-nb-gray-850 bg-nb-gray-935 px-4 py-3 sm:flex-row sm:items-center sm:justify-between"
                                                    }
                                                >
                                                    <div
                                                        className={
                                                            "truncate text-sm font-medium text-nb-gray-100"
                                                        }
                                                    >
                                                        {rule.label}
                                                    </div>
                                                    {options.length > 0 ? (
                                                        <Select
                                                            value={current || options[0].value}
                                                            ariaLabel={t(
                                                                "splitTunnel.exitNodes.selectFor",
                                                                { rule: rule.label },
                                                            )}
                                                            disabled={disabled}
                                                            onChange={(value) =>
                                                                handleExitNode(rule.key, value)
                                                            }
                                                            options={options}
                                                            className={"sm:min-w-[220px]"}
                                                        />
                                                    ) : (
                                                        <div className={"text-xs text-nb-gray-300"}>
                                                            {t("splitTunnel.exitNodes.unavailable")}
                                                        </div>
                                                    )}
                                                </div>
                                            );
                                        })}
                                    </div>
                                )}
                            </div>

                            {saveError && (
                                <SaveErrorNotice error={saveError} onReload={reloadDiscard} />
                            )}

                            {applied && !saveError && <AppliedNotice />}
                        </SectionGroup>
                    )}
                </Tabs.Content>

                <Tabs.Content value={"rules"} className={"flex flex-col gap-5 outline-hidden"}>
                    {draft && canEdit && (
                        <>
                            {rulesUnavailable && (
                                <InlineNotice
                                    tone={"warning"}
                                    icon={Info}
                                    title={t("splitTunnel.rules.conflictsUnavailableTitle")}
                                >
                                    <p>{t("splitTunnel.rules.conflictsUnavailable")}</p>
                                    {rulesError?.message && (
                                        <p className={"mt-1 font-mono text-xs break-all"}>
                                            {rulesError.message}
                                        </p>
                                    )}
                                </InlineNotice>
                            )}
                            {rulesError && !rulesUnavailable && (
                                <InlineNotice
                                    tone={"warning"}
                                    icon={AlertTriangle}
                                    title={t("splitTunnel.rules.conflictsErrorTitle")}
                                    action={
                                        <Button
                                            variant={"secondary"}
                                            size={"sm"}
                                            onClick={() => void loadRules()}
                                        >
                                            {t("common.refresh")}
                                        </Button>
                                    }
                                >
                                    <p>{rulesError.message}</p>
                                </InlineNotice>
                            )}
                            {rulesResult && config && rulesResult.revision !== config.revision && (
                                <InlineNotice
                                    tone={"warning"}
                                    icon={AlertTriangle}
                                    title={t("splitTunnel.rules.staleConflictsTitle")}
                                >
                                    <p>{t("splitTunnel.rules.staleConflicts")}</p>
                                </InlineNotice>
                            )}
                            {appsError && (
                                <InlineNotice
                                    tone={"info"}
                                    icon={Info}
                                    title={t("splitTunnel.rules.appsUnavailableTitle")}
                                >
                                    <p>{t("splitTunnel.rules.appsUnavailable")}</p>
                                </InlineNotice>
                            )}
                            {draft.mode === "standard" && (
                                <InlineNotice
                                    tone={"info"}
                                    icon={Info}
                                    title={t("splitTunnel.rules.standardTitle")}
                                >
                                    <p>{t("splitTunnel.rules.standardHelp")}</p>
                                </InlineNotice>
                            )}
                            <SectionGroup title={t("splitTunnel.rules.title")}>
                                <RuleEditor
                                    rules={draft.rules}
                                    unsupportedRules={unsupportedRules}
                                    conflicts={conflicts}
                                    apps={apps}
                                    appsRedacted={appsRedacted}
                                    exitNodes={exitNodeOptions}
                                    mode={draft.mode}
                                    disabled={disabled || draft.mode === "standard"}
                                    fieldError={saveError?.field ?? ""}
                                    onChange={(rules) =>
                                        updateDraft((current) => ({ ...current, rules }))
                                    }
                                    onRequestDelete={confirmRuleDelete}
                                />
                            </SectionGroup>
                            {saveError && (
                                <SaveErrorNotice error={saveError} onReload={reloadDiscard} />
                            )}
                        </>
                    )}
                </Tabs.Content>

                <Tabs.Content value={"activity"} className={"flex flex-col gap-5 outline-hidden"}>
                    <SectionGroup title={t("splitTunnel.activity.title")}>
                        <ActivityPanel />
                    </SectionGroup>
                </Tabs.Content>

                <Tabs.Content
                    value={"diagnostics"}
                    className={"flex flex-col gap-5 outline-hidden"}
                >
                    {status && (
                        <DiagnosticsLayout status={status}>
                            <SectionGroup title={t("splitTunnel.statistics.title")}>
                                <StatisticsPanel status={status} />
                            </SectionGroup>
                            <SectionGroup title={t("splitTunnel.dns.title")}>
                                <DNSPanel status={status} />
                            </SectionGroup>
                            <SectionGroup title={t("splitTunnel.troubleshooting.title")}>
                                <TroubleshootingPanel />
                            </SectionGroup>
                            <SectionGroup title={t("splitTunnel.support.title")}>
                                <SupportBundlePanel />
                            </SectionGroup>
                            <SectionGroup title={t("splitTunnel.recovery.title")}>
                                <div className={"flex flex-col gap-3"}>
                                    <HelpText margin={false}>
                                        {t("splitTunnel.recovery.description")}
                                    </HelpText>
                                    <p className={"font-mono text-xs break-all text-nb-gray-400"}>
                                        {t("splitTunnel.recovery.missingApi")}
                                    </p>
                                    {olderRevisions.length === 0 ? (
                                        <div
                                            className={
                                                "rounded-lg border border-dashed border-nb-gray-700 px-4 py-3 text-sm text-nb-gray-300"
                                            }
                                        >
                                            {t("splitTunnel.recovery.empty")}
                                        </div>
                                    ) : (
                                        <ul className={"flex flex-col gap-2"}>
                                            {olderRevisions.map((snapshot) => (
                                                <li
                                                    key={snapshot.revision}
                                                    className={
                                                        "flex flex-wrap items-center justify-between gap-3 rounded-lg border border-nb-gray-850 bg-nb-gray-935 px-4 py-3"
                                                    }
                                                >
                                                    <div className={"min-w-0"}>
                                                        <div className={"text-sm text-nb-gray-100"}>
                                                            {t("splitTunnel.recovery.revision", {
                                                                revision: snapshot.revision,
                                                                mode: t(
                                                                    `splitTunnel.mode.${snapshot.mode}`,
                                                                ),
                                                            })}
                                                        </div>
                                                        <div className={"text-xs text-nb-gray-400"}>
                                                            {t("splitTunnel.recovery.seenAt", {
                                                                time: new Date(
                                                                    snapshot.at,
                                                                ).toLocaleString(),
                                                            })}
                                                        </div>
                                                    </div>
                                                    <Button
                                                        variant={"secondary"}
                                                        size={"sm"}
                                                        disabled={disabled}
                                                        onClick={() =>
                                                            void handleRollback(snapshot)
                                                        }
                                                    >
                                                        <RotateCcw size={13} aria-hidden={"true"} />
                                                        {t("splitTunnel.recovery.restore")}
                                                    </Button>
                                                </li>
                                            ))}
                                        </ul>
                                    )}
                                </div>
                            </SectionGroup>
                        </DiagnosticsLayout>
                    )}
                </Tabs.Content>
            </Tabs.Root>

            {config && draft && canEdit && (
                <div
                    className={
                        "flex flex-wrap items-center justify-between gap-3 border-t border-nb-gray-850 pt-4"
                    }
                >
                    <div className={"text-xs text-nb-gray-300"} aria-live={"polite"}>
                        {validationCount > 0
                            ? t("splitTunnel.rules.fixBeforeSave", { count: validationCount })
                            : dirty
                              ? t("splitTunnel.unsaved")
                              : t("splitTunnel.saved")}
                    </div>
                    <div className={"flex flex-wrap justify-end gap-3"}>
                        <Button
                            variant={"secondary"}
                            size={"md"}
                            onClick={handleDiscard}
                            disabled={!dirty || saving || rollingBack}
                        >
                            {t("splitTunnel.discard")}
                        </Button>
                        <Button
                            variant={"primary"}
                            size={"md"}
                            onClick={() => void handleApply()}
                            loading={saving}
                            disabled={!dirty || saving || rollingBack || validationCount > 0}
                        >
                            {t("common.saveChanges")}
                        </Button>
                    </div>
                </div>
            )}
        </div>
    );
};

const TabTrigger = ({
    value,
    icon: Icon,
    label,
}: {
    value: string;
    icon: typeof LayoutDashboard;
    label: string;
}) => (
    <Tabs.Trigger
        value={value}
        className={cn(
            "inline-flex cursor-default items-center gap-2 rounded-md px-3 py-2 text-sm font-medium outline-hidden",
            "text-nb-gray-300 transition-colors hover:bg-nb-gray-900 hover:text-nb-gray-100",
            "data-[state=active]:bg-white data-[state=active]:text-nb-gray-900",
            "dark:data-[state=active]:bg-nb-gray-930 dark:data-[state=active]:text-nb-gray-100",
            "focus-visible:ring-2 focus-visible:ring-nb-gray-50/60 focus-visible:ring-offset-2 focus-visible:ring-offset-nb-gray-940",
        )}
    >
        <Icon size={15} aria-hidden={"true"} />
        {label}
    </Tabs.Trigger>
);

const StatusTile = ({
    icon: Icon,
    label,
    value,
    badge,
    tone = "neutral",
}: {
    icon: typeof CheckCircle2;
    label: string;
    value: string;
    badge?: string;
    tone?: "neutral" | "success" | "warning";
}) => (
    <div
        className={
            "flex min-w-0 items-start gap-3 rounded-lg border border-nb-gray-850 bg-nb-gray-935 px-4 py-3"
        }
    >
        <div
            aria-hidden={"true"}
            className={cn(
                "mt-0.5 flex h-8 w-8 shrink-0 items-center justify-center rounded-md",
                tone === "success" && "bg-green-500/20 text-green-500 dark:text-green-400",
                tone === "warning" && "bg-yellow-500/20 text-yellow-600 dark:text-yellow-300",
                tone === "neutral" && "bg-nb-gray-900 text-nb-gray-300",
            )}
        >
            <Icon size={16} />
        </div>
        <div className={"min-w-0 flex-1"}>
            <div className={"flex flex-wrap items-center gap-2"}>
                <span className={"text-xs text-nb-gray-400"}>{label}</span>
                {badge && (
                    <Badge
                        variant={
                            tone === "success"
                                ? "success"
                                : tone === "warning"
                                  ? "warning"
                                  : "neutral"
                        }
                    >
                        {badge}
                    </Badge>
                )}
            </div>
            <div className={"mt-1 text-sm font-medium break-words text-nb-gray-100"}>{value}</div>
        </div>
    </div>
);

const InlineNotice = ({
    tone,
    icon: Icon,
    title,
    action,
    children,
}: {
    tone: "info" | "warning" | "danger";
    icon: typeof Info;
    title: string;
    action?: ReactNode;
    children?: ReactNode;
}) => (
    <div
        role={tone === "danger" ? "alert" : "status"}
        className={cn(
            "rounded-lg border px-4 py-3 text-sm",
            tone === "info" &&
                "border-sky-300 bg-sky-100 text-sky-900 dark:border-sky-700 dark:bg-sky-900 dark:text-sky-100",
            tone === "warning" &&
                "border-yellow-300 bg-yellow-100 text-yellow-900 dark:border-yellow-700 dark:bg-yellow-900 dark:text-yellow-100",
            tone === "danger" &&
                "border-red-300 bg-red-100 text-red-900 dark:border-red-700 dark:bg-red-900 dark:text-red-100",
        )}
    >
        <div className={"flex flex-wrap items-start justify-between gap-3"}>
            <div className={"flex min-w-0 items-start gap-2"}>
                <Icon size={16} className={"mt-0.5 shrink-0"} aria-hidden={"true"} />
                <div className={"min-w-0"}>
                    <div className={"font-semibold"}>{title}</div>
                    {children && <div className={"mt-1 text-sm"}>{children}</div>}
                </div>
            </div>
            {action}
        </div>
    </div>
);

const DegradedNotice = ({ checks }: { checks: SplitTunnelStatus["degradedChecks"] }) => {
    const { t } = useTranslation();
    return (
        <InlineNotice tone={"warning"} icon={AlertTriangle} title={t("splitTunnel.degraded.title")}>
            <ul className={"list-disc space-y-1 ps-4"}>
                {checks.map((check) => (
                    <li key={check.code}>
                        {t(`splitTunnel.degraded.reason.${check.code}`, {
                            defaultValue: check.code,
                        })}
                        {check.detail && (
                            <span
                                className={
                                    "ms-2 font-mono text-xs break-all text-yellow-800 dark:text-yellow-200"
                                }
                            >
                                {check.detail}
                            </span>
                        )}
                    </li>
                ))}
            </ul>
        </InlineNotice>
    );
};

const SaveErrorNotice = ({ error, onReload }: { error: ServiceError; onReload: () => void }) => {
    const { t } = useTranslation();
    return (
        <InlineNotice
            tone={
                error.code === "split_tunnel_mutation_denied" ||
                error.code === "split_tunnel_invalid_config"
                    ? "warning"
                    : "danger"
            }
            icon={AlertTriangle}
            title={
                error.code === "split_tunnel_revision_conflict"
                    ? t("splitTunnel.error.conflictTitle")
                    : error.code === "split_tunnel_mutation_denied"
                      ? t("splitTunnel.error.permissionTitle")
                      : error.code === "split_tunnel_invalid_config"
                        ? t("splitTunnel.error.validationTitle")
                        : t("splitTunnel.error.saveTitle")
            }
            action={
                error.code === "split_tunnel_revision_conflict" ? (
                    <Button variant={"secondary"} size={"sm"} onClick={onReload}>
                        {t("splitTunnel.error.reload")}
                    </Button>
                ) : undefined
            }
        >
            <p className={"break-words"}>{error.message}</p>
            {error.code === "split_tunnel_revision_conflict" && (
                <p className={"mt-1"}>{t("splitTunnel.error.conflictHint")}</p>
            )}
            {error.field && <p className={"mt-1 font-mono text-xs break-all"}>{error.field}</p>}
        </InlineNotice>
    );
};

const AppliedNotice = () => {
    const { t } = useTranslation();
    return (
        <div
            role={"status"}
            aria-live={"polite"}
            className={
                "flex items-center gap-2 rounded-lg border border-green-300 bg-green-100 px-4 py-3 text-sm text-green-800 dark:border-green-700 dark:bg-green-900 dark:text-green-200"
            }
        >
            <CheckCircle2 size={16} aria-hidden={"true"} />
            {t("splitTunnel.applied")}
        </div>
    );
};
