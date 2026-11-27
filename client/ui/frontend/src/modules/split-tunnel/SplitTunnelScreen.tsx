import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { useTranslation } from "react-i18next";
import {
    AlertTriangle,
    CheckCircle2,
    CircleSlash,
    Info,
    RefreshCw,
    Route,
    ShieldCheck,
    ShieldOff,
} from "lucide-react";
import { Networks as NetworksSvc, SplitTunnel } from "@bindings/services";
import type { Network } from "@bindings/services/models.js";
import type {
    SplitTunnelConfig,
    SplitTunnelExitNodeRule,
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
import { errorCode, formatErrorMessage } from "@/lib/errors";
import { SectionGroup } from "@/modules/settings/SettingsSection";

const MODES = ["standard", "include", "exclude", "custom"] as const;
type Mode = (typeof MODES)[number];

const KILL_SWITCHES = ["disabled", "selective", "global", "strict"] as const;
type KillSwitch = (typeof KILL_SWITCHES)[number];

const DEFAULT_ACTIONS = ["vpn", "direct", "block"] as const;
type DefaultAction = (typeof DEFAULT_ACTIONS)[number];

type Draft = {
    enabled: boolean;
    mode: Mode;
    defaultAction: DefaultAction;
    killSwitch: KillSwitch;
    exitNodes: Record<string, string>;
};

type ServiceError = { code: string; message: string };

const modeFrom = (value: string): Mode =>
    MODES.includes(value as Mode) ? (value as Mode) : "standard";

const killSwitchFrom = (value: string): KillSwitch =>
    KILL_SWITCHES.includes(value as KillSwitch) ? (value as KillSwitch) : "disabled";

const defaultActionFrom = (value: string): DefaultAction =>
    DEFAULT_ACTIONS.includes(value as DefaultAction) ? (value as DefaultAction) : "vpn";

const draftFromConfig = (config: SplitTunnelConfig): Draft => ({
    enabled: config.enabled,
    mode: modeFrom(config.mode),
    defaultAction: defaultActionFrom(config.defaultAction),
    killSwitch: killSwitchFrom(config.killSwitch),
    exitNodes: Object.fromEntries(
        (config.exitNodeRules ?? []).map((rule) => [rule.ruleId, rule.exitNodeId]),
    ),
});

const cloneDraft = (draft: Draft): Draft => ({
    ...draft,
    exitNodes: { ...draft.exitNodes },
});

const draftsEqual = (a: Draft, b: Draft): boolean =>
    a.enabled === b.enabled &&
    a.mode === b.mode &&
    a.defaultAction === b.defaultAction &&
    a.killSwitch === b.killSwitch &&
    Object.keys(a.exitNodes).length === Object.keys(b.exitNodes).length &&
    Object.entries(a.exitNodes).every(([rule, exitNode]) => b.exitNodes[rule] === exitNode);

const isUnavailableCode = (code: string): boolean =>
    code === "split_tunnel_unavailable" || code === "split_tunnel_version_unsupported";

export const SplitTunnelScreen = () => {
    const { t } = useTranslation();
    const confirm = useConfirm();
    const { status: daemonStatus } = useStatus();

    const [status, setStatus] = useState<SplitTunnelStatus | null>(null);
    const [config, setConfig] = useState<SplitTunnelConfig | null>(null);
    const [draft, setDraft] = useState<Draft | null>(null);
    const [exitNodes, setExitNodes] = useState<Network[]>([]);
    const [loading, setLoading] = useState(true);
    const [saving, setSaving] = useState(false);
    const [loadError, setLoadError] = useState<ServiceError | null>(null);
    const [saveError, setSaveError] = useState<ServiceError | null>(null);
    const [applied, setApplied] = useState(false);

    const [initial, setInitial] = useState<Draft | null>(null);
    const dirtyRef = useRef(false);

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
        } catch (e) {
            setLoadError({ code: errorCode(e), message: formatErrorMessage(e) });
        } finally {
            setLoading(false);
        }
    }, []);

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

    const isLoading = loading && !config;
    const unavailable = loadError !== null && isUnavailableCode(loadError.code);
    const canEdit = config !== null && !unavailable;

    const exitNodeOptions = useMemo(() => {
        const ids = new Map<string, string>();
        for (const node of exitNodes) ids.set(node.id, node.id);
        for (const rule of config?.exitNodeRules ?? []) {
            if (rule.exitNodeId) ids.set(rule.exitNodeId, rule.exitNodeId);
        }
        return [...ids.entries()].map(([value, label]) => ({ value, label }));
    }, [config, exitNodes]);

    const backendDegraded = useMemo(
        () =>
            status?.degradedChecks.some((check) =>
                ["backend_unavailable", "backend_degraded", "backend_error"].includes(check.code),
            ) ?? false,
        [status],
    );

    const exitNodeSummary = useMemo(() => {
        const ids = new Set<string>();
        for (const rule of config?.exitNodeRules ?? []) {
            if (rule.exitNodeId) ids.add(rule.exitNodeId);
        }
        return ids.size > 0 ? [...ids].join(", ") : "";
    }, [config]);

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

    const handleExitNode = (rule: SplitTunnelExitNodeRule, exitNodeId: string) => {
        updateDraft((current) => ({
            ...current,
            exitNodes: { ...current.exitNodes, [rule.ruleId]: exitNodeId },
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
        if (!disabling && !switchingToStandard && !removingKillSwitch) return true;

        const description = disabling
            ? t("splitTunnel.confirm.disable")
            : switchingToStandard
              ? t("splitTunnel.confirm.standard")
              : t("splitTunnel.confirm.killSwitch");

        return confirm({
            title: t("splitTunnel.confirm.title"),
            description,
            confirmLabel: t("splitTunnel.confirm.action"),
            cancelLabel: t("common.cancel"),
            danger: true,
        });
    };

    const handleApply = async () => {
        if (!config || !draft || saving) return;
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
                exitNodes: (config.exitNodeRules ?? [])
                    .map((rule) => ({
                        ruleId: rule.ruleId,
                        exitNodeId: draft.exitNodes[rule.ruleId] ?? rule.exitNodeId,
                    }))
                    .filter((selection) => selection.exitNodeId !== ""),
            });
            dirtyRef.current = false;
            setApplied(true);
            await load();
        } catch (e) {
            const code = errorCode(e);
            setSaveError({ code, message: formatErrorMessage(e) });
            // A conflict leaves the local edits in place; the notice offers an
            // explicit reload so nothing is discarded behind the user's back.
        } finally {
            setSaving(false);
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

    return (
        <div className={"flex flex-col gap-6"} aria-busy={isLoading || saving}>
            <div className={"flex flex-wrap items-start justify-between gap-3"}>
                <div className={"min-w-0"}>
                    <h1 className={"text-lg font-semibold text-nb-gray-50"}>
                        {t("splitTunnel.title")}
                    </h1>
                    <HelpText margin={false}>{t("splitTunnel.description")}</HelpText>
                </div>
                <Button
                    variant={"secondary"}
                    size={"sm"}
                    onClick={retry}
                    loading={loading}
                    disabled={saving}
                >
                    <RefreshCw size={14} aria-hidden={"true"} />
                    {t("common.refresh")}
                </Button>
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

            {status && (
                <SectionGroup title={t("splitTunnel.overview.title")}>
                    <div className={"grid grid-cols-1 gap-3 sm:grid-cols-2"}>
                        <StatusTile
                            icon={daemonStatus?.status === "Connected" ? CheckCircle2 : CircleSlash}
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
                                status.running ? "success" : status.enabled ? "warning" : "neutral"
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
                            value={exitNodeSummary || t("splitTunnel.exitNodes.noneSelected")}
                        />
                        <StatusTile
                            icon={
                                (config?.killSwitch ?? "disabled") === "disabled"
                                    ? ShieldOff
                                    : ShieldCheck
                            }
                            label={t("splitTunnel.overview.killSwitch")}
                            value={t(
                                `splitTunnel.killSwitch.${killSwitchFrom(config?.killSwitch ?? "")}`,
                            )}
                            badge={
                                killSwitchFrom(config?.killSwitch ?? "") === "disabled"
                                    ? t("splitTunnel.badge.off")
                                    : t("splitTunnel.badge.on")
                            }
                            tone={
                                killSwitchFrom(config?.killSwitch ?? "") === "disabled"
                                    ? "neutral"
                                    : "success"
                            }
                        />
                        <StatusTile
                            icon={backendDegraded ? AlertTriangle : CheckCircle2}
                            label={t("splitTunnel.overview.backend")}
                            value={status.backend || t("splitTunnel.state.backendUnavailable")}
                            badge={
                                backendDegraded
                                    ? t("splitTunnel.badge.degraded")
                                    : t("splitTunnel.badge.healthy")
                            }
                            tone={backendDegraded ? "warning" : "success"}
                        />
                    </div>

                    {status.degraded && <DegradedNotice checks={status.degradedChecks} />}

                    {status.diagnosticsRedacted && (
                        <InlineNotice
                            tone={"info"}
                            icon={Info}
                            title={t("splitTunnel.diagnostics.restrictedTitle")}
                        >
                            <p>{t("splitTunnel.diagnostics.restricted")}</p>
                        </InlineNotice>
                    )}

                    {status.diagnostics && Object.keys(status.diagnostics).length > 0 && (
                        <details
                            className={
                                "rounded-lg border border-nb-gray-850 bg-nb-gray-935 px-4 py-3 text-sm"
                            }
                        >
                            <summary
                                className={
                                    "cursor-pointer font-medium text-nb-gray-100 outline-hidden focus-visible:ring-2 focus-visible:ring-nb-gray-50/60"
                                }
                            >
                                {t("splitTunnel.diagnostics.title")}
                            </summary>
                            <dl className={"mt-3 grid grid-cols-1 gap-2"}>
                                {Object.entries(status.diagnostics).map(([key, value]) => (
                                    <div
                                        key={key}
                                        className={"flex flex-wrap items-baseline gap-x-3 gap-y-1"}
                                    >
                                        <dt
                                            className={"min-w-0 font-mono text-xs text-nb-gray-400"}
                                        >
                                            {key}
                                        </dt>
                                        <dd
                                            className={"min-w-0 text-xs break-all text-nb-gray-200"}
                                        >
                                            {value}
                                        </dd>
                                    </div>
                                ))}
                            </dl>
                        </details>
                    )}
                </SectionGroup>
            )}

            {config && draft && canEdit && (
                <SectionGroup title={t("splitTunnel.settings.title")}>
                    <FancyToggleSwitch
                        value={draft.enabled}
                        onChange={(enabled) => updateDraft((current) => ({ ...current, enabled }))}
                        disabled={draft.mode === "standard" || saving}
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
                            disabled={saving}
                            onChange={handleMode}
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
                            <HelpText>{t("splitTunnel.settings.defaultAction.help")}</HelpText>
                            <Select
                                value={draft.defaultAction}
                                ariaLabel={t("splitTunnel.settings.defaultAction.label")}
                                disabled={saving}
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
                        <Label as={"div"}>{t("splitTunnel.settings.killSwitch.label")}</Label>
                        <HelpText>{t("splitTunnel.settings.killSwitch.help")}</HelpText>
                        <Select
                            value={draft.killSwitch}
                            ariaLabel={t("splitTunnel.settings.killSwitch.label")}
                            disabled={saving}
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
                            <HelpText className={"mt-2 text-yellow-700 dark:text-yellow-300"}>
                                {t("splitTunnel.settings.killSwitch.inactive")}
                            </HelpText>
                        )}
                    </div>

                    <div>
                        <Label as={"div"}>{t("splitTunnel.exitNodes.label")}</Label>
                        <HelpText>{t("splitTunnel.exitNodes.help")}</HelpText>
                        {config.exitNodeRules.length === 0 ? (
                            <div
                                className={
                                    "rounded-lg border border-dashed border-nb-gray-700 px-4 py-3 text-sm text-nb-gray-300"
                                }
                            >
                                {t("splitTunnel.exitNodes.noRules")}
                            </div>
                        ) : (
                            <div className={"flex flex-col gap-3"}>
                                {config.exitNodeRules.map((rule) => {
                                    const current = draft.exitNodes[rule.ruleId] || rule.exitNodeId;
                                    const options = current
                                        ? exitNodeOptions.some((option) => option.value === current)
                                            ? exitNodeOptions
                                            : [
                                                  { value: current, label: current },
                                                  ...exitNodeOptions,
                                              ]
                                        : exitNodeOptions;
                                    return (
                                        <div
                                            key={rule.ruleId}
                                            className={
                                                "flex flex-col gap-2 rounded-lg border border-nb-gray-850 bg-nb-gray-935 px-4 py-3 sm:flex-row sm:items-center sm:justify-between"
                                            }
                                        >
                                            <div className={"min-w-0"}>
                                                <div
                                                    className={
                                                        "truncate text-sm font-medium text-nb-gray-100"
                                                    }
                                                >
                                                    {rule.name || rule.ruleId}
                                                </div>
                                                <div
                                                    className={
                                                        "truncate font-mono text-xs text-nb-gray-400"
                                                    }
                                                >
                                                    {rule.ruleId}
                                                </div>
                                            </div>
                                            {options.length > 0 ? (
                                                <Select
                                                    value={current || options[0].value}
                                                    ariaLabel={t(
                                                        "splitTunnel.exitNodes.selectFor",
                                                        {
                                                            rule: rule.name || rule.ruleId,
                                                        },
                                                    )}
                                                    disabled={saving}
                                                    onChange={(value) =>
                                                        handleExitNode(rule, value)
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
                        <InlineNotice
                            tone={
                                saveError.code === "split_tunnel_mutation_denied"
                                    ? "warning"
                                    : "danger"
                            }
                            icon={AlertTriangle}
                            title={
                                saveError.code === "split_tunnel_revision_conflict"
                                    ? t("splitTunnel.error.conflictTitle")
                                    : saveError.code === "split_tunnel_mutation_denied"
                                      ? t("splitTunnel.error.permissionTitle")
                                      : t("splitTunnel.error.saveTitle")
                            }
                            action={
                                saveError.code === "split_tunnel_revision_conflict" ? (
                                    <Button
                                        variant={"secondary"}
                                        size={"sm"}
                                        onClick={reloadDiscard}
                                    >
                                        {t("splitTunnel.error.reload")}
                                    </Button>
                                ) : undefined
                            }
                        >
                            <p className={"break-words"}>{saveError.message}</p>
                            {saveError.code === "split_tunnel_revision_conflict" && (
                                <p className={"mt-1"}>{t("splitTunnel.error.conflictHint")}</p>
                            )}
                        </InlineNotice>
                    )}

                    {applied && !saveError && (
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
                    )}

                    <div
                        className={
                            "flex flex-wrap items-center justify-between gap-3 border-t border-nb-gray-850 pt-4"
                        }
                    >
                        <div className={"text-xs text-nb-gray-300"} aria-live={"polite"}>
                            {dirty ? t("splitTunnel.unsaved") : t("splitTunnel.saved")}
                        </div>
                        <div className={"flex flex-wrap justify-end gap-3"}>
                            <Button
                                variant={"secondary"}
                                size={"md"}
                                onClick={handleDiscard}
                                disabled={!dirty || saving}
                            >
                                {t("splitTunnel.discard")}
                            </Button>
                            <Button
                                variant={"primary"}
                                size={"md"}
                                onClick={() => void handleApply()}
                                loading={saving}
                                disabled={!dirty || saving}
                            >
                                {t("common.saveChanges")}
                            </Button>
                        </div>
                    </div>
                </SectionGroup>
            )}

            <SectionGroup title={t("splitTunnel.upcoming.title")}>
                <UpcomingFeature
                    title={t("splitTunnel.upcoming.rulesTitle")}
                    description={t("splitTunnel.upcoming.rulesDescription")}
                />
                <UpcomingFeature
                    title={t("splitTunnel.upcoming.dnsTitle")}
                    description={t("splitTunnel.upcoming.dnsDescription")}
                />
                <UpcomingFeature
                    title={t("splitTunnel.upcoming.supportTitle")}
                    description={t("splitTunnel.upcoming.supportDescription")}
                />
            </SectionGroup>
        </div>
    );
};

type StatusTileProps = {
    icon: typeof CheckCircle2;
    label: string;
    value: string;
    badge?: string;
    tone?: "neutral" | "success" | "warning";
};

const StatusTile = ({ icon: Icon, label, value, badge, tone = "neutral" }: StatusTileProps) => (
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
    children: ReactNode;
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
                    <div className={"mt-1 text-sm"}>{children}</div>
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

const UpcomingFeature = ({ title, description }: { title: string; description: string }) => {
    const { t } = useTranslation();
    return (
        <div
            className={
                "flex flex-col gap-2 rounded-lg border border-dashed border-nb-gray-700 px-4 py-3 sm:flex-row sm:items-center sm:justify-between"
            }
        >
            <div className={"min-w-0"}>
                <div className={"text-sm font-medium text-nb-gray-100"}>{title}</div>
                <HelpText margin={false}>{description}</HelpText>
            </div>
            <Button
                variant={"secondary"}
                size={"sm"}
                disabled
                title={t("splitTunnel.upcoming.unavailableHint")}
            >
                {t("splitTunnel.upcoming.comingSoon")}
            </Button>
        </div>
    );
};
