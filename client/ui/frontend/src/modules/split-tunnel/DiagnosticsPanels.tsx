import { useCallback, useEffect, useMemo, useState, type ReactNode } from "react";
import { useTranslation } from "react-i18next";
import { AlertTriangle, CheckCircle2, CircleSlash, Info, RefreshCw, Search } from "lucide-react";
import { SplitTunnel } from "@bindings/services";
import type {
    SplitTunnelEvent,
    SplitTunnelStatus,
    SplitTunnelTrace,
} from "@bindings/services/models.js";
import { Badge } from "@/components/Badge";
import { Button } from "@/components/buttons/Button";
import { Input } from "@/components/inputs/Input";
import { Select } from "@/components/inputs/Select";
import { HelpText } from "@/components/typography/HelpText";
import { Label } from "@/components/typography/Label";
import { cn } from "@/lib/cn";
import { errorCode, formatErrorMessage } from "@/lib/errors";
import { isUnavailableCode } from "@/modules/split-tunnel/splitTunnelDraft";

type ServiceError = { code: string; message: string };

export const UnavailableState = ({
    title,
    description,
    api,
}: {
    title: string;
    description: string;
    api?: string;
}) => (
    <div
        role={"status"}
        className={
            "rounded-lg border border-nb-gray-800 bg-nb-gray-935 px-4 py-3 text-sm text-nb-gray-300"
        }
    >
        <div className={"font-semibold text-nb-gray-100"}>{title}</div>
        <p className={"mt-1"}>{description}</p>
        {api && <p className={"mt-2 font-mono text-xs break-all text-nb-gray-400"}>{api}</p>}
    </div>
);

const UnavailableNotice = ({ error }: { error: ServiceError }) => {
    const { t } = useTranslation();
    return (
        <UnavailableState
            title={t("splitTunnel.diagnostics.unavailable.title")}
            description={t("splitTunnel.diagnostics.unavailable.description", {
                message: error.message,
            })}
            api={t("splitTunnel.diagnostics.unavailable.api")}
        />
    );
};

export const StatisticsPanel = ({ status }: { status: SplitTunnelStatus }) => {
    const { t } = useTranslation();
    if (status.diagnosticsRedacted) {
        return (
            <UnavailableState
                title={t("splitTunnel.statistics.restrictedTitle")}
                description={t("splitTunnel.statistics.restricted")}
                api={t("splitTunnel.statistics.missingApi")}
            />
        );
    }
    const diagnostics: Record<string, string> = status.diagnostics ?? {};
    const entries = Object.entries(diagnostics)
        .filter(([key]) => key.startsWith("diagnostics."))
        .sort(([a], [b]) => a.localeCompare(b));
    if (entries.length === 0) {
        return (
            <UnavailableState
                title={t("splitTunnel.statistics.emptyTitle")}
                description={t("splitTunnel.statistics.empty")}
                api={t("splitTunnel.statistics.missingApi")}
            />
        );
    }
    return (
        <div className={"overflow-x-auto"}>
            <table className={"w-full min-w-[28rem] border-collapse text-sm"}>
                <caption className={"sr-only"}>{t("splitTunnel.statistics.caption")}</caption>
                <thead>
                    <tr className={"text-start text-xs text-nb-gray-400"}>
                        <th
                            scope={"col"}
                            className={"border-b border-nb-gray-850 py-2 pe-3 text-start"}
                        >
                            {t("splitTunnel.statistics.metric")}
                        </th>
                        <th scope={"col"} className={"border-b border-nb-gray-850 py-2 text-start"}>
                            {t("splitTunnel.statistics.value")}
                        </th>
                    </tr>
                </thead>
                <tbody>
                    {entries.map(([key, value]) => {
                        const unavailable = value.toLowerCase().startsWith("unavailable");
                        return (
                            <tr key={key} className={"align-top"}>
                                <th
                                    scope={"row"}
                                    className={
                                        "border-b border-nb-gray-900 py-2 pe-3 text-start font-mono text-xs font-normal text-nb-gray-400"
                                    }
                                >
                                    {key.replace(/^diagnostics\./, "")}
                                </th>
                                <td className={"border-b border-nb-gray-900 py-2"}>
                                    {unavailable ? (
                                        <Badge variant={"warning"}>
                                            {t("splitTunnel.statistics.unavailable")}
                                        </Badge>
                                    ) : (
                                        <span className={"text-xs break-all text-nb-gray-200"}>
                                            {value}
                                        </span>
                                    )}
                                </td>
                            </tr>
                        );
                    })}
                </tbody>
            </table>
            <HelpText margin={false} className={"mt-2 text-xs"}>
                {t("splitTunnel.statistics.footnote")}
            </HelpText>
        </div>
    );
};

export const DNSPanel = ({ status }: { status: SplitTunnelStatus }) => {
    const { t } = useTranslation();
    const diagnostics = status.diagnostics ?? {};
    const cacheSize = diagnostics["diagnostics.dns.cache_size"] ?? "";
    const domainEntries = [
        ["domain.references", diagnostics["domain.references"]],
        ["domain.addresses", diagnostics["domain.addresses"]],
        ["domain.conflicts", diagnostics["domain.conflicts"]],
    ].filter((entry): entry is [string, string] => Boolean(entry[1]));

    if (status.diagnosticsRedacted || cacheSize === "" || cacheSize === "unavailable") {
        return (
            <div className={"flex flex-col gap-3"}>
                <UnavailableState
                    title={t("splitTunnel.dns.unavailableTitle")}
                    description={t("splitTunnel.dns.unavailable")}
                    api={t("splitTunnel.dns.missingApi")}
                />
                {domainEntries.length > 0 && <DomainSummary entries={domainEntries} />}
            </div>
        );
    }
    return (
        <div className={"flex flex-col gap-3"}>
            <div
                className={"rounded-lg border border-nb-gray-850 bg-nb-gray-935 px-4 py-3 text-sm"}
            >
                <div className={"text-xs text-nb-gray-400"}>{t("splitTunnel.dns.cacheSize")}</div>
                <div className={"mt-1 text-lg font-semibold text-nb-gray-100"}>{cacheSize}</div>
            </div>
            <DomainSummary entries={domainEntries} />
            <UnavailableState
                title={t("splitTunnel.dns.entriesTitle")}
                description={t("splitTunnel.dns.entriesUnavailable")}
                api={t("splitTunnel.dns.missingApi")}
            />
        </div>
    );
};

const DomainSummary = ({ entries }: { entries: [string, string][] }) => {
    const { t } = useTranslation();
    return (
        <div className={"grid grid-cols-1 gap-2 sm:grid-cols-3"}>
            {entries.map(([key, value]) => (
                <div
                    key={key}
                    className={"rounded-lg border border-nb-gray-850 bg-nb-gray-935 px-4 py-3"}
                >
                    <div className={"font-mono text-xs text-nb-gray-400"}>{key}</div>
                    <div className={"mt-1 text-sm font-medium text-nb-gray-100"}>{value}</div>
                </div>
            ))}
        </div>
    );
};

export const ActivityPanel = () => {
    const { t } = useTranslation();
    const [events, setEvents] = useState<SplitTunnelEvent[]>([]);
    const [nextSequence, setNextSequence] = useState(0);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<ServiceError | null>(null);

    const load = useCallback(async (after: number, replace: boolean) => {
        setLoading(true);
        setError(null);
        try {
            const page = await SplitTunnel.ListEvents({ afterSequence: after, limit: 100 });
            setEvents((current) => {
                if (replace) return page.events ?? [];
                const seen = new Set(current.map((event) => event.sequence));
                return [
                    ...current,
                    ...(page.events ?? []).filter((event) => !seen.has(event.sequence)),
                ];
            });
            setNextSequence(page.nextSequence ?? after);
        } catch (e) {
            setError({ code: errorCode(e), message: formatErrorMessage(e) });
        } finally {
            setLoading(false);
        }
    }, []);

    useEffect(() => {
        void load(0, true);
    }, [load]);

    const unavailable = error !== null && isUnavailableCode(error.code);

    return (
        <div className={"flex flex-col gap-3"}>
            <div className={"flex flex-wrap items-center justify-between gap-3"}>
                <HelpText margin={false}>{t("splitTunnel.activity.description")}</HelpText>
                <div className={"flex flex-wrap gap-2"}>
                    <Button
                        variant={"secondary"}
                        size={"sm"}
                        onClick={() => void load(0, true)}
                        loading={loading}
                    >
                        <RefreshCw size={14} aria-hidden={"true"} />
                        {t("common.refresh")}
                    </Button>
                    <Button
                        variant={"secondary"}
                        size={"sm"}
                        onClick={() => void load(nextSequence, false)}
                        disabled={loading || events.length === 0}
                    >
                        {t("splitTunnel.activity.loadMore")}
                    </Button>
                </div>
            </div>

            {error && unavailable && <UnavailableNotice error={error} />}
            {error && !unavailable && (
                <div
                    role={"alert"}
                    className={
                        "rounded-lg border border-red-300 bg-red-100 px-4 py-3 text-sm text-red-900 dark:border-red-700 dark:bg-red-900 dark:text-red-100"
                    }
                >
                    {error.message}
                </div>
            )}

            {!error && !loading && events.length === 0 && (
                <div
                    className={
                        "rounded-lg border border-dashed border-nb-gray-700 px-4 py-3 text-sm text-nb-gray-300"
                    }
                >
                    {t("splitTunnel.activity.empty")}
                </div>
            )}

            {events.length > 0 && (
                <ol className={"flex flex-col gap-2"}>
                    {events.map((event) => (
                        <li
                            key={event.sequence}
                            className={
                                "rounded-lg border border-nb-gray-850 bg-nb-gray-935 px-4 py-3"
                            }
                        >
                            <div className={"flex flex-wrap items-center gap-2"}>
                                <Badge variant={severityVariant(event.severity)}>
                                    {event.severity || t("splitTunnel.activity.info")}
                                </Badge>
                                <span className={"font-mono text-xs text-nb-gray-500"}>
                                    #{event.sequence}
                                </span>
                                <span className={"text-sm font-medium text-nb-gray-100"}>
                                    {event.type || t("splitTunnel.activity.event")}
                                </span>
                                <span className={"ms-auto text-xs text-nb-gray-400"}>
                                    {formatTimestamp(event.timestamp) ||
                                        t("splitTunnel.activity.unknownTime")}
                                </span>
                            </div>
                            <p className={"mt-1 text-sm break-words text-nb-gray-200"}>
                                {event.message}
                            </p>
                            {event.redacted && (
                                <HelpText margin={false} className={"mt-1 text-xs"}>
                                    {t("splitTunnel.activity.redacted")}
                                </HelpText>
                            )}
                            {event.details && Object.keys(event.details).length > 0 && (
                                <dl className={"mt-2 grid grid-cols-1 gap-1"}>
                                    {Object.entries(event.details).map(([key, value]) => (
                                        <div
                                            key={key}
                                            className={
                                                "flex flex-wrap items-baseline gap-x-2 gap-y-1"
                                            }
                                        >
                                            <dt className={"font-mono text-xs text-nb-gray-400"}>
                                                {key}
                                            </dt>
                                            <dd className={"text-xs break-all text-nb-gray-200"}>
                                                {value}
                                            </dd>
                                        </div>
                                    ))}
                                </dl>
                            )}
                            {event.droppedEvents > 0 && (
                                <HelpText margin={false} className={"mt-1 text-xs"}>
                                    {t("splitTunnel.activity.dropped", {
                                        count: event.droppedEvents,
                                    })}
                                </HelpText>
                            )}
                        </li>
                    ))}
                </ol>
            )}
        </div>
    );
};

const severityVariant = (
    severity: string,
): "info" | "success" | "warning" | "danger" | "neutral" => {
    switch (severity.toLowerCase()) {
        case "error":
        case "critical":
            return "danger";
        case "warning":
        case "warn":
            return "warning";
        case "info":
            return "info";
        default:
            return "neutral";
    }
};

const formatTimestamp = (value: string): string => {
    if (!value) return "";
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return value;
    return date.toLocaleString();
};

export const TroubleshootingPanel = () => {
    const { t } = useTranslation();
    const [form, setForm] = useState({
        sourceIp: "",
        destinationIp: "",
        protocol: "tcp",
        sourcePort: "",
        destinationPort: "",
        direction: "outbound",
        uid: "",
        hasUid: false,
    });
    const [trace, setTrace] = useState<SplitTunnelTrace | null>(null);
    const [running, setRunning] = useState(false);
    const [error, setError] = useState<ServiceError | null>(null);
    const [formError, setFormError] = useState("");

    const update = (patch: Partial<typeof form>) => {
        setForm((current) => ({ ...current, ...patch }));
        setFormError("");
        setTrace(null);
        setError(null);
    };

    const runTrace = async () => {
        if (form.sourceIp.trim() === "" || form.destinationIp.trim() === "") {
            setFormError(t("splitTunnel.troubleshooting.error.addresses"));
            return;
        }
        const sourcePort = Number(form.sourcePort || 0);
        const destinationPort = Number(form.destinationPort || 0);
        if (
            !Number.isInteger(sourcePort) ||
            !Number.isInteger(destinationPort) ||
            sourcePort < 0 ||
            sourcePort > 65535 ||
            destinationPort < 0 ||
            destinationPort > 65535
        ) {
            setFormError(t("splitTunnel.troubleshooting.error.ports"));
            return;
        }
        setRunning(true);
        setError(null);
        setTrace(null);
        try {
            const result = await SplitTunnel.TracePacket({
                sourceIp: form.sourceIp.trim(),
                destinationIp: form.destinationIp.trim(),
                protocol: form.protocol,
                sourcePort,
                destinationPort,
                direction: form.direction,
                uid: form.hasUid ? Number(form.uid || 0) : 0,
                hasUid: form.hasUid,
            });
            setTrace(result);
        } catch (e) {
            setError({ code: errorCode(e), message: formatErrorMessage(e) });
        } finally {
            setRunning(false);
        }
    };

    const unavailable = error !== null && isUnavailableCode(error.code);

    return (
        <div className={"flex flex-col gap-4"}>
            <HelpText margin={false}>{t("splitTunnel.troubleshooting.description")}</HelpText>
            <div className={"grid grid-cols-1 gap-3 sm:grid-cols-2"}>
                <div>
                    <Label as={"div"}>{t("splitTunnel.troubleshooting.sourceIp")}</Label>
                    <Input
                        value={form.sourceIp}
                        placeholder={"10.0.0.2"}
                        disabled={running}
                        onChange={(event) => update({ sourceIp: event.target.value })}
                        aria-label={t("splitTunnel.troubleshooting.sourceIp")}
                        spellCheck={false}
                    />
                </div>
                <div>
                    <Label as={"div"}>{t("splitTunnel.troubleshooting.destinationIp")}</Label>
                    <Input
                        value={form.destinationIp}
                        placeholder={"10.1.2.3"}
                        disabled={running}
                        onChange={(event) => update({ destinationIp: event.target.value })}
                        aria-label={t("splitTunnel.troubleshooting.destinationIp")}
                        spellCheck={false}
                    />
                </div>
                <div>
                    <Label as={"div"}>{t("splitTunnel.troubleshooting.protocol")}</Label>
                    <Select
                        value={form.protocol}
                        ariaLabel={t("splitTunnel.troubleshooting.protocol")}
                        disabled={running}
                        onChange={(protocol) => update({ protocol })}
                        options={[
                            { value: "tcp", label: "TCP" },
                            { value: "udp", label: "UDP" },
                        ]}
                    />
                </div>
                <div>
                    <Label as={"div"}>{t("splitTunnel.troubleshooting.direction")}</Label>
                    <Select
                        value={form.direction}
                        ariaLabel={t("splitTunnel.troubleshooting.direction")}
                        disabled={running}
                        onChange={(direction) => update({ direction })}
                        options={[
                            { value: "outbound", label: t("splitTunnel.troubleshooting.outbound") },
                            { value: "inbound", label: t("splitTunnel.troubleshooting.inbound") },
                        ]}
                    />
                </div>
                <div>
                    <Label as={"div"}>{t("splitTunnel.troubleshooting.sourcePort")}</Label>
                    <Input
                        type={"number"}
                        min={0}
                        max={65535}
                        value={form.sourcePort}
                        disabled={running}
                        onChange={(event) => update({ sourcePort: event.target.value })}
                        aria-label={t("splitTunnel.troubleshooting.sourcePort")}
                    />
                </div>
                <div>
                    <Label as={"div"}>{t("splitTunnel.troubleshooting.destinationPort")}</Label>
                    <Input
                        type={"number"}
                        min={0}
                        max={65535}
                        value={form.destinationPort}
                        disabled={running}
                        onChange={(event) => update({ destinationPort: event.target.value })}
                        aria-label={t("splitTunnel.troubleshooting.destinationPort")}
                    />
                </div>
                <div>
                    <Label as={"div"}>{t("splitTunnel.troubleshooting.uid")}</Label>
                    <Input
                        type={"number"}
                        min={0}
                        value={form.uid}
                        disabled={running || !form.hasUid}
                        onChange={(event) => update({ uid: event.target.value })}
                        aria-label={t("splitTunnel.troubleshooting.uid")}
                    />
                    <label
                        className={
                            "mt-2 inline-flex cursor-default items-center gap-2 text-xs text-nb-gray-300"
                        }
                    >
                        <input
                            type={"checkbox"}
                            checked={form.hasUid}
                            disabled={running}
                            onChange={(event) => update({ hasUid: event.target.checked })}
                        />
                        {t("splitTunnel.troubleshooting.restrictUid")}
                    </label>
                </div>
            </div>
            {formError && (
                <div role={"alert"} className={"text-sm text-red-500"}>
                    {formError}
                </div>
            )}
            <div>
                <Button
                    variant={"primary"}
                    size={"sm"}
                    onClick={() => void runTrace()}
                    loading={running}
                >
                    <Search size={14} aria-hidden={"true"} />
                    {t("splitTunnel.troubleshooting.run")}
                </Button>
            </div>

            {error && unavailable && <UnavailableNotice error={error} />}
            {error && !unavailable && (
                <div
                    role={"alert"}
                    className={
                        "rounded-lg border border-red-300 bg-red-100 px-4 py-3 text-sm text-red-900 dark:border-red-700 dark:bg-red-900 dark:text-red-100"
                    }
                >
                    {error.message}
                </div>
            )}

            {trace && (
                <div className={"rounded-lg border border-nb-gray-850 bg-nb-gray-935 px-4 py-3"}>
                    <div className={"flex flex-wrap items-center gap-2"}>
                        <span className={"text-sm font-semibold text-nb-gray-100"}>
                            {t("splitTunnel.troubleshooting.result")}
                        </span>
                        <Badge variant={trace.finalAction === "block" ? "danger" : "success"}>
                            {trace.finalAction || t("splitTunnel.troubleshooting.noAction")}
                        </Badge>
                        {trace.redacted && (
                            <Badge variant={"warning"}>
                                {t("splitTunnel.troubleshooting.redacted")}
                            </Badge>
                        )}
                    </div>
                    {(trace.stages ?? []).length === 0 ? (
                        <HelpText margin={false} className={"mt-2"}>
                            {t("splitTunnel.troubleshooting.noStages")}
                        </HelpText>
                    ) : (
                        <ol className={"mt-3 flex flex-col gap-2"}>
                            {(trace.stages ?? []).map((stage, index) => (
                                <li
                                    key={`${stage.name}-${index}`}
                                    className={
                                        "flex items-start gap-2 rounded-md border border-nb-gray-850 px-3 py-2"
                                    }
                                >
                                    {stage.allowed ? (
                                        <CheckCircle2
                                            size={15}
                                            aria-hidden={"true"}
                                            className={"mt-0.5 shrink-0 text-green-500"}
                                        />
                                    ) : (
                                        <CircleSlash
                                            size={15}
                                            aria-hidden={"true"}
                                            className={"mt-0.5 shrink-0 text-red-500"}
                                        />
                                    )}
                                    <div className={"min-w-0"}>
                                        <div className={"text-xs font-medium text-nb-gray-100"}>
                                            {stage.name}
                                        </div>
                                        <div className={"text-xs break-words text-nb-gray-300"}>
                                            {stage.message}
                                        </div>
                                        {stage.forwardingDetails && (
                                            <div
                                                className={
                                                    "mt-1 font-mono text-xs break-all text-nb-gray-400"
                                                }
                                            >
                                                {stage.forwardingDetails}
                                            </div>
                                        )}
                                    </div>
                                </li>
                            ))}
                        </ol>
                    )}
                </div>
            )}
            <HelpText margin={false} className={"text-xs"}>
                {t("splitTunnel.troubleshooting.apiNote")}
            </HelpText>
        </div>
    );
};

export const SupportBundlePanel = () => {
    const { t } = useTranslation();
    return (
        <UnavailableState
            title={t("splitTunnel.support.unavailableTitle")}
            description={t("splitTunnel.support.unavailable")}
            api={t("splitTunnel.support.missingApi")}
        />
    );
};

export const DiagnosticsLayout = ({
    status,
    children,
}: {
    status: SplitTunnelStatus;
    children?: ReactNode;
}) => {
    const { t } = useTranslation();
    const degraded = useMemo(() => status.degradedChecks ?? [], [status.degradedChecks]);
    return (
        <div className={"flex flex-col gap-6"}>
            {status.diagnosticsRedacted && (
                <div
                    role={"status"}
                    className={
                        "rounded-lg border border-sky-300 bg-sky-100 px-4 py-3 text-sm text-sky-900 dark:border-sky-700 dark:bg-sky-900 dark:text-sky-100"
                    }
                >
                    <div className={"flex items-center gap-2 font-semibold"}>
                        <Info size={16} aria-hidden={"true"} />
                        {t("splitTunnel.diagnostics.restrictedTitle")}
                    </div>
                    <p className={"mt-1"}>{t("splitTunnel.diagnostics.restricted")}</p>
                </div>
            )}
            {degraded.length > 0 && (
                <div
                    role={"status"}
                    className={
                        "rounded-lg border border-yellow-300 bg-yellow-100 px-4 py-3 text-sm text-yellow-900 dark:border-yellow-700 dark:bg-yellow-900 dark:text-yellow-100"
                    }
                >
                    <div className={"flex items-center gap-2 font-semibold"}>
                        <AlertTriangle size={16} aria-hidden={"true"} />
                        {t("splitTunnel.degraded.title")}
                    </div>
                    <ul className={"mt-2 list-disc space-y-1 ps-5"}>
                        {degraded.map((check) => (
                            <li key={check.code}>
                                {t(`splitTunnel.degraded.reason.${check.code}`, {
                                    defaultValue: check.code,
                                })}
                                {check.detail && (
                                    <span
                                        className={cn(
                                            "ms-2 font-mono text-xs break-all",
                                            "text-yellow-800 dark:text-yellow-200",
                                        )}
                                    >
                                        {check.detail}
                                    </span>
                                )}
                            </li>
                        ))}
                    </ul>
                </div>
            )}
            {children}
        </div>
    );
};
