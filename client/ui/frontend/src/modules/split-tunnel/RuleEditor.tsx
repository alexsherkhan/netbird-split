import { useEffect, useId, useState } from "react";
import { useTranslation } from "react-i18next";
import { AlertTriangle, Layers, Pencil, Plus, Trash2 } from "lucide-react";
import type {
    SplitTunnelApplication,
    SplitTunnelCondition,
    SplitTunnelRule,
} from "@bindings/services/models.js";
import { Badge } from "@/components/Badge";
import { Button } from "@/components/buttons/Button";
import { IconButton } from "@/components/buttons/IconButton";
import { Input } from "@/components/inputs/Input";
import { Select } from "@/components/inputs/Select";
import FancyToggleSwitch from "@/components/switches/FancyToggleSwitch";
import { HelpText } from "@/components/typography/HelpText";
import { Label } from "@/components/typography/Label";
import { cn } from "@/lib/cn";
import {
    appLabel,
    CONDITION_TYPES,
    describeCondition,
    isComposite,
    newCondition,
    newGroup,
    newRuleDraft,
    protocolPortParts,
    RULE_ACTIONS,
    type ConditionType,
    type Mode,
    type RuleAction,
    type RuleDraft,
    type Translate,
    validateRule,
} from "@/modules/split-tunnel/splitTunnelDraft";

const APP_LIST_ID = "split-tunnel-applications";

type RuleEditorProps = {
    rules: RuleDraft[];
    unsupportedRules: SplitTunnelRule[];
    conflicts: string[];
    apps: SplitTunnelApplication[];
    appsRedacted: boolean;
    exitNodes: { value: string; label: string }[];
    mode: Mode;
    disabled: boolean;
    fieldError: string;
    onChange: (rules: RuleDraft[]) => void;
    onRequestDelete: (rule: RuleDraft) => Promise<boolean>;
};

export const RuleEditor = ({
    rules,
    unsupportedRules,
    conflicts,
    apps,
    appsRedacted,
    exitNodes,
    mode,
    disabled,
    fieldError,
    onChange,
    onRequestDelete,
}: RuleEditorProps) => {
    const { t } = useTranslation();
    const [editingKey, setEditingKey] = useState<string | null>(null);
    const translate: Translate = (key, options) => t(key, options);

    useEffect(() => {
        if (editingKey && !rules.some((rule) => rule.key === editingKey)) {
            setEditingKey(null);
        }
    }, [editingKey, rules]);

    const updateRule = (key: string, change: (rule: RuleDraft) => RuleDraft) => {
        onChange(rules.map((rule) => (rule.key === key ? change(rule) : rule)));
    };

    const addRule = () => {
        const rule = newRuleDraft();
        onChange([...rules, rule]);
        setEditingKey(rule.key);
    };

    const removeRule = async (rule: RuleDraft) => {
        if (!(await onRequestDelete(rule))) return;
        onChange(rules.filter((current) => current.key !== rule.key));
    };

    const fieldErrorFor = (index: number) =>
        fieldError.startsWith(`splitTunnel.rules[${index}]`) ? fieldError : "";

    return (
        <div className={"flex flex-col gap-4"}>
            <div className={"flex flex-wrap items-start justify-between gap-3"}>
                <div className={"min-w-0"}>
                    <HelpText margin={false}>{t("splitTunnel.rules.description")}</HelpText>
                </div>
                <Button variant={"secondary"} size={"sm"} onClick={addRule} disabled={disabled}>
                    <Plus size={14} aria-hidden={"true"} />
                    {t("splitTunnel.rules.add")}
                </Button>
            </div>

            {conflicts.length > 0 && (
                <div
                    role={"status"}
                    className={
                        "rounded-lg border border-yellow-300 bg-yellow-100 px-4 py-3 text-sm text-yellow-900 dark:border-yellow-700 dark:bg-yellow-900 dark:text-yellow-100"
                    }
                >
                    <div className={"flex items-center gap-2 font-semibold"}>
                        <AlertTriangle size={16} aria-hidden={"true"} />
                        {t("splitTunnel.rules.conflictsTitle")}
                    </div>
                    <ul className={"mt-2 list-disc space-y-1 ps-5"}>
                        {conflicts.map((conflict) => (
                            <li key={conflict} className={"break-words"}>
                                {conflict}
                            </li>
                        ))}
                    </ul>
                </div>
            )}

            {rules.length === 0 ? (
                <div
                    className={
                        "rounded-lg border border-dashed border-nb-gray-700 px-4 py-3 text-sm text-nb-gray-300"
                    }
                >
                    {t("splitTunnel.rules.empty")}
                </div>
            ) : (
                <div className={"flex flex-col gap-3"}>
                    {rules.map((rule, index) => {
                        const issues = validateRule(rule, mode, translate);
                        const ruleConflicts = conflicts.filter(
                            (conflict) =>
                                conflict.includes(`"${rule.id}"`) ||
                                (rule.name !== "" && conflict.includes(rule.name)),
                        );
                        const editing = editingKey === rule.key;
                        const fieldIssue = fieldErrorFor(index);
                        return (
                            <div
                                key={rule.key}
                                className={cn(
                                    "rounded-lg border bg-nb-gray-935",
                                    fieldIssue ? "border-red-500/70" : "border-nb-gray-850",
                                )}
                            >
                                <div
                                    className={
                                        "flex flex-wrap items-start justify-between gap-3 px-4 py-3"
                                    }
                                >
                                    <div className={"min-w-0 flex-1"}>
                                        <div className={"flex flex-wrap items-center gap-2"}>
                                            <span
                                                className={
                                                    "truncate text-sm font-medium text-nb-gray-100"
                                                }
                                            >
                                                {rule.name || t("splitTunnel.rules.unnamed")}
                                            </span>
                                            <Badge variant={rule.enabled ? "success" : "neutral"}>
                                                {rule.enabled
                                                    ? t("splitTunnel.rules.enabled")
                                                    : t("splitTunnel.rules.disabled")}
                                            </Badge>
                                            <Badge variant={"neutral"}>
                                                {t(`splitTunnel.rule.action.${rule.action}`)}
                                            </Badge>
                                            <Badge variant={"neutral"}>
                                                {t("splitTunnel.rules.priorityShort", {
                                                    priority: rule.priority,
                                                })}
                                            </Badge>
                                            {ruleConflicts.length > 0 && (
                                                <Badge variant={"warning"}>
                                                    {t("splitTunnel.rules.conflictBadge")}
                                                </Badge>
                                            )}
                                            {issues.length > 0 && (
                                                <Badge variant={"danger"}>
                                                    {t("splitTunnel.rules.invalidBadge")}
                                                </Badge>
                                            )}
                                        </div>
                                        <div
                                            className={"mt-1 text-xs break-words text-nb-gray-400"}
                                        >
                                            {rule.conditions
                                                .map((condition) =>
                                                    describeCondition(condition, translate, apps),
                                                )
                                                .join(" · ")}
                                        </div>
                                        {rule.id && (
                                            <div
                                                className={
                                                    "mt-1 font-mono text-[0.68rem] text-nb-gray-500"
                                                }
                                            >
                                                {rule.id}
                                            </div>
                                        )}
                                    </div>
                                    <div className={"flex shrink-0 items-center gap-1"}>
                                        <Button
                                            variant={"secondary"}
                                            size={"sm"}
                                            aria-expanded={editing}
                                            onClick={() => setEditingKey(editing ? null : rule.key)}
                                            disabled={disabled}
                                        >
                                            <Pencil size={13} aria-hidden={"true"} />
                                            {editing
                                                ? t("splitTunnel.rules.close")
                                                : t("splitTunnel.rules.edit")}
                                        </Button>
                                        <IconButton
                                            icon={Trash2}
                                            aria-label={t("splitTunnel.rules.deleteFor", {
                                                rule:
                                                    rule.name ||
                                                    rule.id ||
                                                    t("splitTunnel.rules.unnamed"),
                                            })}
                                            onClick={() => void removeRule(rule)}
                                            disabled={disabled}
                                        />
                                    </div>
                                </div>

                                {editing && (
                                    <RuleForm
                                        rule={rule}
                                        mode={mode}
                                        apps={apps}
                                        appsRedacted={appsRedacted}
                                        exitNodes={exitNodes}
                                        disabled={disabled}
                                        issues={issues}
                                        onChange={(next) => updateRule(rule.key, () => next)}
                                    />
                                )}
                            </div>
                        );
                    })}
                </div>
            )}

            {unsupportedRules.length > 0 && (
                <div className={"mt-2 flex flex-col gap-2"}>
                    <div className={"flex items-center gap-2 text-sm font-medium text-nb-gray-200"}>
                        <Layers size={15} aria-hidden={"true"} />
                        {t("splitTunnel.rules.preservedTitle")}
                    </div>
                    <HelpText margin={false}>{t("splitTunnel.rules.preservedHelp")}</HelpText>
                    {unsupportedRules.map((rule) => (
                        <div
                            key={rule.id}
                            className={
                                "rounded-lg border border-dashed border-nb-gray-700 px-4 py-3"
                            }
                        >
                            <div className={"flex flex-wrap items-center gap-2"}>
                                <span className={"text-sm font-medium text-nb-gray-100"}>
                                    {rule.name || rule.id}
                                </span>
                                <Badge variant={"neutral"}>
                                    {t("splitTunnel.rules.preservedBadge")}
                                </Badge>
                            </div>
                            <div className={"mt-1 text-xs break-words text-nb-gray-400"}>
                                {rule.unsupportedReason || t("splitTunnel.rules.preservedReason")}
                            </div>
                        </div>
                    ))}
                </div>
            )}
        </div>
    );
};

const RuleForm = ({
    rule,
    mode,
    apps,
    appsRedacted,
    exitNodes,
    disabled,
    issues,
    onChange,
}: {
    rule: RuleDraft;
    mode: Mode;
    apps: SplitTunnelApplication[];
    appsRedacted: boolean;
    exitNodes: { value: string; label: string }[];
    disabled: boolean;
    issues: string[];
    onChange: (rule: RuleDraft) => void;
}) => {
    const { t } = useTranslation();
    const nameId = useId();
    const descriptionId = useId();

    const change = (patch: Partial<RuleDraft>) => onChange({ ...rule, ...patch });

    const actionOptions = RULE_ACTIONS.map((action) => ({
        value: action,
        label: t(`splitTunnel.rule.action.${action}`),
    }));

    const exitNodeOptions =
        rule.exitNodeId && !exitNodes.some((node) => node.value === rule.exitNodeId)
            ? [{ value: rule.exitNodeId, label: rule.exitNodeId }, ...exitNodes]
            : exitNodes;

    return (
        <div className={"flex flex-col gap-4 border-t border-nb-gray-850 px-4 py-4"}>
            <div className={"grid grid-cols-1 gap-4 sm:grid-cols-2"}>
                <div>
                    <Label htmlFor={nameId}>{t("splitTunnel.rule.name.label")}</Label>
                    <Input
                        id={nameId}
                        value={rule.name}
                        maxLength={256}
                        disabled={disabled}
                        onChange={(event) => change({ name: event.target.value })}
                        aria-label={t("splitTunnel.rule.name.label")}
                    />
                </div>
                <div>
                    <Label htmlFor={descriptionId}>{t("splitTunnel.rule.description.label")}</Label>
                    <Input
                        id={descriptionId}
                        value={rule.description}
                        maxLength={1024}
                        disabled={disabled}
                        onChange={(event) => change({ description: event.target.value })}
                        aria-label={t("splitTunnel.rule.description.label")}
                    />
                </div>
                <div>
                    <Label as={"div"}>{t("splitTunnel.rule.priority.label")}</Label>
                    <Input
                        type={"number"}
                        min={0}
                        max={1_000_000}
                        value={String(rule.priority)}
                        disabled={disabled}
                        onChange={(event) => change({ priority: Number(event.target.value || 0) })}
                        aria-label={t("splitTunnel.rule.priority.label")}
                    />
                    <HelpText margin={false}>{t("splitTunnel.rule.priority.help")}</HelpText>
                </div>
                <div>
                    <Label as={"div"}>{t("splitTunnel.rule.matchMode.label")}</Label>
                    <Select
                        value={rule.matchMode}
                        ariaLabel={t("splitTunnel.rule.matchMode.label")}
                        disabled={disabled}
                        onChange={(value) => change({ matchMode: value === "any" ? "any" : "all" })}
                        options={[
                            { value: "all", label: t("splitTunnel.rule.matchMode.all") },
                            { value: "any", label: t("splitTunnel.rule.matchMode.any") },
                        ]}
                    />
                </div>
                <div>
                    <Label as={"div"}>{t("splitTunnel.rule.action.label")}</Label>
                    <Select
                        value={rule.action}
                        ariaLabel={t("splitTunnel.rule.action.label")}
                        disabled={disabled}
                        onChange={(value) =>
                            change({
                                action: value as RuleAction,
                                exitNodeId: value === "exit_node" ? rule.exitNodeId : "",
                            })
                        }
                        options={actionOptions}
                    />
                </div>
                {rule.action === "exit_node" && (
                    <div>
                        <Label as={"div"}>{t("splitTunnel.rule.exitNode.label")}</Label>
                        {exitNodeOptions.length > 0 ? (
                            <Select
                                value={rule.exitNodeId || exitNodeOptions[0].value}
                                ariaLabel={t("splitTunnel.rule.exitNode.label")}
                                disabled={disabled}
                                onChange={(value) => change({ exitNodeId: value })}
                                options={exitNodeOptions}
                            />
                        ) : (
                            <HelpText
                                margin={false}
                                className={"text-yellow-700 dark:text-yellow-300"}
                            >
                                {t("splitTunnel.rule.exitNode.none")}
                            </HelpText>
                        )}
                    </div>
                )}
            </div>

            <FancyToggleSwitch
                value={rule.enabled}
                onChange={(enabled) => change({ enabled })}
                disabled={disabled || mode === "standard"}
                label={t("splitTunnel.rule.enabled.label")}
                helpText={
                    mode === "standard"
                        ? t("splitTunnel.rule.enabled.standardHelp")
                        : t("splitTunnel.rule.enabled.help")
                }
            />

            {issues.length > 0 && (
                <div
                    role={"alert"}
                    className={
                        "rounded-lg border border-red-300 bg-red-100 px-4 py-3 text-sm text-red-900 dark:border-red-700 dark:bg-red-900 dark:text-red-100"
                    }
                >
                    <ul className={"list-disc space-y-1 ps-5"}>
                        {issues.map((issue) => (
                            <li key={issue}>{issue}</li>
                        ))}
                    </ul>
                </div>
            )}

            <div>
                <Label as={"div"}>{t("splitTunnel.rule.conditions.label")}</Label>
                <HelpText>{t("splitTunnel.rule.conditions.help")}</HelpText>
                <datalist id={APP_LIST_ID}>
                    {apps.map((app) => (
                        <option key={app.desktopId} value={app.desktopId}>
                            {app.name}
                        </option>
                    ))}
                </datalist>
                {appsRedacted && (
                    <HelpText className={"mb-2 text-xs"}>
                        {t("splitTunnel.rule.conditions.pathsRedacted")}
                    </HelpText>
                )}
                <div className={"flex flex-col gap-3"}>
                    {rule.conditions.map((condition, index) => (
                        <ConditionEditor
                            key={`${rule.key}-condition-${index}`}
                            condition={condition}
                            depth={0}
                            apps={apps}
                            disabled={disabled}
                            removable={rule.conditions.length > 1}
                            onChange={(next) =>
                                change({
                                    conditions: rule.conditions.map((current, currentIndex) =>
                                        currentIndex === index ? next : current,
                                    ),
                                })
                            }
                            onRemove={() =>
                                change({
                                    conditions: rule.conditions.filter(
                                        (_, currentIndex) => currentIndex !== index,
                                    ),
                                })
                            }
                        />
                    ))}
                </div>
                <div className={"mt-3 flex flex-wrap gap-2"}>
                    <Button
                        variant={"secondary"}
                        size={"sm"}
                        disabled={disabled}
                        onClick={() =>
                            change({ conditions: [...rule.conditions, newCondition("domain")] })
                        }
                    >
                        <Plus size={13} aria-hidden={"true"} />
                        {t("splitTunnel.rule.conditions.add")}
                    </Button>
                    <Button
                        variant={"secondary"}
                        size={"sm"}
                        disabled={disabled}
                        onClick={() =>
                            change({ conditions: [...rule.conditions, newGroup("all")] })
                        }
                    >
                        <Plus size={13} aria-hidden={"true"} />
                        {t("splitTunnel.rule.conditions.addGroup")}
                    </Button>
                </div>
            </div>
        </div>
    );
};

const ConditionEditor = ({
    condition,
    depth,
    apps,
    disabled,
    removable,
    onChange,
    onRemove,
}: {
    condition: SplitTunnelCondition;
    depth: number;
    apps: SplitTunnelApplication[];
    disabled: boolean;
    removable: boolean;
    onChange: (condition: SplitTunnelCondition) => void;
    onRemove: () => void;
}) => {
    const { t } = useTranslation();
    const composite = isComposite(condition.type);
    const typeValue = CONDITION_TYPES.includes(condition.type as ConditionType)
        ? (condition.type as ConditionType)
        : "domain";

    const changeType = (next: ConditionType) => {
        if (next === "all" || next === "any") {
            onChange({ type: next, value: "", children: [newCondition("domain")] });
            return;
        }
        onChange({ type: next, value: "", children: [] });
    };

    const changeChildren = (children: SplitTunnelCondition[]) =>
        onChange({ ...condition, children });

    return (
        <div
            role={"group"}
            aria-label={t("splitTunnel.rule.condition.group")}
            className={cn(
                "rounded-lg border px-3 py-3",
                composite
                    ? "border-nb-gray-800 bg-nb-gray-930/60"
                    : "border-nb-gray-850 bg-nb-gray-940/40",
            )}
        >
            <div className={"flex flex-wrap items-end gap-2"}>
                <div className={"min-w-[180px] flex-1"}>
                    <Label as={"div"}>{t("splitTunnel.rule.condition.type")}</Label>
                    <Select
                        value={typeValue}
                        ariaLabel={t("splitTunnel.rule.condition.type")}
                        disabled={disabled}
                        onChange={(value) => changeType(value as ConditionType)}
                        options={CONDITION_TYPES.map((type) => ({
                            value: type,
                            label: t(`splitTunnel.rule.conditionType.${type}`),
                        }))}
                    />
                </div>
                {!composite && (
                    <div className={"min-w-[220px] flex-[2]"}>
                        <Label as={"div"}>{t("splitTunnel.rule.condition.value")}</Label>
                        <ConditionValueInput
                            type={typeValue}
                            value={condition.value ?? ""}
                            apps={apps}
                            disabled={disabled}
                            onChange={(value) => onChange({ ...condition, value })}
                        />
                    </div>
                )}
                <Button
                    variant={"ghost"}
                    size={"sm"}
                    aria-label={t("splitTunnel.rule.condition.remove")}
                    disabled={disabled || !removable}
                    onClick={onRemove}
                >
                    <Trash2 size={14} aria-hidden={"true"} />
                </Button>
            </div>

            {composite && (
                <div className={"mt-3 flex flex-col gap-2 border-s border-nb-gray-800 ps-3"}>
                    {(condition.children ?? []).map((child, index) => (
                        <ConditionEditor
                            key={`child-${index}`}
                            condition={child}
                            depth={depth + 1}
                            apps={apps}
                            disabled={disabled}
                            removable={(condition.children ?? []).length > 1}
                            onChange={(next) =>
                                changeChildren(
                                    (condition.children ?? []).map((current, currentIndex) =>
                                        currentIndex === index ? next : current,
                                    ),
                                )
                            }
                            onRemove={() =>
                                changeChildren(
                                    (condition.children ?? []).filter(
                                        (_, currentIndex) => currentIndex !== index,
                                    ),
                                )
                            }
                        />
                    ))}
                    <div className={"flex flex-wrap gap-2"}>
                        <Button
                            variant={"secondary"}
                            size={"sm"}
                            disabled={disabled}
                            onClick={() =>
                                changeChildren([
                                    ...(condition.children ?? []),
                                    newCondition("domain"),
                                ])
                            }
                        >
                            <Plus size={13} aria-hidden={"true"} />
                            {t("splitTunnel.rule.conditions.add")}
                        </Button>
                        {depth < 2 && (
                            <Button
                                variant={"secondary"}
                                size={"sm"}
                                disabled={disabled}
                                onClick={() =>
                                    changeChildren([...(condition.children ?? []), newGroup("any")])
                                }
                            >
                                <Plus size={13} aria-hidden={"true"} />
                                {t("splitTunnel.rule.conditions.addGroup")}
                            </Button>
                        )}
                    </div>
                </div>
            )}
        </div>
    );
};

const ConditionValueInput = ({
    type,
    value,
    apps,
    disabled,
    onChange,
}: {
    type: ConditionType;
    value: string;
    apps: SplitTunnelApplication[];
    disabled: boolean;
    onChange: (value: string) => void;
}) => {
    const { t } = useTranslation();

    if (type === "protocol_port") {
        const parts = protocolPortParts(value);
        return (
            <div className={"flex gap-2"}>
                <Select
                    value={parts.protocol}
                    ariaLabel={t("splitTunnel.rule.condition.protocol")}
                    disabled={disabled}
                    onChange={(protocol) => onChange(`${protocol}/${parts.port}`)}
                    options={[
                        { value: "tcp", label: "TCP" },
                        { value: "udp", label: "UDP" },
                    ]}
                />
                <Input
                    type={"number"}
                    min={1}
                    max={65535}
                    value={parts.port}
                    disabled={disabled}
                    placeholder={t("splitTunnel.rule.condition.portPlaceholder")}
                    onChange={(event) => onChange(`${parts.protocol}/${event.target.value}`)}
                    aria-label={t("splitTunnel.rule.condition.port")}
                />
            </div>
        );
    }

    if (type === "uid") {
        return (
            <Input
                type={"number"}
                min={0}
                value={value}
                disabled={disabled}
                placeholder={t("splitTunnel.rule.condition.uidPlaceholder")}
                onChange={(event) => onChange(event.target.value)}
                aria-label={t("splitTunnel.rule.condition.value")}
            />
        );
    }

    const usesAppList = type === "desktop_id";
    const matched = usesAppList ? appLabel(apps, value) : "";
    return (
        <div>
            <Input
                value={value}
                list={usesAppList ? APP_LIST_ID : undefined}
                disabled={disabled}
                placeholder={t(`splitTunnel.rule.condition.placeholder.${type}`, {
                    defaultValue: "",
                })}
                onChange={(event) => onChange(event.target.value)}
                aria-label={t("splitTunnel.rule.condition.value")}
                spellCheck={false}
                autoCapitalize={"off"}
                autoCorrect={"off"}
            />
            {matched && (
                <HelpText margin={false} className={"mt-1 text-xs"}>
                    {matched}
                </HelpText>
            )}
        </div>
    );
};
