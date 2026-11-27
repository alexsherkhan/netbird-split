import type {
    SplitTunnelCondition,
    SplitTunnelConfig,
    SplitTunnelRule,
} from "@bindings/services/models.js";

export const MODES = ["standard", "include", "exclude", "custom"] as const;
export type Mode = (typeof MODES)[number];

export const KILL_SWITCHES = ["disabled", "selective", "global", "strict"] as const;
export type KillSwitch = (typeof KILL_SWITCHES)[number];

export const DEFAULT_ACTIONS = ["vpn", "direct", "block"] as const;
export type DefaultAction = (typeof DEFAULT_ACTIONS)[number];

export const RULE_ACTIONS = ["vpn", "direct", "block", "exit_node", "default"] as const;
export type RuleAction = (typeof RULE_ACTIONS)[number];

export const SIMPLE_CONDITION_TYPES = [
    "desktop_id",
    "executable",
    "flatpak_id",
    "snap_id",
    "domain",
    "wildcard_domain",
    "cidr",
    "protocol_port",
    "uid",
] as const;
export type SimpleConditionType = (typeof SIMPLE_CONDITION_TYPES)[number];

export const CONDITION_TYPES = [...SIMPLE_CONDITION_TYPES, "all", "any"] as const;
export type ConditionType = (typeof CONDITION_TYPES)[number];

export type RuleDraft = {
    key: string;
    id: string;
    name: string;
    description: string;
    enabled: boolean;
    priority: number;
    matchMode: "all" | "any";
    action: RuleAction;
    exitNodeId: string;
    conditions: SplitTunnelCondition[];
};

export type Draft = {
    enabled: boolean;
    mode: Mode;
    defaultAction: DefaultAction;
    killSwitch: KillSwitch;
    rules: RuleDraft[];
};

export type RevisionSnapshot = {
    revision: number;
    mode: Mode;
    ruleCount: number;
    at: string;
};

export const modeFrom = (value: string): Mode =>
    MODES.includes(value as Mode) ? (value as Mode) : "standard";

export const killSwitchFrom = (value: string): KillSwitch =>
    KILL_SWITCHES.includes(value as KillSwitch) ? (value as KillSwitch) : "disabled";

export const defaultActionFrom = (value: string): DefaultAction =>
    DEFAULT_ACTIONS.includes(value as DefaultAction) ? (value as DefaultAction) : "vpn";

export const ruleActionFrom = (value: string): RuleAction =>
    RULE_ACTIONS.includes(value as RuleAction) ? (value as RuleAction) : "vpn";

export const isComposite = (type: string): type is "all" | "any" =>
    type === "all" || type === "any";

export const cloneCondition = (condition: SplitTunnelCondition): SplitTunnelCondition => ({
    type: condition.type,
    value: condition.value ?? "",
    children: (condition.children ?? []).map(cloneCondition),
});

const cloneConditions = (conditions: SplitTunnelCondition[] | undefined) =>
    (conditions ?? []).map(cloneCondition);

export const newCondition = (type: ConditionType = "domain"): SplitTunnelCondition => ({
    type,
    value: "",
    children: [],
});

export const newGroup = (type: "all" | "any" = "all"): SplitTunnelCondition => ({
    type,
    value: "",
    children: [newCondition("domain")],
});

let nextKey = 0;

export const newRuleDraft = (): RuleDraft => {
    nextKey += 1;
    return {
        key: `new-${nextKey}`,
        id: "",
        name: "",
        description: "",
        enabled: true,
        priority: 100,
        matchMode: "all",
        action: "vpn",
        exitNodeId: "",
        conditions: [newCondition("domain")],
    };
};

export const ruleDraftFrom = (rule: SplitTunnelRule): RuleDraft => ({
    key: rule.id,
    id: rule.id,
    name: rule.name,
    description: rule.description ?? "",
    enabled: rule.enabled,
    priority: rule.priority,
    matchMode: rule.matchMode === "any" ? "any" : "all",
    action: ruleActionFrom(rule.action),
    exitNodeId: rule.exitNodeId ?? "",
    conditions: cloneConditions(rule.conditions),
});

export const draftFromConfig = (config: SplitTunnelConfig): Draft => ({
    enabled: config.enabled,
    mode: modeFrom(config.mode),
    defaultAction: defaultActionFrom(config.defaultAction),
    killSwitch: killSwitchFrom(config.killSwitch),
    rules: (config.rules ?? []).filter((rule) => rule.supported).map(ruleDraftFrom),
});

export const cloneDraft = (draft: Draft): Draft => ({
    ...draft,
    rules: draft.rules.map(cloneRule),
});

export const cloneRule = (rule: RuleDraft): RuleDraft => ({
    ...rule,
    conditions: rule.conditions.map(cloneCondition),
});

const settingsEqual = (a: Draft, b: Draft): boolean =>
    a.enabled === b.enabled &&
    a.mode === b.mode &&
    a.defaultAction === b.defaultAction &&
    a.killSwitch === b.killSwitch;

export const conditionEqual = (a: SplitTunnelCondition, b: SplitTunnelCondition): boolean => {
    const aChildren = a.children ?? [];
    const bChildren = b.children ?? [];
    return (
        a.type === b.type &&
        (a.value ?? "") === (b.value ?? "") &&
        aChildren.length === bChildren.length &&
        aChildren.every((child, index) => conditionEqual(child, bChildren[index]))
    );
};

export const ruleEqual = (a: RuleDraft, b: RuleDraft): boolean =>
    a.id === b.id &&
    a.name === b.name &&
    a.description === b.description &&
    a.enabled === b.enabled &&
    a.priority === b.priority &&
    a.matchMode === b.matchMode &&
    a.action === b.action &&
    a.exitNodeId === b.exitNodeId &&
    a.conditions.length === b.conditions.length &&
    a.conditions.every((condition, index) => conditionEqual(condition, b.conditions[index]));

export const draftsEqual = (a: Draft, b: Draft): boolean =>
    settingsEqual(a, b) &&
    a.rules.length === b.rules.length &&
    a.rules.every((rule, index) => ruleEqual(rule, b.rules[index]));

export const ruleToInput = (rule: RuleDraft) => ({
    id: rule.id,
    name: rule.name,
    enabled: rule.enabled,
    priority: rule.priority,
    matchMode: rule.matchMode,
    action: rule.action,
    exitNodeId: rule.exitNodeId,
    description: rule.description,
    conditions: rule.conditions.map(cloneCondition),
});

export const appLabel = (apps: { desktopId: string; name: string }[], desktopId: string): string =>
    apps.find((app) => app.desktopId === desktopId)?.name ?? "";

export const protocolPortParts = (value: string): { protocol: string; port: string } => {
    const [protocol, port] = value.split("/");
    return {
        protocol: protocol === "udp" ? "udp" : "tcp",
        port: port ?? "",
    };
};

export type Translate = (key: string, options?: Record<string, unknown>) => string;

export const describeCondition = (
    condition: SplitTunnelCondition,
    t: Translate,
    apps: { desktopId: string; name: string }[],
): string => {
    if (isComposite(condition.type)) {
        const children = (condition.children ?? []).map((child) =>
            describeCondition(child, t, apps),
        );
        return t(
            isComposite(condition.type) && condition.type === "all"
                ? "splitTunnel.rule.allOf"
                : "splitTunnel.rule.anyOf",
            {
                items: children.join(", "),
            },
        );
    }
    const value = condition.value ?? "";
    switch (condition.type) {
        case "desktop_id": {
            const name = appLabel(apps, value);
            return t("splitTunnel.rule.describe.application", {
                value: name ? `${name} (${value})` : value,
            });
        }
        case "domain":
            return t("splitTunnel.rule.describe.domain", { value });
        case "wildcard_domain":
            return t("splitTunnel.rule.describe.wildcard", { value });
        case "cidr":
            return t("splitTunnel.rule.describe.cidr", { value });
        case "protocol_port":
            return t("splitTunnel.rule.describe.protocolPort", { value });
        case "uid":
            return t("splitTunnel.rule.describe.uid", { value });
        case "executable":
            return t("splitTunnel.rule.describe.executable", { value });
        case "flatpak_id":
            return t("splitTunnel.rule.describe.flatpak", { value });
        case "snap_id":
            return t("splitTunnel.rule.describe.snap", { value });
        default:
            return `${condition.type}: ${value}`;
    }
};

export const validateRule = (rule: RuleDraft, mode: Mode, t: Translate): string[] => {
    const issues: string[] = [];
    if (rule.name.trim() === "") issues.push(t("splitTunnel.rule.error.name"));
    if (rule.name.length > 256) issues.push(t("splitTunnel.rule.error.nameLength"));
    if (rule.description.length > 1024) issues.push(t("splitTunnel.rule.error.descriptionLength"));
    if (!Number.isInteger(rule.priority) || rule.priority < 0 || rule.priority > 1_000_000) {
        issues.push(t("splitTunnel.rule.error.priority"));
    }
    if (rule.action === "default" && mode !== "custom") {
        issues.push(t("splitTunnel.rule.error.defaultActionMode"));
    }
    if (rule.action === "exit_node" && rule.exitNodeId.trim() === "") {
        issues.push(t("splitTunnel.rule.error.exitNode"));
    }
    if (rule.action !== "exit_node" && rule.exitNodeId.trim() !== "") {
        issues.push(t("splitTunnel.rule.error.exitNodeUnexpected"));
    }
    if (rule.conditions.length === 0) {
        issues.push(t("splitTunnel.rule.error.conditions"));
    }
    issues.push(...validateConditions(rule.conditions, t));
    return issues;
};

const validateConditions = (conditions: SplitTunnelCondition[], t: Translate): string[] => {
    const issues: string[] = [];
    for (const condition of conditions) {
        if (isComposite(condition.type)) {
            if ((condition.children ?? []).length === 0) {
                issues.push(t("splitTunnel.rule.error.groupEmpty"));
            }
            issues.push(...validateConditions(condition.children ?? [], t));
            continue;
        }
        const value = (condition.value ?? "").trim();
        if (value === "") {
            issues.push(t("splitTunnel.rule.error.value"));
            continue;
        }
        if (condition.type === "wildcard_domain" && !value.startsWith("*.")) {
            issues.push(t("splitTunnel.rule.error.wildcard"));
        }
        if (condition.type === "wildcard_domain" && (value.match(/\*/g) ?? []).length !== 1) {
            issues.push(t("splitTunnel.rule.error.wildcard"));
        }
        if (condition.type === "desktop_id" && !value.endsWith(".desktop")) {
            issues.push(t("splitTunnel.rule.error.desktopId"));
        }
        if (condition.type === "protocol_port") {
            const { protocol, port } = protocolPortParts(value);
            const parsed = Number(port);
            if (
                (protocol !== "tcp" && protocol !== "udp") ||
                !Number.isInteger(parsed) ||
                parsed < 1 ||
                parsed > 65535
            ) {
                issues.push(t("splitTunnel.rule.error.protocolPort"));
            }
        }
        if (condition.type === "uid" && !/^\d+$/.test(value)) {
            issues.push(t("splitTunnel.rule.error.uid"));
        }
    }
    return issues;
};

export const isUnavailableCode = (code: string): boolean =>
    code === "split_tunnel_unavailable" ||
    code === "split_tunnel_version_unsupported" ||
    code === "split_tunnel_backend_unavailable";
