// Package classifier assigns running applications to owned cgroup v2 scopes so
// the Linux split tunnel backend can match their sockets before routing.
//
// The classifier does not intercept process creation. It moves a process into
// its scope when the process is observed, or starts a process directly in the
// scope through the managed launcher. A socket that already exists when the
// move happens keeps the cgroup it was created in, so it is not reclassified
// retroactively. For an already-running application, only sockets created after
// the move are classified; the caller must report that limitation instead of
// claiming browser-level attribution for pre-existing connections.
//
// Shared services and local proxies are also not attributed: traffic that leaves
// a process outside the application scope follows the policy default. A policy
// that needs a stricter outcome must set its default action to VPN or block.
package classifier
