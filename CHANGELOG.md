# Changelog

## [0.4.0](https://github.com/exitCodeNihil/qafas-sandbox/compare/v0.3.2...v0.4.0) (2026-10-20)


### Features

* **agent:** POST /ca and Chromium trust for the egress CA ([41ad09a](https://github.com/exitCodeNihil/qafas-sandbox/commit/41ad09aec59e043ed713c86ee76e7fd97e90a33e))
* **egress:** terminate TLS for route hosts, swap credentials, L7 rules ([0c339ef](https://github.com/exitCodeNihil/qafas-sandbox/commit/0c339efaa25c6357815fba307bc42482e2057a67))
* **proto:** add egress routes for credential injection and L7 rules ([8a1d547](https://github.com/exitCodeNihil/qafas-sandbox/commit/8a1d547024117d7feac9c75e110d664fd09f81d1))
* **vm:** choose the OCI runtime for vm sandboxes ([b9a622d](https://github.com/exitCodeNihil/qafas-sandbox/commit/b9a622d5bc578096e81e3011a82112c2bdbeddd2))


### Bug Fixes

* **doctor:** keep log lines out of doctor --json stdout ([0dd8fa2](https://github.com/exitCodeNihil/qafas-sandbox/commit/0dd8fa29db6582684b9cf3bf472281968877b3d2))
* **egress:** allow a route host wildcard only as a whole leftmost label ([21a2ec9](https://github.com/exitCodeNihil/qafas-sandbox/commit/21a2ec9545e2190255eee02eedfd2a0d7a21010c))
* **egress:** answer 400 for a target with no origin form, not send / ([e3ec009](https://github.com/exitCodeNihil/qafas-sandbox/commit/e3ec0093c80acc716c56a8d41b824beee58a1efb))
* **egress:** attribute egress events to the tool call ([fa8d954](https://github.com/exitCodeNihil/qafas-sandbox/commit/fa8d954dea09e443cbe139f88beadc204aff690a))
* **egress:** drop method overrides on rule routes, ranges on secret ones ([e8e5265](https://github.com/exitCodeNihil/qafas-sandbox/commit/e8e5265e82891a5fdd65c9aa4e98fc23e0ced466))
* **egress:** emit egress.deny when the upstream connect fails ([63eb1c6](https://github.com/exitCodeNihil/qafas-sandbox/commit/63eb1c664c50e9649d82a3220f9f461fcdfc9861))
* **egress:** honour egress_allow on the vm and remote tiers ([4139323](https://github.com/exitCodeNihil/qafas-sandbox/commit/41393238ef86ec4813a79847f1f8562b95e4d98f))
* **egress:** keep the egress proxy serving through accept errors ([29768cb](https://github.com/exitCodeNihil/qafas-sandbox/commit/29768cb5a606de898fc96d0f494d4a7e4acca8b0))
* **egress:** keep TLS bytes sent right behind a CONNECT to a route host ([c7a3c87](https://github.com/exitCodeNihil/qafas-sandbox/commit/c7a3c878862552d8c05c13f0c98358a2fdfe33fc))
* **egress:** pass bytes sent behind CONNECT into the blind tunnel ([e852df6](https://github.com/exitCodeNihil/qafas-sandbox/commit/e852df6ac37e4c3b159b071828c63ec89fa266b0))
* **egress:** read every content and transfer coding before scrubbing ([f5c3bc2](https://github.com/exitCodeNihil/qafas-sandbox/commit/f5c3bc26cecf079a4c08beef7076436eff572302))
* **egress:** refuse a route host when the peer lookup fails ([305aeea](https://github.com/exitCodeNihil/qafas-sandbox/commit/305aeea04224615e12dea2bc2d505626e899c0e8))
* **egress:** refuse double-encoded and non-UTF-8 paths on rule routes ([92cd5a1](https://github.com/exitCodeNihil/qafas-sandbox/commit/92cd5a17f9e901216e3de7d5b22e4b374ebfe579))
* **egress:** refuse IPv4 hidden in NAT64, 6to4 and Teredo addresses ([3a04da4](https://github.com/exitCodeNihil/qafas-sandbox/commit/3a04da403f640866cd908f440e64353dbaf64d62))
* **egress:** refuse routes whose hosts, ports and trust overlap ([7f27f83](https://github.com/exitCodeNihil/qafas-sandbox/commit/7f27f831e223e749bcb97b5e87e0339ca91c4142))
* **egress:** relay only a websocket upgrade on a route tunnel ([c34137e](https://github.com/exitCodeNihil/qafas-sandbox/commit/c34137ea9acd0f5d9af90569d1e6e5eca682a2a1))
* **egress:** send the canonical reason phrase, never the upstream's ([dc92732](https://github.com/exitCodeNihil/qafas-sandbox/commit/dc927329ae42473c1b54d7ef7dc3335acae8eb3d))
* **guest:** drain the log queue before the agent exits ([4b6648f](https://github.com/exitCodeNihil/qafas-sandbox/commit/4b6648fc9668621ea0107021050b4f5aa7b445e8))
* **guest:** keep a stalled console from blocking the agent ([11ac15e](https://github.com/exitCodeNihil/qafas-sandbox/commit/11ac15eb4fd6cadb4cc5587f5c3b0e4f7109aa39))
* **guest:** keep the agent token out of /proc/1/environ on gVisor ([9de25f5](https://github.com/exitCodeNihil/qafas-sandbox/commit/9de25f565c272e65df203db0868695d87b121e2c))
* **native:** hide the daemon's state directory from native sandboxes ([200f7ea](https://github.com/exitCodeNihil/qafas-sandbox/commit/200f7ea52be265a6e2e99358c7a5a40a1325d6fe))
* **native:** hide the state dir and route secret files from sandboxes ([d5c933a](https://github.com/exitCodeNihil/qafas-sandbox/commit/d5c933aee40d7223e842f0fc8de016112a49fc2f))
* **native:** keep the proxy bridge and relay up through accept errors ([ddc6fae](https://github.com/exitCodeNihil/qafas-sandbox/commit/ddc6fae792638590bab5b1e538c408685f60d587))
* **native:** let a private-netns sandbox use its own loopback ([a01b0c2](https://github.com/exitCodeNihil/qafas-sandbox/commit/a01b0c219da439f08efd21e81494128e7a0dc056))
* **native:** let Linux native commands reach their own egress proxy ([794aebd](https://github.com/exitCodeNihil/qafas-sandbox/commit/794aebdb1ca76218e6e964d3750496225ad15310))
* **native:** remove a failed create's scratch and name the ns limit ([b737289](https://github.com/exitCodeNihil/qafas-sandbox/commit/b73728976660dbde7317ee09eba3684f1ab77497))
* **native:** run Linux native sandboxes in a private network namespace ([e74c353](https://github.com/exitCodeNihil/qafas-sandbox/commit/e74c353b780dd5e3827f683837c13013ad0254eb))
* **preview:** decode the percent-encoded colon in a query token ([f8fcee3](https://github.com/exitCodeNihil/qafas-sandbox/commit/f8fcee3a4734385cd14f8c71ca71c085f64fcb2c))
* **preview:** reach Linux native dev servers through the shim ([cef1d27](https://github.com/exitCodeNihil/qafas-sandbox/commit/cef1d279878064b36992c1a2a552aeb003785c5a))
* **remote:** give every snapshot clone its own randomness ([98fc031](https://github.com/exitCodeNihil/qafas-sandbox/commit/98fc03118fb4d10d9c1c55bfb791c3a3fbe79fa1))
* **remote:** keep the argv of processes that exit before /proc is read ([7c07537](https://github.com/exitCodeNihil/qafas-sandbox/commit/7c07537c1fc3068783f3edde71f4c7522af398d9))
* **remote:** post /restored once per restore ([45c92fa](https://github.com/exitCodeNihil/qafas-sandbox/commit/45c92fad7edd752cd02fa5f597955be2d969ddef))
* **remote:** remove leftover cgroups at sweep and on failed create ([db40a64](https://github.com/exitCodeNihil/qafas-sandbox/commit/db40a6420c9a91e01db6a94f13caefc6778fc0aa))
* **remote:** remove the firecracker cgroup once the VM is gone ([e65c8d2](https://github.com/exitCodeNihil/qafas-sandbox/commit/e65c8d22a7f4fe330d97819e7c77ef4b0752df22))
* **remote:** report a microVM ready only once bpftrace is attached ([fbd1b32](https://github.com/exitCodeNihil/qafas-sandbox/commit/fbd1b32a839e2556edd3e0bd36d5eb0d4d9a7e6c))
* **shutdown:** stop waiting for a booting guest and bound the exit ([91d2eb0](https://github.com/exitCodeNihil/qafas-sandbox/commit/91d2eb0f1191e4351727152b6c2261d3672bb3db))

## [0.3.2](https://github.com/exitCodeNihil/qafas-sandbox/compare/v0.3.1...v0.3.2) (2026-10-16)


### Bug Fixes

* **alerts:** raise ptrace.attempt for strace, ltrace and gdb attach ([b93733f](https://github.com/exitCodeNihil/qafas-sandbox/commit/b93733f52060afdae5c6039dba4eec3eb5fe178d))
* **docker:** start on Docker 28 when the proxy's pinned IP is refused ([fc51f25](https://github.com/exitCodeNihil/qafas-sandbox/commit/fc51f2565967298dcdb561f77757c7741273fa86))
* **events:** keep guest alerts flowing through lag and redials ([a0ce9a9](https://github.com/exitCodeNihil/qafas-sandbox/commit/a0ce9a9736c9e9e7e7ed132ded79de904abe46f0))
* **exec:** close the WebSocket after Exit ([00f5b45](https://github.com/exitCodeNihil/qafas-sandbox/commit/00f5b453332de16f4aa5e47128596cdb587ce598))
* **exec:** enforce timeout_ms on output pipes, not only the root ([d8abdfb](https://github.com/exitCodeNihil/qafas-sandbox/commit/d8abdfbab10110c2383f17152a5deaaa963cf528))
* **exec:** kill processes left stopped after their tracer died ([0032548](https://github.com/exitCodeNihil/qafas-sandbox/commit/003254884fa8e63937ee9649aa4184c29bd88ba3))
* **native:** refuse UDP sockets in Linux native sandboxes ([7a8944c](https://github.com/exitCodeNihil/qafas-sandbox/commit/7a8944c6d36e554810eedd5b7200ff32a8ca31e6))
* **proto:** align rule severities with the protocol ([fd10fc5](https://github.com/exitCodeNihil/qafas-sandbox/commit/fd10fc5a8c309a814a2566705cd306904076a9c1))
* **remote:** restart a stopped microVM while the old one tears down ([7d0eae6](https://github.com/exitCodeNihil/qafas-sandbox/commit/7d0eae694a793da1f0d391fbf6acf8596264c302))
* **remote:** wait for firecracker's sockets to accept, not to exist ([9e90b71](https://github.com/exitCodeNihil/qafas-sandbox/commit/9e90b71fffcc921cd266df17f35d74636cca9fc5))

## [0.3.1](https://github.com/exitCodeNihil/qafas-sandbox/compare/v0.3.0...v0.3.1) (2026-10-14)


### Bug Fixes

* **guest:** track an exec pid before the PID 1 reaper can reap it ([bafd08e](https://github.com/exitCodeNihil/qafas-sandbox/commit/bafd08ec588dd4e3201846472875c35b98a6807e))
* **guest:** watch the workspace owner's home, not a root daemon's ([1d3c1a8](https://github.com/exitCodeNihil/qafas-sandbox/commit/1d3c1a857f3150c6f0d99e39c6bc69d4e1c9d91e))
* log why a create failed and when base.warm overrides pool_size ([32e8daa](https://github.com/exitCodeNihil/qafas-sandbox/commit/32e8daa57be949e573c01d318fec6bf138272a57))
* **native:** make the native tier work on Linux ([f3b3b99](https://github.com/exitCodeNihil/qafas-sandbox/commit/f3b3b99d491fd12ba74921b6e3c45e4b6a273f57))
* **pool:** no leaks on a failed resize or at shutdown; keep workspaces ([ddfcb8d](https://github.com/exitCodeNihil/qafas-sandbox/commit/ddfcb8d2b2ea6505262ca59fec9819def2ac5786))
* **scan:** tear down the scan sandbox when the daemon stops mid-scan ([f0a91d6](https://github.com/exitCodeNihil/qafas-sandbox/commit/f0a91d60585028ce1637df2b6509f7e8bde4da44))
* **vm:** clean up failed starts and serialise rootless keep-id creates ([1ec6ccb](https://github.com/exitCodeNihil/qafas-sandbox/commit/1ec6ccb232662806bb13a351fb4844a3b86d6f54))


### Performance Improvements

* set TCP_NODELAY on every hop and stream reads in 64 KiB chunks ([5976dfc](https://github.com/exitCodeNihil/qafas-sandbox/commit/5976dfc81513d3efe52c5c505689e70e51bad9c3))

## [0.3.0](https://github.com/exitCodeNihil/qafas-sandbox/compare/v0.2.0...v0.3.0) (2026-10-13)


### Features

* **sdk:** publish the SDKs to npm, PyPI, crates.io and Maven Central ([3b9892d](https://github.com/exitCodeNihil/qafas-sandbox/commit/3b9892d2243c00a8f841f01ad185c7b56c8b2816))

## [0.2.0](https://github.com/exitCodeNihil/qafas-sandbox/compare/v0.1.0...v0.2.0) (2026-10-09)


### Features

* **sdk:** Go SDK with full Python parity ([bf12971](https://github.com/exitCodeNihil/qafas-sandbox/commit/bf129713c02a5e9a7ecc48839df5998c59b4d0ad))
* **sdk:** Java SDK with full Python parity ([884e1aa](https://github.com/exitCodeNihil/qafas-sandbox/commit/884e1aabfd3d5fa9ac7ebfacf621297f40274aa1))
* **sdk:** Rust SDK with full Python parity ([9b9075b](https://github.com/exitCodeNihil/qafas-sandbox/commit/9b9075b71ef2456950bc2da6b93047290ca0995c))


### Bug Fixes

* **alerts:** drop the .netrc canary, match setuid names as commands only ([49ef157](https://github.com/exitCodeNihil/qafas-sandbox/commit/49ef1577876f929b4e12b2005ab029a6c7846bca))
* **sdk:** destroy() is idempotent in the Python and TypeScript SDKs ([caaec0f](https://github.com/exitCodeNihil/qafas-sandbox/commit/caaec0fe8fbaf9aa6ce43c417da6419c732c4be9))
* **sessions:** a command's trailing stderr stays with that command ([955fa7d](https://github.com/exitCodeNihil/qafas-sandbox/commit/955fa7d17ae4b4c90b31ccdf6a68050cd57bfe28))
* **vm:** sandboxes can signal their own processes on podman with crun ([40b926e](https://github.com/exitCodeNihil/qafas-sandbox/commit/40b926edf633b4a449b96c93a0e611078bfcbe58))

## 0.1.0 (2026-10-09)


### Features

* Qafas Sandbox, a secure execution sandbox for LLM coding agents ([8e0f83b](https://github.com/exitCodeNihil/qafas-sandbox/commit/8e0f83be7366212ee6fd9b13d7c46aafe50219f0))
