# Changelog

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
