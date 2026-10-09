# Changelog

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
