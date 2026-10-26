# @worldlibertyfinancial/railgun-engine-fork

**Status: skeleton only.** Do not import from this package until Track 3
lands the engine fork.

Track 3 will vendor and modify roughly 10k lines of
[`@railgun-community/engine`](https://github.com/Railgun-Community/engine)
so that every spending-key, viewing-key, and nullifier access is routed
through the AgentPay Rust daemon instead of an in-process secret. That
work is genuinely multi-week and is not part of this package's current
revision.

The package currently exports a single sentinel
(`RAILGUN_ENGINE_FORK_STATUS`) and a `notVendoredYet(method)` helper that
throws with a clear message. Anything else fails fast on purpose.

See [`MAINTENANCE.md`](./MAINTENANCE.md) for the upstream pin, the rebase
cadence, the exact files we will replace key-access calls in, and the
circuit artifact versioning policy.
