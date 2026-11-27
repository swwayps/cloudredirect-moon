# cloudredirect-moon

A fork of [CloudRedirect](https://github.com/Selectively11/CloudRedirect). This
fork adds cross-distro attach fixes, legacy save-layout healing, and
worker-thread crash containment on Linux.

`./build.sh` produces a 64-bit `cloud_redirect.so` for the current Linux Steam
client, plus `cloud_redirect32.so` and `cloud_redirect_cli32` for legacy 32-bit
Steam processes. The standard CLI is built for 64-bit. The Steam hook is loaded
via `LD_PRELOAD`.

The 64-bit build can discover the x86_64 Steam transport and RemoteStorage
vtables and install their hooks. Cloud RPC interception, playtime tracking, and
KV metadata injection still depend on x86-specific protobuf helpers, layouts,
or trampolines and remain disabled on x86_64. This is not yet a functional
replacement for the 32-bit runtime.

## Credits

Upstream:

- [Selectively11](https://github.com/Selectively11) and contributors —
  the CloudRedirect hook this fork builds on.

## Support

Open an issue: https://github.com/swwayps/cloudredirect-moon/issues
