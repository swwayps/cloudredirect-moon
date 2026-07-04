# cloudredirect-moon

A branch of [CloudRedirect](https://github.com/Selectively11/CloudRedirect)
that redirects Steam Cloud reads/writes to the user's own storage. This branch
adds cross-distro attach fixes, legacy save-layout healing, and worker-thread
crash containment on the Linux 32-bit hook.

The result is a 32-bit `cloud_redirect.so`, loaded into Steam via `LD_PRELOAD`.

## Credits

Upstream:

- [Selectively11](https://github.com/Selectively11) and contributors —
  the CloudRedirect hook this branch builds on.

## Support

Open an issue: https://github.com/swwayps/cloudredirect-moon/issues
