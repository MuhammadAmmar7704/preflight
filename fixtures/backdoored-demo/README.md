# backdoored-demo

Synthetic fixture modeled on the May 2026 `node-ipc` backdoor.

It is intentionally shaped like malware:

- top-level code that forks a detached child process
- reads `.npmrc`, SSH keys, AWS credentials, and git credentials
- base64-encodes the loot
- attempts DNS TXT exfiltration to `*.example.invalid`
- ships a `postinstall` script

It does **not** contact a real endpoint and should only be used inside the
Preflight sandbox or another disposable container.

Build the tarball:

```bash
cd fixtures/backdoored-demo
tar -czf ../backdoored-demo-1.0.0.tgz package
```
