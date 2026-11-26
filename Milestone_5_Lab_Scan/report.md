# Milestone 5: Read a Bounded Lab Scan

Interpretation of the supplied synthetic loopback fixture `synthetic-scan.txt` (`127.0.0.1` only; no external targets scanned).

---

## 1. Port & Service Summary (`127.0.0.1`)

| Port / Protocol | State | Reported Service Label | Observation |
|---|---|---|---|
| `22/tcp` | `closed` | `ssh` | Connection refused / no active SSH daemon listening on loopback in this fixture. |
| `80/tcp` | `closed` | `http` | Standard HTTP port is not accepting connections on loopback. |
| `8765/tcp` | `open` | `training-http` | A socket is listening on high port `8765` labeled illustratively as `training-http`. |

---

## 2. Why an Open Port or Banner Does NOT Prove a Vulnerability

- **An open port only shows reachability:** Seeing `8765/tcp open` simply means a process bound a TCP socket and accepted a connection. Local development servers, health probes, or authorized internal services routinely listen on loopback ports safely.
- **A service label or banner is not proof of an exploit:** Labels like `training-http` are heuristic guesses (or illustrative text) based on port tables or brief strings. They do **not** establish the exact software product, compiled version, patch backports, authentication requirements, or whether any vulnerable endpoint actually exists.

---

## 3. Recommended Defensive Checks

1. **Intended Exposure & Bind Address Check:** Verify whether the service on `8765/tcp` is still needed and confirm it is bound strictly to `127.0.0.1` rather than `0.0.0.0` (all interfaces), supported by host firewall rules.
2. **Vendor Patch Status & Configuration Audit:** Identify the actual process/package running on the port, confirm it is updated to a supported vendor release with security patches applied, and check authentication, access controls, and TLS requirements if exposed beyond loopback.

---

## 4. Ordinary vs. Boundary Interpretation Case

- **Ordinary Case:** Reading `8765/tcp open training-http` on `127.0.0.1` leads to checking the local process inventory, verifying bind scope (`127.0.0.1` vs `0.0.0.0`), and confirming patch status before taking action.
- **Boundary / Failure Case:** Treating `22/tcp closed ssh` or `8765/tcp open` as an automatic CVE finding without verifying software version or reachability leads to false positives, while running scans outside explicitly authorized loopback addresses/ports fails scope boundaries.
- **Takeaway:** Port scan output is a starting inventory signal for verification, never standalone proof of compromise or exploitability.
