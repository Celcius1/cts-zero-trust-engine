# CTS Zero Trust Engine (ZTE) 🛡️

**A sovereign, air-gappable Layer 7 API gateway, cryptographic vault, and Server-Driven UI (SDUI) orchestrator.**

Developed by **Cel-Tech-Serv Pty Ltd**.

## The Architecture
The CTS Zero Trust Engine deprecates vulnerable, browser-based web applications and legacy perimeter VPNs. It operates as an impenetrable cryptographic gateway, serving native user interfaces directly to our universal rendering client. 

*   **Backend Core:** C++ API Gateway executing Zero-Trust validation, identity management, and PostgreSQL ledger storage.
*   **The Agnostic Client:** C# Avalonia UI desktop application functioning purely as a "dumb renderer." It connects securely and draws the interface based on dynamically generated JSON payloads, ensuring no business logic is ever exposed to the client hardware.
*   **Networking:** Natively integrates with isolated WireGuard containers to enforce strict, hardware-level perimeter access before any Layer 7 traffic is permitted.

## License
This project is strictly licensed under the **GNU Affero General Public License v3.0 (AGPL-3.0)**. 
See the `LICENSE` file for full legal details.
