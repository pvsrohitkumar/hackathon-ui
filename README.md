# hackathon-ui

# Angular Security Lab

An Angular 17 training application containing deliberately vulnerable, local-only exercises. Use it to practice identifying insecure client-side patterns and designing the server-side controls that should replace them.

## Run locally

```bash
npm install
npm start
```

Open `http://localhost:4200/`. The app does not call a backend or send exercise input anywhere. Do not deploy this project or reuse its vulnerable patterns in a production application.

## Exercise register

- Untrusted HTML preview: unsafe HTML rendering and injection risk.
- Profile object reference: insecure direct object reference (IDOR).
- Unvalidated return URL: open redirect risk.
- Token in browser storage: client-side token exposure.
- Client-side role update: mass assignment and privilege escalation.
- UI-only admin gate: authorization enforced only in the UI.
- Weak password policy: incomplete client-side validation.
- Verbose error details: implementation and data disclosure.

The intended workflow is to reproduce each behavior, identify the trust boundary, then replace the vulnerable behavior with a secure implementation and a focused test.

## Validate

```bash
npm run build
```
