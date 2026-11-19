# Dashboard UX & CRUD overhaul — task list

Scope: the customer dashboard (station owners) and the admin console in `src/dashboard/*`,
plus the SMTP settings in `src/lib/{mail,settings}.ts`.

Sizes: **S** < ½ day · **M** ≈ 1 day · **L** ≥ 2 days. `[x]` = done on this branch.

---

## Why it does not feel smooth (root causes)

| #  | Problem | Effect |
|----|---------|--------|
| R1 | Every validation error redirects through `back()` and throws the typed values away; the error is a page-level banner, not next to the field. | Re-typing whole forms (plans, add person, create station, claim, settings). |
| R2 | No modal: confirmations are the browser's `confirm()`; typed-confirm deletes sit open on the page. | Context-free grey dialogs; red delete forms always visible. |
| R3 | No pagination: lists are silently cut at 50/100/200/300 rows. | Older rows (audit, people #201…) are unreachable except by search. |
| R4 | No dropdown/row-action menus: every action is an inline button, destructive next to safe. | Mis-taps (Suspend beside Open); cluttered rows on phones. |
| R5 | No submit/loading state. | Double submits; slow tests look frozen. |
| R6 | Wrong control for the choice (`<select>` for 2–3 options, filters behind a "Filter" button). | Extra clicks; options not visible. |

Missing confirmations: sign out device / all others, switch payment provider, DNS provider → None,
add name (silently overwrites).

---

## Phase 0 — SMTP (host / port / security / username / password)

Today SMTP is a single secret URL (`smtps://user:pass@host:465`): passwords with `@ : / # ? %` or
spaces break it, the whole URL must be re-typed to change one part, there is no SSL/STARTTLS
choice, and it can only be tested after saving.

- [x] 1. **M** Split SMTP into `smtpHost`, `smtpPort`, `smtpSecurity` (`ssl`·`starttls`·`none`), `smtpUser`, `smtpPassword` (secret) in `config.ts`, `lib/settings.ts`, `lib/mail.ts`; nodemailer transport built from an options object. `SMTP_URL` (env and a previously saved setting) is still read and split into the fields.
- [x] 2. **M** New Email settings form: provider presets (Gmail, Microsoft 365, SES, Mailgun, Postmark, SendGrid, Brevo, Zoho, Custom), security radio cards that set the default port, port, username, password with show/hide and "remove password", sender name + sender email.
- [x] 3. **S** "Send test email" uses the values in the form (before saving) to a chosen address: `verify()` then send, with plain-language errors (auth, connection, timeout, TLS mismatch, DNS, sender rejected).
- [x] 4. **S** Setup checks / overview / `setup.sh` / `.env.example` / README / tests updated.

## Phase 1 — Shared UI building blocks (`html.ts`, `/static/app.js`)

- [ ] 5. **M** Form state: errors keep the typed values (never secrets) and show the message under the field (`aria-invalid`), via a short-lived cookie next to the flash.
- [ ] 6. **M** Modal on native `<dialog>` (CSP-safe): every `data-confirm` becomes a styled confirm dialog; typed-confirm dialogs (submit enabled only when the text matches); forms inside dialogs.
- [ ] 7. **M** Action menu (`⋯` on rows, "Actions ▾" on pages): keyboard usable, closes on Esc / outside click / another menu opening, positioned so table scrolling does not clip it.
- [ ] 8. **M** Pagination: one query helper (page, per page, total) + footer "Showing 51–100 of 812 · ‹ 1 2 3 … ›" keeping the other query parameters.
- [ ] 9. **S** Filter bar: search, status chips (links), selects that apply on change; all in the URL.
- [ ] 10. **S** Submit buttons show a busy state and block double submits.
- [ ] 11. **S** Radio-card and segmented-control helpers; `<thead>/<tbody>` tables; phone menu closes on Esc / outside click; user menu on the avatar.

## Phase 2 — Admin lists

- [ ] 12. **M** People: pagination, filters (role, status, 2FA, email confirmed, invited), row menu, "Actions ▾" on the person page, delete in a typed-confirm modal.
- [ ] 13. **M** All stations: pagination, status filter (online/offline/suspended), row menu (open, suspend/restore, delete via modal), create form keeps values.
- [ ] 14. **M** Audit log, DNS & ACME events, Payments, Audio relay: pagination, date range, level/status chips, expandable metadata, search on payments.
- [ ] 15. **S** Names and Certificates: pagination and search; "Retry now" on failed/waiting certificates.

## Phase 3 — Admin CRUD gaps

- [ ] 16. **S** Plan form keeps values and shows field errors; the default plan cannot be deleted; delete in a modal stating how many people move.
- [ ] 17. **M** Edit a person's email (new address must be confirmed; old address told); "Invited" state; "Resend invite".
- [ ] 18. **S** Edit a reserved/blocked name (kind, reason); adding one that exists warns instead of overwriting.
- [ ] 19. **S** Payment detail page; Role, Name kind, DNS provider and certificate environment as radio cards; confirmations for provider switch, DNS → None, production certificates.

## Phase 4 — Station-owner side

- [ ] 20. **S** Claim / rename keep the typed name; station delete in a typed-confirm modal; confirmations before signing devices out.
- [ ] 21. **L** Two-step recovery codes (10 single-use, shown once, regenerate, usable at sign-in and to confirm identity); "Cancel" for an unfinished two-step setup.
- [ ] 22. **M** Change your own email (sudo; link to the new address; notice to the old one).
- [ ] 23. **M** Delete your own account (sudo + typed confirm modal; the super admin must hand over the role first).
- [ ] 24. **S** Billing history pagination + receipt page; confirm-password and show/hide on sign-up and reset.

---

## Control changes (R6)

| Was | Where | Now |
|-----|-------|-----|
| select Owner/Admin | role, add person | radio cards |
| select Blocked/Reserved | names | radio cards |
| select Cloudflare/None | DNS provider | radio cards (None confirms) |
| select Staging/Production | certificates | radio cards (Production confirms) |
| select month/year | plan period | segmented control |
| select + Filter button | payments | status chips |
| — | SMTP security | radio cards |
