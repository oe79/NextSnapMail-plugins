# NextSnapMail plugins

Plugin repository for NextSnapMail.

This repository is intended to be published through GitHub Pages and consumed by
NextSnapMail as a SnappyMail-compatible plugin repository.

Gmail / Google OAuth2 login is no longer distributed as a separate plugin. It is
integrated directly into NextSnapMail starting with version `0.1.11`.

Repository URL after GitHub Pages is enabled:

```text
https://oe79.github.io/NextSnapMail-plugins/repository/v2/
```

## Structure

- `repository/v2/packages.json` – plugin index read by NextSnapMail
- `repository/v2/plugins/` – packaged plugin archives (`.tgz`)
- `plugins/` – plugin source folders

## Notes

Packages listed in `packages.json` should use file paths relative to
`repository/v2/`, for example:

```json
{
  "type": "plugin",
  "id": "login-gmail-oauth",
  "name": "Login Gmail OAuth2",
  "version": "0.4",
  "release": "2026-08-05",
  "file": "plugins/login-gmail-oauth-0.4.tgz",
  "required": "2.36.1",
  "description": "Gmail and Google Workspace IMAP/SMTP login using current Google OAuth2 endpoints"
}
```

At the moment, no external plugin package is published here.
