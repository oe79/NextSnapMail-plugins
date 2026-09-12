# NextSnapMail plugins

Plugin repository for NextSnapMail.

This repository is intended to be published through GitHub Pages and consumed by
NextSnapMail as a SnappyMail-compatible plugin repository.

Gmail / Google OAuth2 login is no longer distributed as a separate plugin. It is
integrated directly into NextSnapMail starting with version `0.1.11`.

The repository may provide legacy SnappyMail plugins for administrators who
still need them. These packages are offered as old and untested compatibility
plugins. Install and use them at your own risk.

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
  "id": "example-plugin",
  "name": "Example Plugin",
  "version": "1.0",
  "release": "2026-09-12",
  "file": "plugins/example-plugin-1.0.tgz",
  "required": "2.38.0",
  "description": "Legacy / untested SnappyMail plugin. Use at your own risk."
}
```

Legacy Gmail plugins are intentionally not published here because Gmail / Google
OAuth2 support is integrated directly into NextSnapMail.
