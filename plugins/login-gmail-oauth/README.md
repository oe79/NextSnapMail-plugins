# Login Gmail OAuth2

Experimental NextSnapMail Gmail/Google Workspace OAuth2 login plugin.

This plugin is intentionally separate from the legacy `login-gmail` plugin. It
uses current Google OAuth2 endpoints and keeps the old plugin untouched while
the new flow is tested.

It supports two flows:

- login from the classic SnappyMail/NextSnapMail login screen
- adding a Gmail/Google Workspace address as an additional account from the
  user account settings

## Google Cloud configuration

Create an OAuth client of type "Web application" in Google Cloud Console and add
the redirect URI shown in the plugin settings.

Typical Nextcloud redirect URI:

```text
https://example.com/index.php/apps/nextsnapmail/?LoginGmailOauth
```

When enabled, the plugin can automatically create Gmail-style domain
configuration entries for configured domains, using:

- IMAP: `imap.gmail.com:993` SSL/TLS
- SMTP: `smtp.gmail.com:587` STARTTLS

The plugin requests:

- `openid`
- `email`
- `profile`
- `https://mail.google.com/`

The `https://mail.google.com/` scope is required for Gmail IMAP/SMTP OAuth2.

## Status

Experimental. It should be tested on a non-critical account first.
