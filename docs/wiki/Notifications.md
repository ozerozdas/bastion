# Notifications

Notifications are opt-in and off by default. Turn them on in **Configuration →
Notifications**: pick a threshold (**Critical and high**, the default, or
**Critical only**) and configure Slack, email, or both. A Slack incoming-webhook
URL is stored in the OS keyring, never in SQLite, and the API only reports
whether one is configured.

Email sends through SMTP submission with **STARTTLS required**: set the host,
the port (587 by default), the sender, one or more comma-separated recipients,
and optionally a username and password. There is no plain-text fallback, and
implicit TLS on port 465 is not supported. The password is stored in the OS
keyring and is never returned by the API; clearing it leaves the rest of the
settings intact.

After a scan succeeds, bastion diffs it against the asset's previous succeeded
scan and posts one short message per enabled notifier when at least one new
finding meets the threshold. The first scan of an asset sends nothing: with no
baseline every finding would look new and a fresh install would flood the
channel. A notification failure is logged and never affects the scan.


## Scheduled scans


Set a project or image to scan daily or weekly from its **Schedule** column. Schedules
run only while `bastion serve` is open; a scan missed while it was closed runs once at the
next start.
