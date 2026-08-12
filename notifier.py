"""
notifier.py

Cross-platform desktop popup notifications + optional instant mobile push
(via ntfy.sh), with a simple cooldown so the same finding doesn't spam the
user every poll cycle.
"""

import time
import logging
import smtplib
from email.mime.text import MIMEText

import requests

try:
    from plyer import notification as _plyer_notification
except Exception:  # plyer may not have a backend on some minimal systems
    _plyer_notification = None

logger = logging.getLogger("ram_guard.notifier")


class Notifier:
    def __init__(self, enabled: bool = True, cooldown_seconds: int = 120,
                 ntfy_topic: str | None = None, ntfy_enabled: bool = False,
                 email_cfg: dict | None = None):
        self.enabled = enabled
        self.cooldown_seconds = cooldown_seconds
        self.ntfy_topic = ntfy_topic
        self.ntfy_enabled = ntfy_enabled and bool(ntfy_topic)
        self.email_cfg = email_cfg or {}
        self.email_enabled = bool(self.email_cfg.get("enabled"))
        self._last_sent: dict[str, float] = {}

    def _on_cooldown(self, key: str) -> bool:
        last = self._last_sent.get(key)
        return last is not None and (time.time() - last) < self.cooldown_seconds

    def notify(self, title: str, message: str, key: str, severity: str = "warning"):
        if not self.enabled:
            logger.info("[notify-disabled] %s: %s", title, message)
            return
        if self._on_cooldown(key):
            return

        self._last_sent[key] = time.time()
        logger.warning("[%s] %s - %s", severity.upper(), title, message)

        if _plyer_notification is None:
            print(f"\n[RAM-GUARD ALERT | {severity.upper()}] {title}\n{message}\n")
            return

        try:
            _plyer_notification.notify(
                title=f"RAM-Guard: {title}",
                message=message[:250],
                app_name="RAM-Guard",
                timeout=10,
            )
        except Exception as e:
            logger.error("Desktop notification failed (%s); printing instead.", e)
            print(f"\n[RAM-GUARD ALERT | {severity.upper()}] {title}\n{message}\n")

        self._send_mobile_push(title, message, severity)
        self._send_email(title, message, severity)

    def _send_email(self, title: str, message: str, severity: str):
        """Send an alert email that lands as a normal phone notification via
        the built-in mail app — no extra app or account signup needed on the
        receiving side."""
        if not self.email_enabled:
            return
        try:
            smtp_host = self.email_cfg["smtp_host"]
            smtp_port = self.email_cfg.get("smtp_port", 587)
            sender = self.email_cfg["sender_email"]
            password = self.email_cfg["sender_app_password"]
            recipient = self.email_cfg["recipient_email"]

            msg = MIMEText(message)
            msg["Subject"] = f"[RAM-Guard | {severity.upper()}] {title}"
            msg["From"] = sender
            msg["To"] = recipient

            with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as server:
                server.starttls()
                server.login(sender, password)
                server.sendmail(sender, [recipient], msg.as_string())
        except Exception as e:
            logger.error("Email alert failed: %s", e)

    def _send_mobile_push(self, title: str, message: str, severity: str):
        """Send an instant push notification to the phone via ntfy.sh.
        No account needed on either end — just a shared topic name."""
        if not self.ntfy_enabled:
            return

        priority_map = {"critical": "urgent", "warning": "high", "info": "default"}
        try:
            requests.post(
                f"https://ntfy.sh/{self.ntfy_topic}",
                data=message.encode("utf-8"),
                headers={
                    # HTTP headers are Latin-1 by default; findings can contain
                    # non-Latin-1 characters (em dashes, arrows), so the title
                    # must go over the wire as raw UTF-8 bytes, not a str.
                    "Title": f"RAM-Guard: {title}".encode("utf-8"),
                    "Priority": priority_map.get(severity, "default"),
                    "Tags": "warning" if severity != "critical" else "rotating_light",
                },
                timeout=5,
            )
        except Exception as e:
            logger.error("Mobile push (ntfy) failed: %s", e)
