import logging
import socket
import ssl
from datetime import datetime
from telegram import Update
from telegram.ext import Application, CommandHandler, MessageHandler, ContextTypes, filters
import os

logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.INFO
)
logger = logging.getLogger(__name__)

BOT_TOKEN = os.environ.get("BOT_TOKEN")


def check_ssl(domain: str) -> dict:
    domain = domain.strip().replace("https://", "").replace("http://", "").split("/")[0]
    context = ssl.create_default_context()
    try:
        with socket.create_connection((domain, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()

        issuer = dict(x[0] for x in cert["issuer"])
        subject = dict(x[0] for x in cert["subject"])
        expires = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
        issued = datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z")
        days_left = (expires - datetime.utcnow()).days

        return {
            "valid": True,
            "domain": domain,
            "issuer": issuer.get("organizationName", issuer.get("commonName", "Unknown")),
            "subject": subject.get("commonName", domain),
            "issued": issued.strftime("%Y-%m-%d"),
            "expires": expires.strftime("%Y-%m-%d"),
            "days_left": days_left,
        }
    except ssl.SSLCertVerificationError as e:
        return {"valid": False, "domain": domain, "error": f"Certificate verification failed: {e.verify_message}"}
    except socket.gaierror:
        return {"valid": False, "domain": domain, "error": "Domain not found. Check the spelling."}
    except socket.timeout:
        return {"valid": False, "domain": domain, "error": "Connection timed out."}
    except ConnectionRefusedError:
        return {"valid": False, "domain": domain, "error": "Connection refused on port 443."}
    except Exception as e:
        return {"valid": False, "domain": domain, "error": str(e)}


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "🔒 *QuickSSLCheck Bot*\n\n"
        "Send me a domain (e.g. `example.com`) and I'll check its SSL certificate status, "
        "issuer, and expiry date.\n\n"
        "Just type or paste a domain to get started.",
        parse_mode="Markdown"
    )


async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "Usage:\nJust send a domain name, e.g:\n`google.com`\n`example.com`",
        parse_mode="Markdown"
    )


async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    domain = update.message.text.strip()

    if not domain or " " in domain:
        await update.message.reply_text("⚠️ Please send a single valid domain, e.g. `example.com`", parse_mode="Markdown")
        return

    checking_msg = await update.message.reply_text(f"🔍 Checking SSL for `{domain}`...", parse_mode="Markdown")

    result = check_ssl(domain)

    if result["valid"]:
        status_emoji = "✅" if result["days_left"] > 14 else "⚠️"
        reply = (
            f"{status_emoji} *SSL Certificate Valid*\n\n"
            f"*Domain:* `{result['domain']}`\n"
            f"*Issued to:* {result['subject']}\n"
            f"*Issuer:* {result['issuer']}\n"
            f"*Issued on:* {result['issued']}\n"
            f"*Expires on:* {result['expires']}\n"
            f"*Days remaining:* {result['days_left']}"
        )
        if result["days_left"] <= 14:
            reply += "\n\n⚠️ _Certificate expiring soon!_"
    else:
        reply = f"❌ *SSL Check Failed*\n\n*Domain:* `{result['domain']}`\n*Error:* {result['error']}"

    await checking_msg.edit_text(reply, parse_mode="Markdown")


def main():
    if not BOT_TOKEN:
        raise ValueError("BOT_TOKEN environment variable is not set")

    app = Application.builder().token(BOT_TOKEN).build()

    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("help", help_command))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))

    logger.info("QuickSSLCheckBot starting...")
    app.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()
