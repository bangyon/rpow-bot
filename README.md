# rpow-bot

Auto-mining bot and dashboard for `rpow.hopeware.ltd`.

## What it does

- mines rPOW A (`alpha`), rPOW B (`beta`), or both
- shows a live dashboard
- sends webhook notifications on start, stop, challenge, mint, and error
- uses `RPOW_PRIVATE_KEY_HEX` from Zo Secrets when present

## Run locally

```bash
npm install
npm start
```

## Environment

- `RPOW_PRIVATE_KEY_HEX` — your 32-byte private key in hex
- `RPOW_DASHBOARD_TOKEN` — optional dashboard lock token
- `RPOW_TARGET` — `alpha`, `beta`, or `both`
- `RPOW_WEBHOOK_URL` — optional default webhook

## Notes

The `data/` folder is local runtime state and is ignored by Git.
