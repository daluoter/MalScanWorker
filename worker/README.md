# MalScan Worker

Malware analysis worker with 5-stage pipeline.

## Stages

1. **file-type** - File type detection using python-magic
2. **clamav** - ClamAV scanning using clamscan CLI
3. **yara** - YARA rule matching using yara CLI
4. **ioc-extract** - IOC extraction using regex patterns
5. **sandbox** - Sandbox analysis (mock in MVP)

## Development

```bash
poetry install
poetry run python -m malscan_worker.main
```
