# MalScan API

FastAPI backend for MalScan malware analysis service.

## Development

```bash
poetry install
poetry run uvicorn malscan.main:app --reload
```

## API Endpoints

- `POST /api/v1/files` - Upload file for analysis
- `GET /api/v1/jobs/{job_id}` - Get job status
- `GET /api/v1/reports/{job_id}` - Get analysis report
