"""Маршрут для читання звітів лабораторних вимірювань криптографії."""

import json
from pathlib import Path
from fastapi import APIRouter, HTTPException, status

router = APIRouter(prefix="/api/v1/crypto-lab", tags=["Crypto Lab"])

DEFAULT_REPORT_PATH = Path("benchmarks/crypto_report.json")


@router.get("/report", status_code=status.HTTP_200_OK)
def get_benchmark_report():
    """Отримати фіксований звіт бенчмарків."""
    if not DEFAULT_REPORT_PATH.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Benchmark report not found",
        )
    try:
        with open(DEFAULT_REPORT_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error reading benchmark report",
        )