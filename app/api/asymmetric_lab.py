"""Додайте новий маршрут та підключення до наявного app/main.py."""
import json
from pathlib import Path
from typing import Literal, Optional
from fastapi import APIRouter, HTTPException, Query
from pydantic import ValidationError

# Переконайтеся, що ви імпортуєте BenchmarkResponse, який створили раніше
from app.schemas.asymmetric_report import BenchmarkReport, BenchmarkResponse, validate_complete_report

router = APIRouter(prefix="/api/v1/lab/crypto", tags=["asymmetric-lab"])
REPORT_PATH = Path(__file__).resolve().parents[2] / "results/practice-03/report.json"
MAX_REPORT_BYTES = 1048576  # Local teaching limit, not a universal JSON limit.


def _reject_constant(value: str):
    raise ValueError("non-finite JSON number")


def _unique_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON member")
        result[key] = value
    return result


def load_report() -> BenchmarkReport:
    try:
        with REPORT_PATH.open("rb") as stream:
            raw = stream.read(MAX_REPORT_BYTES + 1)
        if len(raw) > MAX_REPORT_BYTES:
            raise ValueError("report too large")
        data = json.loads(raw, object_pairs_hook=_unique_object,
                          parse_constant=_reject_constant)
        return validate_complete_report(data)
    except FileNotFoundError as exc:
        raise HTTPException(404, "benchmark report not found") from exc
    except (OSError, ValueError, ValidationError) as exc:
        raise HTTPException(500, "benchmark report invalid") from exc


@router.get("/asymmetric-benchmark-results", response_model=BenchmarkResponse)
def get_asymmetric_benchmark_results(
    operation: Optional[Literal["encrypt", "decrypt"]] = Query(
        None, description="Фільтр результатів за криптографічною операцією"
    )
):
    report = load_report()
    
    # Конвертуємо у словник для формування відповіді
    response_data = report.model_dump()
    
    # Застосовуємо фільтрацію за варіантом (залишаємо key_generation та checks недоторканими)
    if operation:
        filtered_results = [r for r in response_data["results"] if r["operation"] == operation]
        response_data["results"] = filtered_results

    return response_data