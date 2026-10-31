"""ML service (10): input-risk model + readable activity. Routes match 04-api-contract §C."""
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse

from app import narrate as narr
from app.input_model import get_model
from app.schemas import ClassifyInputRequest, ClassifyInputResponse, NarrateRequest, NarrateResponse

log = logging.getLogger("ml")


@asynccontextmanager
async def lifespan(_: FastAPI):
    m = get_model()          # load once at start, warm the vectorisers
    if m:
        m.classify("warm-up; id")
    yield


app = FastAPI(title="Deception SOC ML service", version="1.0.0", lifespan=lifespan)


def _error(status: int, code: str, message: str) -> JSONResponse:
    return JSONResponse(status_code=status, content={"error": {"code": code, "message": message}})


@app.get("/health")
def health():
    m = get_model()
    cfg = narr.Config.from_env()
    return {"ok": True, "models": {"input": m.version if m else None},
            "narration": "llm" if cfg.enabled else "off", "llm_model": cfg.model if cfg.enabled else None}


@app.post("/ml/v1/classify-input", response_model=ClassifyInputResponse)
def classify_input(req: ClassifyInputRequest):
    m = get_model()
    if m is None:
        return _error(503, "model_missing", "input model not trained; run python -m training.train_input")
    return m.classify(req.value)


@app.post("/ml/v1/narrate", response_model=NarrateResponse)
async def narrate(req: NarrateRequest):
    try:
        out = await run_in_threadpool(narr.narrate, req)
    except narr.LLMOff:
        return _error(503, "llm_off", "LLM_API_KEY / LLM_MODEL not set; use template")
    except narr.LLMError as e:
        log.warning("narrate failed kind=%s ref=%s: %s", req.kind, req.ref_id, e)
        return _error(502, "llm_error", str(e))
    if out.get("guard"):
        log.info("narrate guard kind=%s ref=%s checks=%s", req.kind, req.ref_id, out["guard"])
    return out
