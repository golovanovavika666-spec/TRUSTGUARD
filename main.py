import os
import json

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from dotenv import load_dotenv
from google import genai
from tavily import TavilyClient
from risk_engine import calculate_risk

load_dotenv()

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
TAVILY_API_KEY = os.getenv("TAVILY_API_KEY")

if not GEMINI_API_KEY:
    raise RuntimeError("GEMINI_API_KEY не задан в переменных окружения")

if not TAVILY_API_KEY:
    raise RuntimeError("TAVILY_API_KEY не задан в переменных окружения")
gemini = genai.Client(api_key=GEMINI_API_KEY)
tavily = TavilyClient(api_key=TAVILY_API_KEY)


app = FastAPI(
    title="TRUSTGUARD CORE",
    description="AI-система анализа интернет-мошенничества",
    version="0.5.0"
)


class AnalyzeRequest(BaseModel):
    text: str


@app.get("/")
def root():
    return {
        "project": "TRUSTGUARD",
        "status": "running"
    }


@app.get("/health")
def health():
    return {
        "status": "ok"
    }


@app.post("/analyze")
def analyze(request: AnalyzeRequest):

    text = request.text.strip()

    if not text:
        raise HTTPException(
            status_code=400,
            detail="Текст для анализа не может быть пустым"
        )

    # -------------------------------------------------
    # 1. GEMINI — первичный анализ
    # -------------------------------------------------

    analysis_prompt = f"""
Ты — AI-аналитик системы TRUSTGUARD.

Проанализируй сообщение на признаки интернет-мошенничества
и социальной инженерии.

НЕ утверждай, что это мошенничество на 100%.
Оценивай только имеющиеся признаки.

Определи:

- risk_score от 0 до 100;
- risk_level: LOW, MEDIUM или HIGH;
- scam_type;
- intent — что человека пытаются заставить сделать;
- indicators — подозрительные признаки;
- search_queries — 2-4 поисковых запроса, которые помогут
  проверить ситуацию в интернете;
- explanation — простое объяснение.

Возможные scam_type:

- мошенническая вакансия
- дропперская схема
- инвестиционное мошенничество
- фальшивый сотрудник банка
- фальшивый сотрудник организации/госслужбы
- фишинг
- подозрительная ссылка
- романтическое мошенничество
- мошенничество с доставкой/покупками
- неизвестно

Верни ТОЛЬКО JSON:

{{
  "risk_score": 0,
  "risk_level": "LOW",
  "scam_type": "неизвестно",
  "intent": "",
  "indicators": [],
  "search_queries": [],
  "explanation": ""
}}

Сообщение:

{text}
"""

    try:
        print(">>> GEMINI START", flush=True)

        ai_response = gemini.interactions.create(
            model="gemini-3.5-flash-lite",
            input=analysis_prompt,
        )

        print(">>> GEMINI DONE", flush=True)

        raw_ai = ai_response.output_text.strip()

        if not raw_ai:
            raise Exception("Gemini вернул пустой ответ")

        if raw_ai.startswith("```"):
            raw_ai = raw_ai.replace("```json", "")
            raw_ai = raw_ai.replace("```", "")
            raw_ai = raw_ai.strip()

        analysis = json.loads(raw_ai)

    except json.JSONDecodeError:
        raise HTTPException(
            status_code=500,
            detail="AI вернул неправильный JSON"
        )

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"GEMINI ERROR: {repr(e)}"
        )
    # -------------------------------------------------
    # 2. RISK ENGINE
    # -------------------------------------------------

    # -------------------------------------------------
    # 2. TAVILY — поиск в интернете
    # -------------------------------------------------

    sources = []

    search_queries = analysis.get("search_queries", [])

    for query in search_queries[:4]:

        try:
            search_result = tavily.search(
                query=query,
                max_results=5
            )

            for result in search_result.get("results", []):

                sources.append({
                    "title": result.get("title"),
                    "url": result.get("url"),
                    "content": result.get("content", "")
                })

        except Exception:
            continue

    # Убираем дубликаты URL

    unique_sources = {}

    for source in sources:

        url = source.get("url")

        if url and url not in unique_sources:
            unique_sources[url] = source

    sources = list(unique_sources.values())

    # -------------------------------------------------
    # 3. RISK ENGINE — независимая оценка риска
    # -------------------------------------------------

    risk_result = calculate_risk(
        text=text,
        scam_type=analysis.get("scam_type", "")
    )

    # Risk Engine является основой итоговой оценки.
    # AI-анализ сохраняем отдельно.

    analysis["ai_risk_score"] = analysis.get("risk_score")
    analysis["ai_risk_level"] = analysis.get("risk_level")

    analysis["risk_score"] = risk_result["risk_score"]
    analysis["risk_level"] = risk_result["risk_level"]

    # Объединяем признаки AI и Risk Engine

    ai_indicators = analysis.get("indicators", [])

    all_indicators = []

    for indicator in ai_indicators + risk_result["indicators"]:
        if indicator not in all_indicators:
            all_indicators.append(indicator)

    analysis["indicators"] = all_indicators

    # -------------------------------------------------
    # 4. Возвращаем итоговый результат
    # -------------------------------------------------

    return {
        "status": "success",

        "analysis": analysis,

        "risk_engine": {
            "risk_score": risk_result["risk_score"],
            "risk_level": risk_result["risk_level"],
            "indicators": risk_result["indicators"]
        },

        "sources": sources
    }

class PhoneCheckRequest(BaseModel):
    phone_number: str



@app.post("/check-phone")
def check_phone(request: PhoneCheckRequest):
    import re

    phone = request.phone_number.strip()
    digits = re.sub(r"\D", "", phone)

    if not 7 <= len(digits) <= 15:
        raise HTTPException(
            status_code=400,
            detail="Некорректный номер телефона"
        )

    try:
        result = tavily.search(
            query=f'"{digits}" мошенничество OR спам OR мошенник',
            max_results=10,
            search_depth="advanced"
        )

        sources = []
        confirmed_mentions = 0

        complaint_words = (
            "мошенник",
            "мошенники",
            "мошенничество",
            "спам",
            "обман",
            "развод",
            "вымогательство",
            "fraud",
            "scam"
        )

        for item in result.get("results", []):
            title = item.get("title", "")
            content = item.get("content", "")
            url = item.get("url", "")

            text = f"{title} {content}".lower()
            normalized_text = re.sub(r"\D", "", text)

            if digits not in normalized_text:
                continue

            has_complaint = any(
                word in text for word in complaint_words
            )

            sources.append({
                "title": title,
                "url": url,
                "has_complaint": has_complaint
            })

            if has_complaint:
                confirmed_mentions += 1

        if confirmed_mentions >= 3:
            risk_level = "HIGH"
            explanation = (
                "Найдено несколько упоминаний номера "
                "рядом с признаками мошенничества. "
                "Рекомендуется соблюдать осторожность."
            )
        elif confirmed_mentions >= 1:
            risk_level = "MEDIUM"
            explanation = (
                "Найдены подозрительные упоминания номера. "
                "Мошенничество пока не подтверждено."
            )
        else:
            risk_level = "UNKNOWN"
            explanation = (
                "Данных недостаточно для оценки номера. "
                "Это не означает, что номер безопасен."
            )

        return {
            "status": "success",
            "phone_number": phone,
            "risk_level": risk_level,
            "is_suspicious": confirmed_mentions > 0,
            "explanation": explanation,
            "complaint_count": confirmed_mentions,
            "sources": sources
        }

    except Exception as e:
        print(f"PHONE CHECK ERROR: {e}", flush=True)

        return {
            "status": "error",
            "phone_number": phone,
            "risk_level": "UNKNOWN",
            "is_suspicious": False,
            "explanation": "Не удалось проверить номер",
            "complaint_count": 0,
            "sources": []
        }
