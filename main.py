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

    original = request.phone_number.strip()
    digits = re.sub(r"\D", "", original)

    if not 7 <= len(digits) <= 15:
        raise HTTPException(
            status_code=400,
            detail="Некорректный номер телефона"
        )

    def normalize(value):
        value = re.sub(r"\D", "", str(value))
        if len(value) == 11 and value[0] in ("7", "8"):
            value = value[1:]
        return value

    target = normalize(digits)
    variants = {digits, target}

    if len(target) == 10:
        local = target
        formatted = (
            f"{local[:3]} {local[3:6]} "
            f"{local[6:8]} {local[8:]}"
        )
        variants.update({
            "7" + local,
            "8" + local,
            "+7" + local,
            "+7 " + formatted,
            "8 " + formatted,
            formatted,
            f"{local[:3]}-{local[3:6]}-{local[6:8]}-{local[8:]}",
        })

    queries = []
    for number in list(variants)[:4]:
        queries.append(f'"{number}"')
        queries.append(f'"{number}" мошенники отзывы')

    results_by_url = {}
    errors = []

    for query in queries[:8]:
        try:
            response = tavily.search(
                query=query,
                max_results=5,
                search_depth="advanced"
            )
            for item in response.get("results", []):
                url = str(item.get("url", ""))
                if not url:
                    continue

                if url not in results_by_url:
                    results_by_url[url] = {
                        "title": str(item.get("title", "")),
                        "url": url,
                        "content": str(item.get("content", "")),
                    }
        except Exception as exc:
            errors.append(str(exc)[:200])

    complaint_pattern = re.compile(
        r"мошенн|мошенник|спам|жалоб|"
        r"не берите трубк|обман|развод|"
        r"scam|scammer|fraud|spam",
        re.IGNORECASE
    )

    matched = []

    for item in results_by_url.values():
        text = (
            item["title"] + " " +
            item["content"] + " " +
            item["url"]
        )

        # Ищем совпадение с отдельным номером,
        # а не с произвольной последовательностью цифр страницы.
        number_candidates = re.findall(
            r"(?<!\d)\+?\d(?:[\d\s().-]{5,}\d)?(?!\d)",
            text
        )

        exact_match = any(
            normalize(candidate) == target
            for candidate in number_candidates
        )

        if not exact_match:
            continue

        # Страницы справочников и общие статьи
        # не считаются жалобами сами по себе.
        has_complaint = bool(complaint_pattern.search(text))

        matched.append({
            "title": item["title"],
            "url": item["url"],
            "content": item["content"][:1000],
            "has_complaint": has_complaint,
        })

    complaint_sources = [
        item for item in matched
        if item["has_complaint"]
    ]

    complaint_count = len(complaint_sources)

    # Несколько результатов одного сайта не считаем
    # независимыми подтверждениями.
    independent_domains = set()

    for item in complaint_sources:
        domain_match = re.search(
            r"https?://([^/]+)",
            item["url"],
            re.IGNORECASE
        )
        if domain_match:
            domain = domain_match.group(1).lower()
            if not domain.endswith("ps.kz"):
                independent_domains.add(domain)

    if len(independent_domains) >= 3:
        risk_level = "HIGH"
        is_suspicious = True
        explanation = (
            "Найдены жалобы на этот номер на нескольких доменах. "
            "Результаты требуют проверки перед автоматической блокировкой."
        )
    elif complaint_count >= 1:
        risk_level = "MEDIUM"
        is_suspicious = False
        explanation = (
            "Найдены страницы с совпадающим номером и признаками жалоб. "
            "Данных недостаточно для уверенного подтверждения."
        )
    elif matched:
        risk_level = "UNKNOWN"
        is_suspicious = False
        explanation = (
            "Номер встречается в поиске, но достоверных жалоб "
            "не установлено."
        )
    else:
        risk_level = "UNKNOWN"
        is_suspicious = False
        explanation = (
            "Поиск не нашёл страниц с точным совпадением номера. "
            "Это не доказывает, что номер безопасен."
        )

    return {
        "status": "success",
        "phone_number": original,
        "normalized_number": target,
        "risk_level": risk_level,
        "is_suspicious": is_suspicious,
        "explanation": explanation,
        "complaint_count": complaint_count,
        "search_diagnostics": {
            "queries_sent": min(len(queries), 8),
            "raw_results_count": len(results_by_url),
            "exact_match_count": len(matched),
            "matched_sources_count": len(matched),
            "independent_domains": len(independent_domains),
            "search_errors": errors,
        },
        "sources": matched[:30],
    }

