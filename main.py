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
    from urllib.parse import urlparse

    phone = request.phone_number.strip()
    digits = re.sub(r"\D", "", phone)

    if not 7 <= len(digits) <= 15:
        raise HTTPException(
            status_code=400,
            detail="Некорректный номер телефона"
        )

    # Поддержка казахстанских номеров в форматах 7 и 8.
    variants = {digits}

    if len(digits) == 11 and digits.startswith("8"):
        variants.add("7" + digits[1:])

    if len(digits) == 11 and digits.startswith("7"):
        variants.add("8" + digits[1:])

    # Ищем номер вместе с разными словами и фразами.
    queries = []
    for number in sorted(variants):
        queries.extend([
            f'"{number}"',
            f'"{number}" кто звонил',
            f'"{number}" отзывы',
            f'"{number}" мошенники',
            f'"{number}" спам',
            f'"{number}" жалобы',
        ])

    # Признаки возможной жалобы. Само по себе слово
    # не доказывает мошенничество: дополнительно проверяем номер.
    complaint_pattern = re.compile(
        r"мошенн|спам|жалоб|не берите трубк|"
        r"нежелательн.{0,20}звон|обман|развод|"
        r"scam|scammer|fraud|spam|reported.{0,20}number",
        re.IGNORECASE
    )

    sources_by_url = {}
    search_errors = []
    raw_results_count = 0
    exact_match_count = 0

    excluded_domains = {
        "docs.ps.kz",
        "autocall.kz",
    }

    for query in queries:
        try:
            result = tavily.search(
                query=query,
                max_results=5,
                search_depth="advanced"
            )
        except Exception as error:
            print(
                f"PHONE SEARCH ERROR: {error}",
                flush=True
            )
            search_errors.append(str(error))
            continue

        results = result.get("results", [])
        raw_results_count += len(results)

        for item in results:
            title = item.get("title") or ""
            content = item.get("content") or ""
            url = item.get("url") or ""

            combined = f"{title} {content} {url}"
            normalized = re.sub(r"\D", "", combined)

            exact_match = any(
                number in normalized
                for number in variants
            )

            if exact_match:
                exact_match_count += 1

            # Сохраняем результаты, чтобы увидеть, что реально
            # возвращает Tavily, даже если номер не попал в сниппет.
            domain = urlparse(url).netloc.lower().split(":")[0]
            domain = domain.removeprefix("www.")

            if domain in excluded_domains:
                continue

            text_to_check = f"{title} {content}"
            has_complaint = bool(
                exact_match
                and complaint_pattern.search(text_to_check)
            )

            key = url or f"{title}:{content[:150]}"

            if key not in sources_by_url:
                sources_by_url[key] = {
                    "title": title,
                    "url": url,
                    "content": content[:500],
                    "exact_number_found": exact_match,
                    "possible_complaint": has_complaint,
                }
            else:
                source = sources_by_url[key]
                source["exact_number_found"] = (
                    source["exact_number_found"] or exact_match
                )
                source["possible_complaint"] = (
                    source["possible_complaint"] or has_complaint
                )

    sources = list(sources_by_url.values())

    # Для оценки риска учитываем только страницы, где номер
    # действительно найден в заголовке, тексте или ссылке.
    matched_sources = [
        source for source in sources
        if source["exact_number_found"]
    ]

    complaint_sources = [
        source for source in matched_sources
        if source["possible_complaint"]
    ]

    complaint_count = len(complaint_sources)

    if complaint_count >= 3:
        risk_level = "HIGH"
        explanation = (
            "Найдены несколько страниц с номером и признаками "
            "возможных жалоб. Это требует дополнительной проверки."
        )
    elif complaint_count >= 1:
        risk_level = "MEDIUM"
        explanation = (
            "Найдена страница с номером и возможными признаками "
            "жалобы. Это не является доказательством мошенничества."
        )
    elif matched_sources:
        risk_level = "UNKNOWN"
        explanation = (
            "Номер найден в результатах поиска, но достаточных "
            "признаков жалоб не обнаружено."
        )
    elif search_errors:
        risk_level = "UNKNOWN"
        explanation = (
            "Часть запросов не выполнилась. Результат проверки "
            "неполный, поэтому безопасность номера не подтверждена."
        )
    else:
        risk_level = "UNKNOWN"
        explanation = (
            "В результатах поиска не найдено точного совпадения "
            "номера. Это не означает, что номер безопасен."
        )

    # Временно возвращаем диагностику, чтобы понять,
    # что именно выдаёт Tavily.
    return {
        "status": "success",
        "phone_number": phone,
        "normalized_number": digits,
        "risk_level": risk_level,
        "is_suspicious": complaint_count > 0,
        "explanation": explanation,
        "complaint_count": complaint_count,
        "search_diagnostics": {
            "queries_sent": len(queries),
            "raw_results_count": raw_results_count,
            "exact_match_count": exact_match_count,
            "matched_sources_count": len(matched_sources),
            "search_errors": search_errors,
        },
        "sources": sources[:30],
    }
