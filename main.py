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
    from urllib.parse import quote_plus

    original_phone = request.phone_number.strip()
    digits = re.sub(r"\D", "", original_phone)

    if not 7 <= len(digits) <= 15:
        raise HTTPException(
            status_code=400,
            detail="Некорректный номер телефона"
        )

    # Приводим казахстанские номера к единому формату:
    # +7 777 621 18 33 и 8 777 621 18 33 -> 7776211833
    def normalize_phone(value):
        value = re.sub(r"\D", "", str(value))

        if len(value) == 11 and value[0] in ("7", "8"):
            value = value[1:]

        return value

    target = normalize_phone(digits)

    # Создаём варианты номера для поисковых запросов.
    variants = {digits, target}

    if len(target) == 10:
        variants.update({
            "7" + target,
            "8" + target,
            "+7" + target,
            "+7 " + target[:3] + " " + target[3:6]
            + " " + target[6:8] + " " + target[8:],
            "8 " + target[:3] + " " + target[3:6]
            + " " + target[6:8] + " " + target[8:],
            target[:3] + " " + target[3:6]
            + " " + target[6:8] + " " + target[8:],
        })

    # Убираем повторы и пустые значения.
    variants = list(dict.fromkeys(v for v in variants if v))

    queries = []
    for number in variants[:6]:
        queries.extend([
            f'"{number}" мошенники',
            f'"{number}" отзывы спам',
        ])

    all_results = []
    search_errors = []
    queries_sent = 0

    # Ищем номер в разных написаниях.
    for query in queries[:8]:
        queries_sent += 1

        try:
            response = tavily.search(
                query=query,
                max_results=5,
                search_depth="advanced"
            )

            results = response.get("results", [])
            for item in results:
                all_results.append({
                    "title": str(item.get("title", "")),
                    "url": str(item.get("url", "")),
                    "content": str(item.get("content", "")),
                    "query": query,
                })

        except Exception as exc:
            search_errors.append(str(exc)[:300])

    # Сравниваем номер с отдельными телефонными последовательностями,
    # а не с произвольной склейкой всех цифр страницы.
    def contains_exact_phone(text):
        candidates = re.findall(
            r"(?<!\d)\+?\d(?:[\d\s().-]{5,}\d)?(?!\d)",
            text
        )

        for candidate in candidates:
            candidate_digits = re.sub(r"\D", "", candidate)

            if normalize_phone(candidate_digits) == target:
                return True

        # Отдельно проверяем непрерывное написание номера.
        for candidate in re.findall(r"(?<!\d)\d{10,15}(?!\d)", text):
            if normalize_phone(candidate) == target:
                return True

        return False

    complaint_pattern = re.compile(
        r"мошенн|мошенник|спам|жалоб|"
        r"не берите трубк|нежелательн.{0,30}звон|"
        r"обман|развод|scam|scammer|fraud|spam|"
        r"reported.{0,30}number",
        re.IGNORECASE
    )

    matched_sources = []
    seen_urls = set()

    for item in all_results:
        combined = (
            item["title"] + " "
            + item["content"] + " "
            + item["url"]
        )

        if not contains_exact_phone(combined):
            continue

        url = item["url"]

        if url in seen_urls:
            continue

        seen_urls.add(url)

        # Исключаем страницы, которые сами по себе не являются
        # отзывами о конкретном номере.
        if "docs.ps.kz" in url.lower():
            continue

        has_complaint = bool(complaint_pattern.search(combined))

        matched_sources.append({
            "title": item["title"],
            "url": url,
            "content": item["content"][:1000],
            "has_complaint": has_complaint,
        })

    complaint_sources = [
        source for source in matched_sources
        if source["has_complaint"]
    ]

    complaint_count = len(complaint_sources)

    # Не объявляем номер опасным только из-за общих поисковых страниц.
    if complaint_count >= 3:
        risk_level = "HIGH"
        is_suspicious = True
        explanation = (
            "Найдены несколько результатов с точным совпадением номера "
            "и признаками жалоб. Рекомендуется проверить источники."
        )
    elif complaint_count >= 1:
        risk_level = "MEDIUM"
        is_suspicious = False
        explanation = (
            "Найдена как минимум одна страница с точным совпадением "
            "номера и признаками жалоб. Данных недостаточно "
            "для уверенного подтверждения мошенничества."
        )
    elif matched_sources:
        risk_level = "UNKNOWN"
        is_suspicious = False
        explanation = (
            "Номер найден в поиске, но убедительных признаков "
            "мошенничества не обнаружено."
        )
    else:
        risk_level = "UNKNOWN"
        is_suspicious = False
        explanation = (
            "Не найдено страниц с точным совпадением номера. "
            "Это не означает, что номер безопасен."
        )

    return {
        "status": "success",
        "phone_number": original_phone,
        "normalized_number": target,
        "risk_level": risk_level,
        "is_suspicious": is_suspicious,
        "explanation": explanation,
        "complaint_count": complaint_count,
        "search_diagnostics": {
            "queries_sent": queries_sent,
            "raw_results_count": len(all_results),
            "exact_match_count": len(matched_sources),
            "matched_sources_count": len(matched_sources),
            "search_errors": search_errors,
        },
        "sources": matched_sources[:30],
    }

