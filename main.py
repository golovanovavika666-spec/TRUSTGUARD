import os
import json

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
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

    original = request.phone_number.strip()
    digits = re.sub(r"\D", "", original)

    if not 7 <= len(digits) <= 15:
        raise HTTPException(
            status_code=400,
            detail="Некорректный номер телефона"
        )

    def normalize(value):
        value = re.sub(r"\D", "", str(value))

        # Нормализация номеров Казахстана и России:
        # 8XXXXXXXXXX -> 7XXXXXXXXXX -> XXXXXXXXXX
        if len(value) == 11 and value[0] == "8":
            value = "7" + value[1:]

        if len(value) == 11 and value[0] == "7":
            value = value[1:]

        return value

    target = normalize(digits)

    # Формируем варианты написания номера для поиска.
    search_variants = []
    queries = []

    def add_search_variant(value):
        if value and value not in search_variants:
            search_variants.append(value)

    add_search_variant(target)
    add_search_variant(digits)

    if len(target) == 10:
        formatted = (
            f"{target[:3]} {target[3:6]} "
            f"{target[6:8]} {target[8:]}"
        )

        add_search_variant("+7" + target)
        add_search_variant("8" + target)
        add_search_variant("+7 " + formatted)
        add_search_variant("8 " + formatted)
        add_search_variant(formatted)

    for number in search_variants:
        queries.append(f'"{number}"')
        queries.append(f'"{number}" отзывы жалобы мошенники')

    # Ограничиваем количество запросов к поиску.
    queries = queries[:8]

    # Собираем результаты, исключая дубликаты URL.
    results_by_url = {}
    errors = []

    for query in queries:
        try:
            response = tavily.search(
                query=query,
                max_results=5,
                search_depth="advanced"
            )

            for result in response.get("results", []):
                url = str(result.get("url", "")).strip()

                if not url:
                    continue

                if url not in results_by_url:
                    results_by_url[url] = {
                        "title": str(result.get("title", "")),
                        "url": url,
                        "content": str(result.get("content", "")),
                    }

        except Exception as exc:
            errors.append(str(exc)[:200])

    # Ищем формулировки, похожие на конкретную жалобу.
    # Одного слова "мошенники" недостаточно.
    complaint_pattern = re.compile(
        r"меня обманул|меня обманули|обманули меня|"
        r"украли деньги|списали деньги без моего согласия|"
        r"мошенники звонили|звонили мошенники|"
        r"представились сотрудниками банка|"
        r"представился сотрудником банка|"
        r"представились сотрудниками полиции|"
        r"вымогали деньги|пытались обмануть|"
        r"не возвращают деньги|жалуюсь на номер|"
        r"жалоба на номер|отзыв о номере|"
        r"не берите трубку|звонили и требовали|"
        r"алаяқ|алаяқтар|алдап кетті|"
        r"ақшамды алды|ақшамды ұрлады|"
        r"scam caller|phone scam|fraudulent call|"
        r"reported as spam",
        re.IGNORECASE
    )

    # Признаки официальной справочной страницы.
    # Само упоминание полиции не отменяет наличие жалобы.
    official_contact_pattern = re.compile(
        r"киберпол|cyberpol|"
        r"официальный телефон|официальный номер|"
        r"горячая линия|телефон доверия|"
        r"справочная служба|"
        r"консультаци[яи]\s+по вопросам",
        re.IGNORECASE
    )

    strong_complaint_pattern = re.compile(
        r"меня обманул|меня обманули|"
        r"украли деньги|вымогали деньги|"
        r"пытались обмануть|"
        r"алаяқтар|алдап кетті|"
        r"phone scam|fraudulent call",
        re.IGNORECASE
    )

    matched = []

    for item in results_by_url.values():
        text = (
            item["title"] + " " +
            item["content"] + " " +
            item["url"]
        )

        # Извлекаем телефонные последовательности
        # и сравниваем их после нормализации.
        number_candidates = re.findall(
            r"(?<!\d)\+?\d(?:[\d\s().-]{5,}\d)(?!\d)",
            text
        )

        exact_match = any(
            normalize(candidate) == target
            for candidate in number_candidates
        )

        if not exact_match:
            continue

        has_complaint_phrase = bool(
            complaint_pattern.search(text)
        )

        official_context = bool(
            official_contact_pattern.search(text)
        )

        strong_complaint = bool(
            strong_complaint_pattern.search(text)
        )

        # Не считаем обычную официальную контактную страницу
        # жалобой, если нет конкретных признаков негативного опыта.
        has_complaint = (
            has_complaint_phrase
            and (
                not official_context
                or strong_complaint
            )
        )

        domain = (
            urlparse(item["url"]).hostname or ""
        ).lower()

        if domain.startswith("www."):
            domain = domain[4:]

        matched.append({
            "title": item["title"],
            "url": item["url"],
            "content": item["content"][:1000],
            "has_complaint": has_complaint,
            "domain": domain,
        })

    # Оставляем только источники с признаками жалоб.
    complaint_sources = [
        item for item in matched
        if item["has_complaint"]
    ]

    # Считаем разные домены, а не количество страниц.
    # ps.kz исключён из подсчёта.
    independent_domains = {
        item["domain"]
        for item in complaint_sources
        if item["domain"]
        and item["domain"] != "ps.kz"
        and not item["domain"].endswith(".ps.kz")
    }

    complaint_count = len(complaint_sources)

    if len(independent_domains) >= 3:
        risk_level = "HIGH"
        is_suspicious = True
        explanation = (
            "Найдены совпадающий номер и признаки жалоб "
            "на трёх или более разных доменах. Это поисковые "
            "сигналы, а не окончательное доказательство мошенничества."
        )

    elif complaint_count >= 1:
        risk_level = "MEDIUM"
        is_suspicious = False
        explanation = (
            "Найдена страница с совпадающим номером и возможными "
            "признаками жалобы. Требуется дополнительная проверка."
        )

    elif matched:
        risk_level = "UNKNOWN"
        is_suspicious = False
        explanation = (
            "Номер найден в поиске, но убедительных признаков "
            "жалоб в найденных фрагментах нет."
        )

    else:
        risk_level = "UNKNOWN"
        is_suspicious = False
        explanation = (
            "Поиск не обнаружил страниц с точным совпадением номера. "
            "Это не гарантирует, что номер безопасен."
        )

    # Убираем внутреннее поле domain из публичного ответа.
    public_sources = [
        {
            "title": item["title"],
            "url": item["url"],
            "content": item["content"],
            "has_complaint": item["has_complaint"],
        }
        for item in matched
    ]

    return {
        "status": "success",
        "phone_number": original,
        "normalized_number": target,
        "risk_level": risk_level,
        "is_suspicious": is_suspicious,
        "explanation": explanation,
        "complaint_count": complaint_count,
        "search_diagnostics": {
            "queries_sent": len(queries),
            "raw_results_count": len(results_by_url),
            "exact_match_count": len(matched),
            "matched_sources_count": len(matched),
            "independent_domains": len(independent_domains),
            "search_errors": errors,
        },
        "sources": public_sources[:30],
    }


class ChatMessage(BaseModel):
    role: str
    content: str


class ChatRequest(BaseModel):
    message: str
    history: list[ChatMessage] = Field(default_factory=list)



@app.post("/chat")
def chat(request: ChatRequest):
    message = request.message.strip()

    if not message:
        raise HTTPException(
            status_code=400,
            detail="Напиши сообщение для ИИ"
        )

    contents = []

    for item in request.history[-20:]:
        if item.role not in {"user", "assistant"}:
            continue

        content = item.content.strip()

        if content:
            role = "model" if item.role == "assistant" else "user"

            contents.append({
                "role": role,
                "parts": [{"text": content[:5000]}]
            })

    contents.append({
        "role": "user",
        "parts": [{"text": message[:10000]}]
    })

    try:
        response = gemini.models.generate_content(
            model="gemini-2.5-flash",
            contents=contents,
            config={
                "system_instruction": (
                    "Ты — дружелюбный ИИ-помощник приложения TRUSTGUARD. "
                    "Общайся на русском языке, отвечай понятно и по существу. "
                    "Помогай с обычными вопросами и программированием. "
                    "При подозрительных просьбах перевести деньги помогай "
                    "безопасно проверить ситуацию."
                ),
                "temperature": 0.7,
            },
        )

        answer = (response.text or "").strip()

        if not answer:
            raise HTTPException(
                status_code=502,
                detail="ИИ не вернул ответ"
            )

        return {
            "status": "success",
            "reply": answer
        }

    except HTTPException:
        raise

    except Exception as e:
        print(f">>> CHAT ERROR: {repr(e)}", flush=True)

        raise HTTPException(
            status_code=502,
            detail="Не удалось получить ответ от ИИ. Проверь настройки сервера."
        )
