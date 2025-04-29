https://github.com/zhanymkanov/fastapi-best-practices

```bash
backend
├── src
│   ├── suricata
│   │   ├── parser.py           # czytanie eve.json
│   │   ├── service.py          # ekstrakcja CVE, zapis Eventów do DB
│   │   ├── models.py           # SQLAlchemy: SuricataEvent, SuricataCVE
│   │   ├── schemas.py          # Pydantic: SuricataEventIn, SuricataEventOut
│   │   ├── constants.py
│   │   └── exceptions.py
│   ├── epss
│   │   ├── client.py           # HTTP client do API FIRST / CSV offline
│   │   ├── service.py          # pobranie score, zapis/aktualizacja w DB
│   │   ├── models.py           # SQLAlchemy: CVEScore (cve, epss, percentile, date)
│   │   ├── schemas.py          # Pydantic: CVEScoreOut
│   │   ├── config.py
│   │   └── exceptions.py
│   ├── alerts
│   │   ├── router.py           # GET /alerts, WebSocket itp.
│   │   ├── service.py          # łączenie Event + CVEScore → Alert, zapis do DB
│   │   ├── models.py           # SQLAlchemy: Alert (event_id, cve, epss, status…)
│   │   ├── schemas.py          # Pydantic: AlertOut
│   │   ├── dependencies.py     # wspólne zależności (DB session, cache)
│   │   ├── constants.py
│   │   └── exceptions.py
│   ├── database.py             # init SQLAlchemy engine, SessionLocal, Base
│   ├── config.py               # globalne ENV, URL DB, klucze API…
│   ├── exceptions.py           # globalne wyjątki i handler
│   ├── pagination.py           # paginacja zapytań / odpowiedzi
│   └── main.py                 # tworzy FastAPI app, rejestruje routery, eventy startup/shutdown
├── tests
│   ├── suricata
│   ├── epss
│   └── alerts
├── .env
├── .gitignore
├── pyproject.toml
```