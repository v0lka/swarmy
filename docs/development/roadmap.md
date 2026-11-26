# swarmy — роадмап разработки

- **Версия:** 0.1
- **Дата:** 2026-11-25
- **Основание:** [spec.md](spec.md) v0.3-draft (принципы P1–P5, решения D1–D22, фазы F0–F6 §12.3) и [architecture.md](architecture.md) v0.1-draft (компоненты §2.3, решения AD-1–AD-8, инварианты §16, анти-паттерны §17, трассировка §18)
- **Статус:** рабочий документ планирования. Иерархия: **майлстоун → фаза → атомарная задача** (What/Where/How/Acceptance Criteria)
- **Языки:** документация — русский; код, идентификаторы, CLI, UI — английский (D8)

---

## 1. Как читать документ

- **Иерархия:** `M1–M5` — майлстоуны (поставки, каждому — свой Definition of Done), `P1.1–P5.5` — фазы (рабочие области внутри майлстоуна), `T#.#.#` — атомарные задачи.
- **Соответствие spec:** каждая фаза помечена фазой spec §12.3 (`F0–F6`); критерии готовности фаз из spec переносятся в DoD фаз и майлстоунов и **не ослабляются**.
- **Схема задачи:** **What** — наблюдаемый результат; **Where** — канонические пути из architecture.md §3.1 (расхождение кода с ними — дефект, §1 arch); **How** — подход и ключевые шаги; **Acceptance criteria** — бинарные проверяемые критерии (чек-боксы).
- **Атомарность:** задача рассчитана на один обзоряемый PR и проверяется самостоятельно, без соседних задач фазы.
- **Выполнение:** задача закрыта, когда все её AC отмечены и CI зелёный; фаза закрыта, когда закрыты все её задачи и выполнен её DoD; майлстоун закрыт по своему DoD (§5.0–§9.0).
- **Порядок:** задачи внутри фазы перечислены в рекомендуемом порядке исполнения; зависимости между фазами — §10.
- **Оценки трудоёмкости и календарные даты сознательно не включены:** исходные документы не дают оснований для них; документ фиксирует состав, порядок и критерии готовности.
- **Сопровождение:** документ живёт вместе с реализацией. Расхождение кода со spec/architecture — дефект дизайна (не «обходной путь»); новые планировочные решения добавляются в журнал RD (§4) по образцу журнала решений spec §13.

---

## 2. Майлстоуны: обзор

| Майлстоун | Фазы | F-spec | Цель | DoD (кратко) | Задач |
|---|---|---|---|---|---|
| **M1 Фундамент** | P1.1–P1.5 | F0, F1 | Репозиторий, инструменты качества, доменное ядро: память (схема+FTS5), события (шина+журнал), гардрейлы (конвейер+DSL), реестр инструментов + лоадер модулей | Установка и `swarmy --help` на всех платформах; ядро под юнит-тестами; unit-gate ≥ 85 % активен; модуль-пустышка загружается | 29 |
| **M2 Периметр исполнения** | P2.1–P2.4 | F2 | Сеть под контролем: скоуп, лимиты, HTTP-клиент, улики, санитизация LLM-контекста | Эхо-приложение: вне скоупа блокируется, улики пишутся, бюджеты/маскирование работают; integration-gate ≥ 70 % активен | 13 |
| **M3 Рой и HITL** | P3.1–P3.5 | F3 | Оркестратор: конфиг/сессия/движок, runtime + политики событий, HITL (профили, очередь), LLM-судья, async-параллелизм делегаций | Сценарий «находка → верификация» через события; параллельные `task()` с глобальными лимитами; очередь аппрувов работает | 19 |
| **M4 Консоль оператора** | P4.1–P4.4 | F4 | TUI: 6 панелей, чат, HITL-модалки, деревья атак | Полная сессия управляется из TUI без CLI-ввода | 11 |
| **M5 Референсный рой и релиз** | P5.1–P5.5 | F5, F6 | Встроенные модули `crawler` и `xss-detector`, минимальные деревья атак, демо-сессия, отчёт, релиз v0.1 | Демо-сессия F5; `report.md` генерируется из сессии F5; приёмка v0.1 (установка из git, D17) | 12 |

Майлстоуны зависят линейно (состав фаз и точные зависимости — §10):

```
M1 (фундамент: F0+F1)
 │
 ▼
M2 (периметр исполнения: F2)
 │
 ▼
M3 (рой и HITL: F3)
 │
 ▼
M4 (консоль оператора: F4)
 │
 ▼
M5 (референсный рой, отчёт, релиз: F5+F6)
```

Смысл границ: после M1 система имеет ядро без сети и агентов; после M2 — контролируемый доступ к цели с гарантиями скоупа/лимитов/улик; после M3 — работающий рой с HITL (headless, без TUI); после M4 — управляемая из TUI сессия; M5 доводит до демо-сценария и релиза v0.1.

---

## 3. Глобальные ограничения и сквозные практики

Действуют во всех фазах; нарушение трактуется как дефект так же, как расхождение со spec/architecture.

| # | Ограничение | Источник |
|---|---|---|
| G1 | Python `>=3.11,<4.0`; runtime-цель 3.15 (smoke в CI); платформы windows/amd64, macos/arm64, linux/amd64+arm64; никаких POSIX-only API в ядре | spec §11; arch §15.4 |
| G2 | L0 = deepagents `>=0.7.41,<0.8`, не форкается; только документированные точки расширения (arch §2.1); обновление — процедура D18 | D16, D18 |
| G3 | Pydantic v2 для всех границ; запрет `Any`/`dict[str, Any]` в доменном коде; нетипизированные зависимости — только через типизированные врапперы | D9; spec §11 |
| G4 | Runtime-зависимости: deepagents, pydantic, httpx, textual, rich, jinja2, aiosqlite, langgraph-checkpoint-sqlite; менеджмент — uv + lock-файл | spec §11; AD-2 |
| G5 | Пороги покрытия (D22): unit ≥ 85 %, integration ≥ 70 % — **отдельные** команды CI; активация: unit с T1.5.6, integration с T2.4.3; исключения точечные (`pragma: no cover`), blanket-omit целых пакетов запрещён | D22 |
| G6 | Инварианты arch §16 (10 шт.) и анти-паттерны arch §17 — проверяемые требования; архитектурные тесты на правила импортов (arch §2.5) поддерживаются непрерывно с момента появления пакетов | arch §16–§17 |
| G7 | Fail-fast старта сессии: все проблемы конфигурации, манифестов, гардрейлов и коллизий имён обнаруживаются до первого LLM-вызова | arch §16.10 |
| G8 | Секреты оператора: только `secrets.yaml` (chmod 600), маскирование в LLM-контексте/TUI/журнале; сырые значения — только в файлах улик | AD-5; D21; arch §12.3 |
| G9 | Каждый PR проходит CI-матрицу (G1) и не снижает покрытие ниже активных порогов (G5) | D22 |
| G10 | Docstring tool-функций — описание для LLM (непустой, типизированная сигнатура); комментарии-трассировки «← arch §N» приветствуются | arch §1, §8.5 |

**DoD-иерархия:** AC задач → DoD фазы (в заголовке фазы) → DoD майлстоуна (§5.0–§9.0). DoD майлстоунов наследуют критерии фаз spec §12.3 дословно по смыслу (с оговоркой RD-6 для F3/F4).

---

## 4. Решения роадмапа (RD)

Специфичные для этого документа решения: не меняют spec/architecture, но снимают неоднозначность планирования там, где arch §18.3 оставляет фазу не назначенной или порядок исполнения требует уточнения.

| # | Решение | Обоснование |
|---|---|---|
| RD-1 | Майлстоуны группируют фазы spec §12.3: M1 = F0+F1; M2 = F2; M3 = F3; M4 = F4; M5 = F5+F6+релиз. Крупные фазы spec разбиты на под-фазы (F0 → P1.1; F1 → P1.2–P1.5; F2 → P2.1–P2.4; F3 → P3.1–P3.5; F4 → P4.1–P4.4; F5 → P5.1–P5.3; F6 → P5.4) | Трёхуровневая структура «майлстоун → фаза → задача» при сохранении F0–F6 как скелета и их критериев как DoD |
| RD-2 | LLM-судья (arch §6.7) отнесён к P3.4 (майлстоун F3); в F1/F2 он не входит | arch §18.3 не назначает §6.7 фазе явно; эскалации судьи требуют ApprovalQueue и «временных врат» `JudgeEscalationRegistry` — зависимость от HITL |
| RD-3 | ToolRegistry (arch §6.1) отнесён к P1.5 (фаза лоадера) | arch §18.3 не назначает §6.1; коллизии имён и risk-классы нужны лоадеру для fail-fast сборки SubAgent-словарей (§8.3) |
| RD-4 | В M1 дайджесты аргументов в `GuardrailBlocked` — тривиальное усечение; с P2.3 (T2.3.2) заменяются на ContextProjector | §5.5 arch требует projector для всех дайджестов, но ContextProjector реализуется в F2; в F1 шина/журнал уже нужны |
| RD-5 | «Верификатор» демо-сценария — без нового встроенного модуля: повторная делегация `xss-detector` с безопасными пейлоадами + платформенный `update_finding_status` | §4.6 spec фиксирует ровно два встроенных модуля v0.1; arch §13.4 упоминает `task(верификатор)` без определения отдельного модуля |
| RD-6 | Критерий F3 «HITL-модалка перехватывает destructive» принимается двумя шагами: логика очереди — headless-приёмка в P3.3; UI-модалка — в P4.3 (финальная приёмка вместе с F4) | TUI реализуется в F4 (§12.3 spec); потенциальное противоречие критериев F3↔F4 снимается разделением приёмки |
| RD-7 | `generate_report` включается в tools движка в P5.4; до этого движок собирается без него | arch §9.1 перечисляет инструмент в сборке, но реализация отчёта — F6; заглушка не требуется |
| RD-8 | Миграции всех таблиц одного `memory.sqlite` (домен + `events` + FTS) — единый список в `memory/schema.py`; владение семантикой таблиц остаётся за подсистемами | arch §4.3 описывает единый мигратор; правила импортов arch §2.5 не нарушаются (DDL-константы — не кросс-импорт) |
| RD-9 | Приёмка P4.4 (панель Attack Trees) — на фикстурных данных дерева (тестовая фикстура записывает `AttackNode`/`AttackEdge` в память); живые демо-данные приходят в P5.3 без обратной зависимости P4.4 ← P5.3 | Взаимная зависимость P4.4 ↔ P5.3 (панель ← демо-данные; демо ← панель) образовывала бы цикл против линейного порядка майлстоунов (§2, §10.1); панель проверяется на фикстуре в M4, сквозная проверка «дерево доходит до TUI» остаётся в P5.3 (T5.3.1) |
| RD-10 | Хуки pre-tool-call middleware L0 подтверждены по пину (deepagents 0.7.41 → langchain 1.5.2): базовый класс — `langchain.agents.middleware.AgentMiddleware`, хуки `wrap_tool_call`/`awrap_tool_call`, запрос — `langgraph.prebuilt.tool_node.ToolCallRequest` (поля `tool_call{name,args,id}`, `tool`, `state`, `runtime`); блок — возврат `ToolMessage` без вызова handler. `GuardrailMiddleware` исполняется в асинхронном варианте `awrap_tool_call`, синхронный хук — fail-closed (RuntimeError) | Имя хука совпало с предположением arch §6.5/§19.1; swarmy работает только асинхронно (aiosqlite, Textual), поэтому Enforcement — в `awrap_tool_call`, а синхронный путь сознательно закрыт, чтобы не оставить инструмент без гардрейлов; `create_deep_agent(middleware=…)` и `SubAgent["middleware"]` принимают список middleware (сверено с исходниками пина, T1.4.5) |

---

## 5. Майлстоун 1 — «Фундамент» (F0 + F1)

**Состав:** P1.1 скелет и инфраструктура · P1.2 общая память · P1.3 события · P1.4 гардрейлы (конвейер+DSL) · P1.5 реестр инструментов и лоадер модулей.

### M1 · Definition of Done

Наследует критерии F0 и F1 (spec §12.3):

- [x] `pip install -e .` и `swarmy --help` работают на всех платформах CI-матрицы (F0)
- [x] smoke на Python 3.15 зелёный (runtime-цель, spec §11)
- [x] юнит-тесты ядра зелёные; **unit-gate покрытия ≥ 85 % активен в CI** (D22; T1.5.6)
- [x] **модуль-пустышка загружается** лоадером (F1; T1.5.5)
- [x] журнал событий append-only, доставка подписчикам — журнально-первая (T1.3.5)
- [x] конвейер гардрейлов детерминирован (И-композиция), DSL валидируется fail-fast (T1.4.6)

---

### P1.1 · Фаза «Скелет пакета и инфраструктура» (F0)

**Цель:** репозиторий собирается, устанавливается и проверяется на всех целевых платформах; инструменты качества настроены под D9/D22.
**Зависимости:** нет (стартовая фаза).
**DoD фазы:** критерий F0 spec — установка + `swarmy --help` на всех платформах.
**Задачи:** T1.1.1–T1.1.6.

#### T1.1.1 — Метаданные пакета и зависимости
- **What:** `pyproject.toml` как единый источник сборки: метаданные, runtime/dev-зависимости, entry point, конфигурации инструментов.
- **Where:** `pyproject.toml`, `uv.lock`.
- **How:** по arch §3.2: `[project] name = "swarmy"`, `license = "MIT"`, `requires-python = ">=3.11,<4.0"`; `[project.scripts] swarmy = "swarmy.cli:main"`; runtime-deps: `deepagents>=0.7.41,<0.8` (D18), `pydantic>=2,<3` (D9), `httpx`, `textual`, `rich`, `jinja2>=3.1`, `aiosqlite`, `langgraph-checkpoint-sqlite` (AD-2); dev-группа: `pytest`, `pytest-asyncio`, `pytest-cov`, `ruff`, `ty` (или `mypy` — выбор фиксируется этой задачей), `aiohttp` (для эхо-приложения фикстур). src-layout.
- **Acceptance criteria:**
  - [x] `uv lock` резолвит полный граф; `uv.lock` закоммичен
  - [x] `uv run python -m swarmy --version` отвечает без импорта L0-стека
  - [x] выбор типчекера (ty или mypy) зафиксирован в `pyproject.toml` и здесь (в T1.1.3)

#### T1.1.2 — Скелет пакетов и CLI-заглушка
- **What:** дерево `src/swarmy` по arch §3.1 с пакетами-заглушками, `__version__`, `__main__.py` и CLI на argparse (без сторонних CLI-фреймворков — P4).
- **Where:** `src/swarmy/**` (`core/`, `events/`, `memory/`, `tools/`, `guardrails/`, `modules/`, `report/`, `tui/`, `agents/`), `src/swarmy/cli.py`, `src/swarmy/__main__.py`, `agents/` (корень — пример пользовательского каталога).
- **How:** пакеты создаются с docstring-заглушками; `cli.py` поддерживает только `--version`/`--help` (полный синтаксис §3.4 arch добавляется в T4.1.3).
- **Acceptance criteria:**
  - [x] `swarmy --version` и `--help` работают на всех платформах матрицы
  - [x] состав пакетов соответствует arch §3.1 (сверка по списку)
  - [x] тест-гард: старт CLI не импортирует `deepagents`/LangChain

#### T1.1.3 — Конфигурация качества
- **What:** ruff strict, ty/mypy strict, pytest (asyncio), конфигурация покрытия под два порога D22.
- **Where:** `pyproject.toml` — секции `[tool.ruff]`, `[tool.ty]`/`[tool.mypy]`, `[tool.pytest.ini_options]`, `[tool.coverage.*]`.
- **How:** ruff — strict-набор в духе upstream deepagents: запрет `Any` (`ANN401`), обязательные аннотации, `I`/`UP`/`B`; типчекер strict: `disallow_any_explicit`, `disallow_untyped_defs`, `warn_return_any`; pytest: `asyncio_mode = "auto"`, маркеры `unit`/`integration`; coverage: два источника (`tests/unit` → 85, `tests/integration` → 70), `exclude_lines` — только точечные (активация команд CI: T1.5.6 и T2.4.3).
- **Acceptance criteria:**
  - [x] `ruff check src tests` и типчекер — чисто на скелете
  - [x] `uv run pytest -m unit` и `-m integration` запускаются (0 тестов — допустимо)
  - [x] конфигурация coverage содержит оба порога и политику исключений

#### T1.1.4 — Smoke на Python 3.15
- **What:** подтверждение runtime-цели spec §11: установка и запуск на Python 3.15.
- **Where:** CI-workflow (отдельная джоба), `uv.lock`, `pyproject.toml` (минимальные версии).
- **How:** джоба: `uv sync` под 3.15 → `swarmy --version`; классификаторы deepagents заявляют до 3.14 — smoke подтверждает фактическую совместимость (spec §11); минимальные версии остальных зависимостей фиксируются по результату (arch §19.3).
- **Acceptance criteria:**
  - [x] smoke-джоба Py3.15 зелёная в CI
  - [x] минимальные версии в `pyproject.toml` соответствуют результатам smoke
  - [x] если smoke красный — заведён вопрос в §12 роадмапа (процедура дефекта)

#### T1.1.5 — CI-матрица платформ
- **What:** GitHub Actions: 4 комбинации OS/arch + шаги качества; каркас для последующих coverage-gates.
- **Where:** `.github/workflows/ci.yml`.
- **How:** матрица `windows/amd64`, `macos/arm64`, `linux/amd64`, `linux/arm64`; шаги: `uv sync` → ruff → типчекер → `pytest -m unit` → `pytest -m integration` → smoke `swarmy --version`; кэш uv; команды coverage-gates добавляются задачами T1.5.6/T2.4.3, джоба Py3.15 — задачей T1.1.4.
- **Acceptance criteria:**
  - [x] CI зелёный на всех четырёх комбинациях OS/arch
  - [x] конфиг матрицы принимает джобы T1.1.4/T1.5.6/T2.4.3 без дублирования шагов (переиспользуемый composite/anchor)

#### T1.1.6 — README и LICENSE
- **What:** MIT-лицензия и публичный дисклеймер ответственности (D15, spec §8.6).
- **Where:** `README.md`, `LICENSE`.
- **How:** дисклеймер: инструмент для **авторизованного** тестирования, ответственность на операторе; краткое описание проекта; ссылка на `docs/development`; установка из исходников (git-install описывается в P5.5).
- **Acceptance criteria:**
  - [x] `LICENSE` — MIT
  - [x] README содержит дисклеймер об ответственности и законности тестирования
  - [x] README описывает установку и сборку из исходников

---

### P1.2 · Фаза «Общая память» (F1)

**Цель:** доменные модели (leaf), схема SQLite одного файла сессии, типизированный стор и полнотекстовый поиск.
**Зависимости:** P1.1 (скелет, `core/database` каркас создаётся здесь).
**DoD фазы:** схема+FTS5 и MemoryStore покрыты юнит-тестами (вклад в unit-gate T1.5.6).
**Задачи:** T1.2.1–T1.2.6.

#### T1.2.1 — Доменные модели (`memory/models.py`)
- **What:** Pydantic v2 модели всех доменных сущностей — единственное место доменных типов, leaf-модуль (arch §2.5, §4.1).
- **Where:** `src/swarmy/memory/models.py`.
- **How:** enums: `Severity` (обязателен у Finding, D14), `FindingStatus`, `FindingType` (xss/sqli/auth — открытый набор), `EvidenceKind` (`http_request_response`; `screenshot`/`har`/`grpc_file` зарезервированы — D20); модели: `Target`, `ScopeEntry` (kind/value/origin), `Endpoint` (host:port, method, path, auth_requirements, research_status, out_of_scope, notes), `Parameter`, `Finding` (severity обязателен, cvss опционален, endpoint_ref, evidence_refs, reproduction, created_by/at), `Evidence`, `AttackNode` (kind: precondition/finding/goal), `AttackEdge` (requires/enables/leads_to), `Note`, `Fact`; ссылки между сущностями — `int`-id, без вложенных графов (arch §4.2); импорт — только pydantic + stdlib.
- **Acceptance criteria:**
  - [x] архитектурный тест: модуль не импортирует другие пакеты swarmy
  - [x] состав полей соответствует arch §4.2 (сверка по модели)
  - [x] `EvidenceKind` содержит 4 значения; порождается в v0.1 только `http_request_response` (D20)
  - [x] типчекер strict чист

#### T1.2.2 — Обёртка БД (`core/database.py`)
- **What:** `Database` — управление соединениями к одному файлу `memory.sqlite`, WAL, мигратор.
- **Where:** `src/swarmy/core/database.py`.
- **How:** aiosqlite; по соединению на подсистему (AD-6), WAL, `busy_timeout = 5000`, `foreign_keys = ON`; мигратор: `schema_migrations(version, applied_at)` + последовательный список пар `(version, ddl)`, применяется в транзакции при `Session.open()` (запуск — T3.1.2); повторный open с той же версией — no-op; resume при совпадении версии пропускает миграции (arch §13.1); чекпойнтерные таблицы L0 — вне нашего DDL (создаёт checkpointer).
- **Acceptance criteria:**
  - [x] свежий файл: pragmas WAL/busy_timeout/foreign_keys применены (тест)
  - [x] миграции применяются в транзакции, версия фиксируется; повторный open идемпотентен
  - [x] попытка открыть каталог сессии более новой схемы — явная ошибка (сообщение о версии)

#### T1.2.3 — Схема SQLite (`memory/schema.py`)
- **What:** DDL всех таблиц одного файла памяти: 10 доменных, `events`, 4 FTS5 + триггеры синхронизации, `schema_migrations`.
- **Where:** `src/swarmy/memory/schema.py`.
- **How:** правила arch §4.3: многозначные поля (`tags`, `examples`, `evidence_refs`) — JSON-строки; `events.payload` — JSON payload-модели, `events.ts` — UTC ISO-8601; все доменные таблицы — `id INTEGER PRIMARY KEY AUTOINCREMENT`; FTS5-таблицы `fts_endpoints/fts_findings/fts_facts/fts_notes` (колонки title/body) с `AFTER INSERT/UPDATE` триггерами; владение: домен — MemoryStore, `events` — JournalWriter (append-only), fts — SearchIndex; единый мигратор (RD-8).
- **Acceptance criteria:**
  - [x] миграции создают все таблицы из arch §4.3 (сверка списком)
  - [x] триггеры: вставка/обновление Endpoint/Finding/Fact/Note синхронно обновляет соответствующую fts-таблицу (юнит-тест)
  - [x] DDL не создаёт чекпойнтерных таблиц L0 (их владелец — checkpointer)

#### T1.2.4 — Поиск (`memory/search.py`)
- **What:** интерфейс `SearchIndex` (Protocol) + реализация `Fts5SearchIndex`.
- **Where:** `src/swarmy/memory/search.py`.
- **How:** Protocol по arch §4.5 (`index_up`, `search`); реализация FTS5: bm25 + усиление совпадения в title, фильтр по типам сущностей, `limit`; выбор бэкенда — ключ конфига `memory.search_backend` (`vec`/sqlite-vec — фаза 2, не реализуется, интерфейс уже допускает — P4: две реализации не обязательны, но абстракция заложена).
- **Acceptance criteria:**
  - [x] на fixture-данных поиск возвращает релевантные хиты; совпадение в title ранжируется выше (тест)
  - [x] фильтр `entity_types` работает
  - [x] клиенты используют только Protocol (архитектурный тест: нет прямых обращений к FTS вне SearchIndex)

#### T1.2.5 — Стор (`memory/store.py`)
- **What:** `MemoryStore` — типизированный CRUD по таблице API arch §4.4.
- **Where:** `src/swarmy/memory/store.py`.
- **How:** методы: `search`, `get`, `upsert_endpoint` (дедуп по `(host, method, path)`, параметры — append), `save_finding` (валидация `evidence_refs` на существование), `update_finding_status`, `link_attack_node` (узел + рёбра атомарно), `add_fact`, `add_note`, `list_endpoints`, `list_findings`; `SearchHit` = `{entity_type, id, title_snippet, score}`; store **не импортирует** events/tools/tui (arch §2.5): платформенные события (`EndpointsDiscovered`/`EndpointUpdated`) публикуют обёртки `tools/platform.py` (T1.2.6) после успешной мутации — §5.2 arch «событие создаёт платформа».
- **Acceptance criteria:**
  - [x] все методы arch §4.4 реализованы с заявленными сигнатурами
  - [x] повторный `upsert_endpoint` обновляет запись, не дублирует (тест)
  - [x] `save_finding` с несуществующим `evidence_ref` — ошибка валидации (тест)
  - [x] `link_attack_node` создаёт узел и рёбра атомарно (тест отката при ошибке ребра)
  - [x] архитектурный тест: store не импортирует events/tools/tui

#### T1.2.6 — Платформенные обёртки `memory_*` (`tools/platform.py`)
- **What:** инструменты `memory_search/get/upsert_endpoint/save_finding/link_attack_node/add_fact/add_note` и платформенный `update_finding_status` (arch §4.4, §6.1).
- **Where:** `src/swarmy/tools/platform.py`.
- **How:** tool-функции с полной типизацией и docstring-описаниями; валидация аргументов Pydantic-моделями до вызова стора (arch §4.4); после успешной мутации — публикация платформенного события (payload по arch §5.5); инструменты получают `SessionContext` из замыкания фабрики (arch §8.5) — прямых импортов ядра из tool-функций нет.
- **Acceptance criteria:**
  - [x] каждый инструмент валидирует аргументы моделями (негативные тесты)
  - [x] `upsert_endpoint` публикует `EndpointsDiscovered`/`EndpointUpdated` с корректными payload (тест)
  - [x] `update_finding_status` публикует `FindingVerified`/`FindingRejected` по новому статусу (тест)
  - [x] все сигнатуры полностью типизированы, docstring непустые (проверка лоадера-валидатором из T1.5.3)

---

### P1.3 · Фаза «События: модели, шина, журнал» (F1)

**Цель:** таксономия событий v0.1, реестр типов, append-only журнал, шина с журнально-первым порядком, фабрика `emit_event`.
**Зависимости:** P1.2 (payload-модели ссылаются на доменные id; схема `events` из T1.2.3).
**DoD фазы:** шина/журнал покрыты юнит-тестами: порядок, фильтрация, изоляция ошибок, дочитывание.
**Задачи:** T1.3.1–T1.3.5.

#### T1.3.1 — Конверт, payload-модели, реестр (`events/models.py`)
- **What:** `EventEnvelope`, `EventSource`, payload-модели таксономии v0.1 и `EventRegistry`.
- **Where:** `src/swarmy/events/models.py`.
- **How:** конверт по arch §5.1: `id` (журнальный PK), `ts` (UTC), `type`, `source` (platform/orchestrator/module), `source_detail`, `correlation_id` ("" вне цепочек), `payload` (типизированная модель); payload-модели всех 13 типов §5.5 (TargetSet, ScopeChanged, EndpointsDiscovered, EndpointUpdated, FindingCandidate, FindingVerified, FindingRejected, AttackTreeUpdated, GuardrailBlocked, TaskRequested, TaskCompleted, OperatorMessage, OperatorDecision) — идентификаторы доменных сущностей + санитизированные дайджесты, без вложенных доменных объектов (arch §4.1); `EventRegistry.register/lookup` — единственное место «имя типа → payload-класс»; встроенные регистрируются при импорте пакета. *(Примечание v0.1: в таксономии 14-й встроенный тип — `OutboundSecretWarn`, добавлен после M2, см. D27 в spec §13; критерии ниже фиксируют состояние на момент M2.)*
- **Acceptance criteria:**
  - [x] реестр содержит все 13 типов; каждому — payload-класс (тест)
  - [x] payload-модели не содержат вложенных доменных моделей (архитектурный тест)
  - [x] повторная регистрация имени — ошибка (защита от коллизий модульных типов)

#### T1.3.2 — Журнал (`events/journal.py`)
- **What:** `JournalWriter` (append-only) и `JournalReader` (`tail`, `range`, `by_correlation`, `by_type`).
- **Where:** `src/swarmy/events/journal.py`.
- **How:** writer — только INSERT; `id` назначает SQLite (монотонный порядок — основа упорядоченной доставки, arch §5.3); reader — методы §5.4; `payload` — JSON (формат arch §4.3); append-only усиливается на уровне API (нет мутаций) + опциональный триггер-страж на UPDATE/DELETE таблицы `events`.
- **Acceptance criteria:**
  - [x] append возвращает монотонные id; порядок чтения = порядку записи (конкурентный тест)
  - [x] API не предоставляет мутаций; (если введён триггер) UPDATE/DELETE падает на уровне СУБД
  - [x] `by_correlation` восстанавливает цепочку на синтетических данных (тест)

#### T1.3.3 — Шина (`events/bus.py`)
- **What:** `EventBus` — in-memory asyncio pub/sub с журнально-первым порядком доставки.
- **Where:** `src/swarmy/events/bus.py`.
- **How:** очередь на подписчика; journal-first: append в `events` до fan-out → доставка по возрастанию `id` (arch §5.3); `subscribe(types: set[str] | None)`; изоляция ошибок обработчика (логирование, доставка остальным продолжается); режим coalescing для UI-подписчика (слияние обновлений: лишние перерисовки схлопываются, события доставляются полностью).
- **Acceptance criteria:**
  - [x] при конкурентной публикации подписчик получает события по возрастанию id (тест)
  - [x] исключение обработчика одного подписчика не мешает другим (тест)
  - [x] coalescing: N однотипных событий в очереди UI → одна отрисовка, счётчики корректны (тест)

#### T1.3.4 — Фабрика `emit_event` (`events/emit.py`)
- **What:** tool-функция `emit_event`, привязанная к сессии (bus, journal, correlation-контекст).
- **Where:** `src/swarmy/events/emit.py`.
- **How:** механика arch §5.2: аргументы `{type, payload}` валидируются реестром (неизвестный тип / невалидный payload → ошибка инструмента агенту); `source`/`source_detail` — от имени вызвавшего субагента (агент не может подделать источник); `correlation_id` — из contextvar контекста делегации (заполняется runtime в T3.2.3; до того — ""); публикация через шину после append в журнал.
- **Acceptance criteria:**
  - [x] неизвестный тип и невалидный payload отвергаются с понятным текстом ошибки (тесты)
  - [x] инструмент не принимает `source` извне — конверт собирает его сам (тест)
  - [x] `correlation_id` подхватывается из contextvar (тест с установленным контекстом)

#### T1.3.5 — Контурный тест «событие → журнал → подписчики»
- **What:** сквозной тест журнально-первого порядка и дочитывания после resume.
- **Where:** `tests/integration/events/test_journal_flow.py`.
- **How:** N конкурентных публикаций → в журнале N строк в порядке id; подписчики получили их по возрастанию id; имитация resume: новый reader с `range(from_id)` дочитывает хвост (arch §5.4).
- **Acceptance criteria:**
  - [x] тест зелёный на реальной SQLite (не моках)
  - [x] зафиксирован как канонический пример свойства «долговечность до доставки» (arch §5.3)

---

### P1.4 · Фаза «Гардрейлы: конвейер и DSL» (F1)

**Цель:** детерминированный pre-tool-call конвейер (3 слоя, И-композиция) + декларативный DSL `guardrails.yaml`; judge-слот зарезервирован (подключение в P3.4, RD-2).
**Зависимости:** P1.3 (событие `GuardrailBlocked`), P1.2 (модели домена в предикатах не нужны, но конвейер живёт на tool-аргументах).
**DoD фазы:** юнит-набор гардрейлов зелёный (каркас тестов §15.1 arch).
**Задачи:** T1.4.1–T1.4.6.

#### T1.4.1 — Типы правил (`guardrails/models.py`)
- **What:** модели правил, вердиктов и классов риска.
- **Where:** `src/swarmy/guardrails/models.py`.
- **How:** `RuleCondition` — 5 предикатов v0.1: `any_param_matches`/`url_matches`/`header_matches`/`body_size_above`/`tool_in` (конъюнкция предикатов, внутри `any_param_matches` — дизъюнкция, arch §6.6); `GuardrailRule` (id, applies_to, condition, `action: Literal["block"]` — v0.1, severity, message); `ModuleGuardrails` (`tool_classes` + `rules`); `Verdict` (allow/block/escalate_hitl/flag), `BlockedFeedback` (rule_id, layer, reason); `RiskClass` (passive/network-write/verify/destructive) живёт здесь, чтобы `tools.*` импортировал его без цикла (arch §2.5, AD-7).
- **Acceptance criteria:**
  - [x] модели соответствуют arch §6.6 (сверка)
  - [x] архитектурный тест: `tools.*` импортирует `RiskClass` из guardrails без цикла зависимостей
  - [x] типчекер strict чист

#### T1.4.2 — DSL `guardrails.yaml` (`guardrails/dsl.py`)
- **What:** парсинг и валидация файла модульных правил.
- **Where:** `src/swarmy/guardrails/dsl.py`.
- **How:** YAML → `ModuleGuardrails` (Pydantic); fail-fast — список ВСЕХ проблем файла сразу (arch §4.5); компиляция всех regex при валидации; проверка уникальности id; сверка `applies_to` против ToolRegistry — доступна с P1.5, до того структурная проверка имён.
- **Acceptance criteria:**
  - [x] пример spec §8.3 (`no-true-based-sqli`) парсится без ошибок
  - [x] файл с тремя разными ошибками даёт три записи в отчёте (тест)
  - [x] невалидный regex отклоняется на этапе валидации (тест)

#### T1.4.3 — Слой 1: инварианты (`guardrails/invariants.py`)
- **What:** платформенные инварианты — неотключаемый слой конвейера.
- **Where:** `src/swarmy/guardrails/invariants.py`.
- **How:** правила-константы кода с идентификаторами `invariant:*`: `platform-http` (сеть только платформенным клиентом — arch §6.5); слоты-заглушки для `scope`/`limits`/`timeout`/`out-of-scope-target`, подключаемые реальными проверками в P2.1 (T2.1.3); оценка — по аргументам до сети; инварианты отсутствуют в конфиг-схеме.
- **Acceptance criteria:**
  - [x] инварианты не конфигурируются (слот конфига отсутствует — тест схемы конфига после T3.1.1)
  - [x] правило `platform-http` срабатывает на инструменте вне платформенного http-набора с сетевым поведением (тест с фейковым «сетевым» инструментом)
  - [x] source всех правил слоя — префикс `invariant:` (тест)

#### T1.4.4 — Слой 2: базовые правила движка (`guardrails/engine_rules.py`)
- **What:** поставляемый отключаемый набор правил по умолчанию.
- **Where:** `src/swarmy/guardrails/engine_rules.py`.
- **How:** дефолтный набор (arch §6.6): `no-true-based-sqli` (пример spec §8.3), блок методов `TRACE`/`CONNECT`, блок известных опасных пейлоадов; отключение набора — параметр конвейера (в конфиге — ключ `guardrails.engine_rules`, читается с T3.1.1; до того — аргумент сборки).
- **Acceptance criteria:**
  - [x] TRUE-конструкции ловятся на `http_get`/`http_post` (параметризованный тест по образцу spec §8.3)
  - [x] `TRACE`/`CONNECT` блокируются (тест)
  - [x] набор отключаем флагом: вкл/выкл меняют вердикт (тест)

#### T1.4.5 — Конвейер (`guardrails/pipeline.py`)
- **What:** `GuardrailPipeline` + `GuardrailMiddleware` — pre-tool-call точка расширения L0.
- **Where:** `src/swarmy/guardrails/pipeline.py`.
- **How:** слои 1→2→3, И-композиция: запрет любого запрещает, разрешение требует всех (D11, arch §6.5); слой 3 — правила модуля для его инструментов; judge-слот зарезервирован (P3.4); семантика нарушения (spec §8.5, arch §6.5): вызов не выполняется; `GuardrailBlocked` в журнал+шину (payload arch §5.1 с `tool_args_digest`); агент получает текстовый фидбек (id правила, слой, причина); у субагента middleware = инварианты+движок+правила его модуля, у оркестратора = инварианты+движок; дайджест аргументов в M1 — тривиальное усечение, заменяется на ContextProjector в T2.3.2 (RD-4); имена middleware-хуков L0 сверяются с исходниками пина 0.7.41 (arch §19.1).
- **Acceptance criteria:**
  - [x] матрица композиции: каждый слой блокирует независимо; разрешение требует всех (параметризованный тест)
  - [x] при блоке: инструмент не вызван (spy), `GuardrailBlocked` в журнале и шине, агент получил фидбек с rule_id/layer (тест)
  - [x] подтверждены фактические имена хуков L0 для middleware; расхождение зафиксировано в §12 роадмапа

#### T1.4.6 — Юнит-набор гардрейлов
- **What:** каркас тестов конвейера по arch §15.1: DSL, слои, композиция, фидбек.
- **Where:** `tests/unit/guardrails/`.
- **How:** параметризованные матрицы композиции, негативные файлы DSL, spy-проверки семантики нарушения; mock-инструменты вместо сети.
- **Acceptance criteria:**
  - [x] набор покрывает все правила arch §6.5–§6.6; зелёный; без `xfail` без тикета
  - [x] вклад в unit-gate ≥ 85 % по `guardrails/` (локальная проверка `pytest --cov`)

---

### P1.5 · Фаза «Реестр инструментов и лоадер модулей» (F1)

**Цель:** fail-fast загрузка декларативных модулей: манифест, импорт инструментов, модульные гардрейлы, сборка SubAgent-словарей (RD-3: ToolRegistry здесь).
**Зависимости:** P1.4 (GuardrailMiddleware в словаре субагента), P1.3 (EventRegistry для проверки `events`), P1.2 (платформенные `memory_*` в toolset).
**DoD фазы:** модуль-пустышка загружается (критерий F1); unit-gate ≥ 85 % активен в CI.
**Задачи:** T1.5.1–T1.5.6.

#### T1.5.1 — Реестр инструментов (`tools/registry.py`)
- **What:** `ToolRegistry` — имена, risk-классы, владельцы, коллизии.
- **Where:** `src/swarmy/tools/registry.py`.
- **How:** `ToolEntry{fn, risk_class, owner, source}`; owner: `platform` | имя модуля; source: `builtin` | `module:<dir>` (arch §6.1); зарезервированные префиксы `memory_*`/`event_*`/`session_*` — модулям запрещены; платформенные инструменты доступны каждому субагенту (лоадер включает их в toolset — arch §6.1); коллизии — fail-fast агрегированным списком; risk_class — из атрибута `swarmy_risk_class` (дефолт `passive`, AD-7); авто-классификация http-инструментов — в P2.2 (T2.2.3).
- **Acceptance criteria:**
  - [x] регистрация дубликата имени и нарушение префикса дают агрегированную ошибку (тест)
  - [x] risk_class берётся из `swarmy_risk_class`, дефолт passive (тест AD-7)
  - [x] реестр различает owner/source (тест)

#### T1.5.2 — Манифест (`modules/manifest.py`)
- **What:** `AgentModuleManifest` + парсинг `AGENT.md`.
- **Where:** `src/swarmy/modules/manifest.py`.
- **How:** поля arch §8.2: `name`, `description` (обязательные), `model`, `mode`, `interrupt_on`, `events`, `guardrails`, `result` (AD-3: путь `"<module>/tools/result.py:Class"` → `response_format`); тело ниже фронтматтера → `system_prompt`; строгий YAML: неизвестные поля — ошибка; skills/tools во фронтматтере не объявляются (лоадер подключает папки автоматически).
- **Acceptance criteria:**
  - [x] минимальный манифест (name+description) валиден (тест)
  - [x] формат поля `result` распознаётся (без импорта класса — импорт в лоадере)
  - [x] неизвестное поле / плохой тип — точная ошибка валидации (тест)

#### T1.5.3 — Лоадер (`modules/loader.py`)
- **What:** `ModuleLoader` — сканирование, импорт, валидация, сборка SubAgent-словарей.
- **Where:** `src/swarmy/modules/loader.py`.
- **How:** конвейер arch §8.3: scan (пользовательские каталоги + встроенные модули: `<package>/agents` в wheel или `<repo>/agents` в editable-checkout); импорт `tools/*.py` через `importlib.util.spec_from_file_location` (не в `sys.path`); runtime-проверка типов (`typing.get_type_hints`: запрет `Any`/`dict[str, Any]`/неаннотированных параметров, обязательный docstring); парсинг `guardrails.yaml` (T1.4.2); регистрация модульных event-моделей из `tools/event_models.py`; fail-fast — единый список проблем по ВСЕМ модулям → `ModuleLoadError` (старт сессии прерван); сборка словаря: `name, description, system_prompt, model, mode, tools=[platform+module], middleware=[GuardrailMiddleware(...)], interrupt_on=merge(профиль, манифест), skills=[<dir>/skills/], response_format`; статический анализ импортов модуля: `socket`/`urllib`/`http.client` — ошибка (arch §8.5); коллизия имени с встроенным — ошибка без override (AD-4).
- **Acceptance criteria:**
  - [x] фикстурный модуль с валидными AGENT.md/tools/guardrails.yaml загружается; словарь соответствует arch §8.3 (сверка ключей)
  - [x] пять видов нарушений (нет docstring; `Any`-аннотация; зарезервированный префикс; сетевой импорт; незарегистрированный тип события) — каждое даёт точную строку в агрегированной ошибке (тесты)
  - [x] ошибка в одном модуле не прерывает сбор списка проблем по остальным (тест)

#### T1.5.4 — Реестр модулей (`modules/registry.py`)
- **What:** `ModuleRegistry` — имена модулей и сверка объявлений событий.
- **Where:** `src/swarmy/modules/registry.py`.
- **How:** имя → модуль; `events` фронтматтера сверяются с `EventRegistry` (arch §8.4); рантайм-сверка emit по реестру уже в T1.3.4 — здесь подключается проверка «объявленное = зарегистрированное».
- **Acceptance criteria:**
  - [x] объявленный, но незарегистрированный тип — ошибка загрузки (тест)
  - [x] emit незаявленного в манифесте типа — ошибка инструмента агенту (тест, стык с T1.3.4)

#### T1.5.5 — Модуль-пустышка и smoke загрузки
- **What:** минимальный фикстурный модуль + сквозной тест загрузки (критерий F1).
- **Where:** `tests/fixtures/modules/dummy/` (AGENT.md + tools/), `tests/integration/modules/test_loader_smoke.py`.
- **How:** dummy: фронтматтер name/description + один тривиальный типизированный инструмент; тест: сборка лоадера → dummy в реестре → SubAgent-словарь собран → fail-fast ошибки отсутствуют; фикстура становится шаблоном для модулей M3/M5.
- **Acceptance criteria:**
  - [x] критерий spec F1 «модуль-пустышка загружается» выполняется в CI
  - [x] структура фикстуры документирована как шаблон пользовательского модуля (комментарий в фикстуре)

#### T1.5.6 — Активация unit-gate покрытия (D22)
- **What:** порог unit ≥ 85 % включается в CI отдельной командой.
- **Where:** `.github/workflows/ci.yml`, `[tool.coverage.*]`.
- **How:** команда `pytest tests/unit --cov=swarmy --cov-fail-under=85`; исключения — только точечные `pragma: no cover` с фиксацией в `exclude_lines`; blanket-omit запрещён (D22); порог считается по этому набору отдельно (arch §15.1).
- **Acceptance criteria:**
  - [x] CI содержит отдельную команду unit-прогона с `--cov-fail-under=85`
  - [x] порог реально работает: локальный прогон с заниженным порогом падает (ручная проверка зафиксирована в PR)
  - [x] текущий набор ≥ 85 % по `src/swarmy`; исключения точечные и перечислены в конфиге

---

## 6. Майлстоун 2 — «Периметр исполнения» (F2)

**Состав:** P2.1 скоуп и лимиты · P2.2 HTTP-клиент и улики · P2.3 ContextProjector и секреты · P2.4 эхо-приложение и интеграционный контур.

### M2 · Definition of Done

Наследует критерий F2 (spec §12.3):

- [x] против эхо-приложения: запросы вне скоупа блокируются, улики пишутся, бюджеты/маскирование в `ContextProjector` работают
- [x] **integration-gate покрытия ≥ 70 % активен в CI** (D22; T2.4.3)
- [x] все 10 инвариантов arch §16, зависящие от периметра (1, 4, 7), подтверждены тестами

---

### P2.1 · Фаза «Скоуп и лимиты» (F2)

**Цель:** allowlist цели и глобальные ресурсные лимиты сессии; подключение инвариантов в конвейер.
**Зависимости:** P1.4 (слой инвариантов со слотами — T1.4.3).
**DoD фазы:** скоуп-матчинг и лимитёры покрыты юнит-тестами; инварианты блокируют до сети.
**Задачи:** T2.1.1–T2.1.3.

#### T2.1.1 — ScopeRegistry (`tools/scope.py`)
- **What:** allowlist скоупа и проверка цели каждого сетевого хопа.
- **Where:** `src/swarmy/tools/scope.py`.
- **How:** источник — `scope_entries` конфига; `check(url) → ScopeVerdict(allowed | denied(reason))`; семантика совпадения (arch §6.3): домен — точное имя или подчинённый поддомен (`example.com` покрывает `*.example.com`), IP — подсети `ipaddress`, порты — явный список (дефолт 80/443 по схеме), схемы — allowlist; `extend()` — только с `origin = operator` (публикация `ScopeChanged` — платформенный контур HITL, стыкуется в P3.3); запись памяти с `out_of_scope=True` сетевыми инструментами не обслуживается (`invariant: out-of-scope-target`).
- **Acceptance criteria:**
  - [x] матрица совпадений: поддомен да/нет, CIDR, порт по умолчанию, схема — параметризованные тесты
  - [x] `extend()` API-требует `origin=operator` (тест: программное расширение без оператора невозможно)
  - [x] запрос эндпоинта с `out_of_scope=True` — блок `invariant: out-of-scope-target` (тест)

#### T2.1.2 — ResourceLimiter (`tools/limits.py`)
- **What:** глобальные ресурсные лимиты сессии.
- **Where:** `src/swarmy/tools/limits.py`.
- **How:** механизмы arch §6.4: token bucket per host (`rate_limit`), глобальный `asyncio.Semaphore` (`max_concurrent_requests`), отсечка `max_body_bytes` при чтении, счётчик `max_redirect_depth` (используется клиентом), атомарный `total_request_budget` (исчерпание → отказ всех сетевых вызовов + `GuardrailBlocked(invariant: budget)`), connect/read таймауты; `acquire(host, method)` — async-контекст; лимиты **глобальные на сессию** — лимитёр не знает о субагентах (D19, инвариант 7 arch §16).
- **Acceptance criteria:**
  - [x] rps на хост соблюдается при параллельных вызовах (тест с замером интервалов)
  - [x] суммарные конкурентные запросы ≤ `max_concurrent_requests` в любой момент (тест-счётчик)
  - [x] исчерпание бюджета блокирует новые вызовы и публикует `invariant: budget` (тест)
  - [x] ожидание семафора/rate не блокирует event loop (async-тест)

#### T2.1.3 — Подключение инвариантов скоупа/лимитов
- **What:** слой 1 получает реальные проверки вместо слотов T1.4.3.
- **Where:** `src/swarmy/guardrails/invariants.py`.
- **How:** правила `invariant: scope`, `invariant: limits`, `invariant: out-of-scope-target`, `invariant: timeout`; оценка строго до сетевого вызова (порядок конвейера arch §6.2: гардрейлы → лимитёр → httpx); события — `layer="invariant"`.
- **Acceptance criteria:**
  - [x] запрос вне скоупа блокируется с `layer=invariant` до открытия соединения (юнит на мок-транспорте)
  - [x] инварианты срабатывают раньше `ResourceLimiter.acquire` (тест порядка конвейера)

---

### P2.2 · Фаза «HTTP-клиент и улики» (F2)

**Цель:** единственный сетевой путь с конвейером arch §6.2: гардрейлы → лимиты → httpx (ручные редиректы) → улики → проекция.
**Зависимости:** P2.1 (скоуп/лимиты в конвейере), P1.4 (GuardrailPipeline).
**DoD фазы:** конвейер клиента покрыт юнит-тестами на мок-транспорте; интеграционные сценарии — в P2.4.
**Задачи:** T2.2.1–T2.2.4.

#### T2.2.1 — Модели HTTP (`tools/http/models.py`)
- **What:** `RequestSpec` и `ResponseRecord`.
- **Where:** `src/swarmy/tools/http/models.py`.
- **How:** поля arch §6.2: `RequestSpec` — `method: Literal[GET, HEAD, POST, PUT, PATCH, DELETE]`, `url: HttpUrl`, `headers`, `query`, `body`, `evidence: bool = True`, `evidence_depth: Literal[request, request_response]`; `ResponseRecord` — `status`, `reason`, `headers`, `body_preview` (уже санитизированная проекция), `body_bytes`, `elapsed_ms`, `redirects: list[str]`, `evidence_id`, `request_id` (correlation).
- **Acceptance criteria:**
  - [x] модели соответствуют arch §6.2 (сверка)
  - [x] невалидный метод — ошибка валидации Pydantic (тест)

#### T2.2.2 — SwarmyHttpClient (`tools/http/client.py`)
- **What:** конвейер каждого сетевого вызова.
- **Where:** `src/swarmy/tools/http/client.py`.
- **How:** конвейер arch §6.2: `GuardrailPipeline.allow?` → `ResourceLimiter.acquire(host, method)` → `httpx.AsyncClient` (`redirects=False`) → **ручной цикл редиректов**: каждый хоп — повторный проход скоупа+лимитов со счётчиком глубины; кросс-доменный редирект вне скоупа = `GuardrailBlocked` → `EvidenceRecorder` (если `evidence=True`) → проекция (до T2.3.2 — сырой preview с отсечкой по `max_body_bytes`; после — ContextProjector) → `ResponseRecord`; таймауты из лимитов; нарушение = `TimeoutError` → `GuardrailBlocked(invariant: timeout)` + фидбек агенту; гигиена исходящих: детектор секретов в заголовках/теле → warn-событие + маскирование в preview (warn **не** блокирует — оператор сознательно передал креды).
- **Acceptance criteria:**
  - [x] каждый хоп редиректа проходит скоуп/лимиты (юнит на мок-цепочке; интеграционные цепочки — T2.4.2)
  - [x] таймаут возвращает агенту фидбек и пишет `invariant: timeout` в журнал (тест)
  - [x] секрет в исходящих → warn-событие, вызов не блокируется, preview маскирован (тест)
  - [x] вызов вне скоупа не открывает соединение (мок-транспорт, тест)

#### T2.2.3 — HTTP-инструменты (`tools/http/tools.py`)
- **What:** платформенные `http_get/http_post/http_put/http_delete`.
- **Where:** `src/swarmy/tools/http/tools.py`.
- **How:** тонкие обёртки над `client.request(RequestSpec)`; авто-классификация риска по HTTP-методу (AD-7): GET/HEAD → `passive`, POST/PUT/PATCH/DELETE → `network-write`; регистрация в ToolRegistry с `owner=platform`; клиент поддерживает все 6 Literal-методов, платформенных обёрток — четыре именованных (arch §6.1).
- **Acceptance criteria:**
  - [x] risk-классы проставлены по методу (тест реестра)
  - [x] инструменты проходят GuardrailPipeline (блок вне скоупа до сети — тест)

#### T2.2.4 — EvidenceRecorder (`tools/http/evidence.py`)
- **What:** файлы улик сессии + записи `Evidence`.
- **Where:** `src/swarmy/tools/http/evidence.py`.
- **How:** `evidence/<uuid>/request.txt` + `response.txt` — сырые, целиком (тело до порога `max_body_bytes`, дальше — маркер обрезки); запись `Evidence` (`kind=http_request_response`, `session_paths`, metadata: ts, инструмент, correlation_id); глубина `request` | `request_response` — по `evidence_depth` (D20: прочие kind зарезервированы; v0.1 порождает только перечисленные).
- **Acceptance criteria:**
  - [x] файлы улик байт-в-байт соответствуют трафику до порога (тест)
  - [x] запись Evidence связана с `ResponseRecord.evidence_id` (тест)
  - [x] `depth=request` не пишет `response.txt` (тест)

---

### P2.3 · Фаза «ContextProjector и секреты» (F2)

**Цель:** санитизированная проекция LLM-контекста (D21) и пломбирование секретов (AD-5).
**Зависимости:** P2.2 (preview HTTP-ответов), P1.3 (дайджесты событий).
**DoD фазы:** четыре шага проекции покрыты юнит-тестами; секреты не покидают периметр сессии.
**Задачи:** T2.3.1–T2.3.3.

#### T2.3.1 — ContextProjector (`tools/projector.py`)
- **What:** санитизация всего, что возвращается модели.
- **Where:** `src/swarmy/tools/projector.py`.
- **How:** четыре шага arch §6.8 в порядке 1→4: (1) байтовые бюджеты по классам инструментов (`context.budgets`) — усечение с маркером `[truncated N bytes]`, полное содержимое остаётся в уликах; (2) маскирование секретов оператора — значения/паттерны `secrets.yaml` + встроенные детекторы (Authorization/Cookie-подобные заголовки, bearer-токены) → `<masked:secret-name>`; (3) untrusted-маркировка — `[untrusted-target-content begin] ... [untrusted-target-content end]`; (4) нормализация control-символов и скрытого Unicode (biDi, zero-width).
- **Acceptance criteria:**
  - [x] каждый шаг покрыт юнит-тестом; форматы маркеров соответствуют arch §6.8 дословно
  - [x] шаги применяются в порядке §6.8 (тест-цепочка)
  - [x] детекты: bearer, Cookie, Authorization маскируются; обычные значения — нет (тесты)

#### T2.3.2 — ProjectorMiddleware и дайджесты
- **What:** post-tool-call проекция результатов всех агентов + перевод дайджестов на projector.
- **Where:** `src/swarmy/tools/projector.py`, `src/swarmy/guardrails/pipeline.py` (замена дайджеста), `src/swarmy/events/` (digest'ы payload).
- **How:** `ProjectorMiddleware` (post-tool-call хук L0, arch §19.1 — имена сверяются) у каждого агента: оркестратора и субагентов; `GuardrailBlocked.tool_args_digest` и журнальные digest'ы — через ContextProjector (закрытие RD-4); preview HTTP-ответов — через projector (смена заглушки T2.2.2).
- **Acceptance criteria:**
  - [x] результат любого инструмента проходит проекцию (интеграционный тест: большое тело + секрет)
  - [x] регресс-тест RD-4: дайджест в `GuardrailBlocked` маскирует секреты
  - [x] имена post-tool-call хуков L0 подтверждены; расхождение — в §12 роадмапа

#### T2.3.3 — Секреты оператора
- **What:** `secrets.yaml` (chmod 600), ссылки по имени, гарантии неразглашения.
- **Where:** `src/swarmy/core/config.py` (каркас загрузки — интеграция с SessionConfig в T3.1.1), `src/swarmy/tools/projector.py`.
- **How:** AD-5/arch §12.3: секреты — отдельный файл (chmod 600), категории `auth_headers`/`cookies`/`tokens`; в конфиге и инструментах — адресация по имени; в `session.yaml` не попадают; в улики — как есть; в журнал/чат/контекст — только `<masked:secret-name>`; до T3.1.1 projector принимает паттерны явно (конструктор/тесты).
- **Acceptance criteria:**
  - [x] права файла 600 выставляются (POSIX-тест; ограничение Windows задокументировано)
  - [x] скан тестовой сессии: сырое значение есть только в evidence-файлах (тест)
  - [x] снимок `session.yaml` не содержит значений секретов (тест; финальная проверка — T3.1.1)

---

### P2.4 · Фаза «Эхо-приложение и интеграционный контур» (F2)

**Цель:** фикстурный сервер и сквозные сценарии периметра; активация integration-gate.
**Зависимости:** P2.1–P2.3 (полный конвейер).
**DoD фазы:** критерий F2 spec выполняется; integration-gate ≥ 70 % активен.
**Задачи:** T2.4.1–T2.4.3.

#### T2.4.1 — Эхо-приложение (`tests/fixtures/echo_app`)
- **What:** управляемый aiohttp-сервер с воспроизводимым поведением.
- **Where:** `tests/fixtures/echo_app/` (dev-группа зависимостей).
- **How:** режимы arch §15.2: эхо параметров (отражения для детекторов), цепочки редиректов (внутри и вне скоупа), большие тела, «медленные» эндпоинты (таймауты), формы, sitemap, robots.txt; запуск на свободном localhost-порту из pytest-фикстуры; скоуп тестовых сессий указывает на него.
- **Acceptance criteria:**
  - [x] фикстура поднимается/останавливается в pytest без конфликтов портов (случайный порт)
  - [x] каждый режим поведения покрыт smoke-тестом фикстуры
  - [x] `aiohttp` — только dev-группа: runtime-импорт отсутствует (тест импорта)

#### T2.4.2 — Интеграционные сценарии периметра
- **What:** сквозные проверки F2 против эхо-приложения.
- **Where:** `tests/integration/http/`.
- **How:** сценарии: блок запроса вне скоупа (прямой + через редирект), запись улик байт-в-байт, бюджет тела и бюджета сессии, rate limit, таймаут → `invariant: timeout`, маскирование в preview, `out_of_scope`-эндпоинт не обслуживается.
- **Acceptance criteria:**
  - [x] каждый сценарий — отдельный именованный тест; зелёный на всей матрице CI
  - [x] критерий F2: вне скоупа блокируется, улики пишутся, бюджеты/маскирование работают (проверено на эхо-приложении)

#### T2.4.3 — Активация integration-gate (D22)
- **What:** порог integration ≥ 70 % в CI отдельной командой.
- **Where:** `.github/workflows/ci.yml`.
- **How:** `pytest tests/integration --cov=swarmy --cov-fail-under=70`; пороги считаются по каждому набору отдельно (D22; arch §15.1).
- **Acceptance criteria:**
  - [x] обе команды CI (unit 85 %, integration 70 %) зелёные и независимые
  - [x] локальное снятие порога роняет соответствующую команду (проверено и зафиксировано)

---

## 7. Майлстоун 3 — «Рой и HITL» (F3)

**Состав:** P3.1 конфиг, сессия, движок · P3.2 runtime и политики · P3.3 HITL · P3.4 LLM-судья · P3.5 параллельные делегации и сценарий верификации.

### M3 · Definition of Done

Наследует критерий F3 (spec §12.3) с оговоркой RD-6:

- [x] сценарий «находка → верификация» проходит через события (headless; T3.5.3)
- [x] параллельные `task()` работают с **глобальными** лимитами сессии (T3.5.1)
- [x] очередь аппрувов перехватывает `destructive`-вызовы и обслуживает решения (headless-приёмка, T3.3.3; UI-модалка — P4.3, RD-6)
- [x] resume-цикл: перезапуск процесса восстанавливает прерывания и продолжается без потерь (T3.3.3)
- [x] инварианты arch §16 № 2, 3, 5, 6, 8, 10 подтверждены тестами

---

### P3.1 · Фаза «Конфиг, сессия, движок» (F3)

**Цель:** composition root сессии, конфиг YAML с резолюцией, сборка deep-agent (оркестратора) с чекпойнтером, системный промпт.
**Зависимости:** P1.5 (лоадер и SubAgent-словари), P2.4 (периметр — tools движка), P1.2–P1.3 (память/события).
**DoD фазы:** `Session.open()` собирает все компоненты на одном Database; граф компилируется и чекпойнтерится.
**Задачи:** T3.1.1–T3.1.5.

#### T3.1.1 — SessionConfig (`core/config.py`)
- **What:** схема конфига сессии, резолюция, снимок `session.yaml`.
- **Where:** `src/swarmy/core/config.py`.
- **How:** секции arch §12.1: `target`, `scope`, `profile`, `mode`, `model`, `limits`, `memory.search_backend`, `context.budgets`, `guardrails.engine_rules`, `judge`, `policies`, `mcp_servers`, `agents_dirs` (AD-1: YAML); резолюция arch §12.2: CLI-флаги → файл → профиль → консервативные дефолты в коде; итог — иммутабельный Pydantic-объект + снимок `session.yaml` в каталог сессии (аудит); интеграция загрузки `secrets.yaml` (T2.3.3); ошибки — fail-fast списком.
- **Acceptance criteria:**
  - [x] пример конфига arch §12.1 парсится целиком (тест)
  - [x] приоритет резолюции проверен тестами (CLI побеждает файл, файл — дефолты)
  - [x] три ошибки конфига дают три записи отчёта (fail-fast списком)
  - [x] снимок `session.yaml` соответствует применённой конфигурации и не содержит секретов (тест)

#### T3.1.2 — Session (`core/session.py`)
- **What:** composition root: `open`/`resume`/`close`.
- **Where:** `src/swarmy/core/session.py`.
- **How:** порядок запуска arch §13.1: Database → JournalWriter/EventBus/ScopeRegistry/ResourceLimiter/ToolRegistry → MemoryStore+SearchIndex → ModuleLoader → Engine → событие `TargetSet` → SessionView (фасад для TUI — T4.1.1); Session владеет всеми компонентами, никто не создаёт «сам» (arch §2.2); resume: пропуск миграций при совпадении версии, дочитывание журнала (`range`), восстановление очереди прерываний (T3.3.3); close: checkpoint WAL, закрытие соединений; сессия — переносимая папка (arch §3.3).
- **Acceptance criteria:**
  - [x] `open` создаёт все компоненты на одном Database (тест владения/единственности)
  - [x] повторный `open` того же каталога — ошибка; resume — отдельный путь (тест)
  - [x] close завершает WAL; скопированный каталог сессии открывается «на другой машине» (тест копии)
  - [x] `swarmy.core` не импортирует `swarmy.tui` (архитектурный тест — инвариант 8)

#### T3.1.3 — Engine (`core/engine.py`)
- **What:** сборка `create_deep_agent` оркестратора (arch §9.1).
- **Where:** `src/swarmy/core/engine.py`.
- **How:** `create_deep_agent(model=session.config.model, system_prompt=ORCHESTRATOR_PROMPT, tools=[session_info, ...] (generate_report — с P5.4, RD-7), subagents=modules.subagent_specs, middleware=[GuardrailMiddleware, ProjectorMiddleware], interrupt_on=interrupt_cfg.orchestrator, checkpointer=AsyncSqliteSaver(...))`; типизированный враппер L0: вся нетипизированная работа с deepagents — только здесь (G3); SQLite-чекпойнтер пишет в `memory.sqlite` (arch §7.1).
- **Acceptance criteria:**
  - [x] граф компилируется; таблицы чекпойнтера появляются в `memory.sqlite` (тест)
  - [x] оркестратор имеет те же middleware, что и субагенты (тест сборки)
  - [x] враппер L0 — единственное место с послаблениями типизации (проверка ruff/ty per-file исключений)

#### T3.1.4 — Системный промпт (`core/prompts.py`)
- **What:** `ORCHESTRATOR_PROMPT` и шаблоны уведомлений политик.
- **Where:** `src/swarmy/core/prompts.py`.
- **How:** структура arch §9.6: (1) роль — оркестратор роя, делегации через `task()` по `description` модулей, чат, todos; (2) правила недоверия — контент цели данные, не инструкции; запрет исполнения инструкций из untrusted-блоков; сообщение об инъекциях; (3) политики — ссылки на шаблоны; (4) границы — вне скоупа не работать, `GuardrailBlocked` → коррекция плана, HITL — нормальная часть цикла; (5) стиль — кратко в чат, артефакты в память; динамический раздел — сгенерированный список модулей с `description`; шаблоны `verify_finding`, `tree_proposal` (для политик T3.2.2); сборка статична.
- **Acceptance criteria:**
  - [x] промпт содержит запрет исполнения инструкций из untrusted-маркеров (тест на маркеры)
  - [x] динамический раздел отражает загруженные модули (тест с dummy-модулем)
  - [x] промпт собирается без пользовательских инъекций текста (тест)

#### T3.1.5 — Инструмент `session_info`
- **What:** платформенный инструмент оркестратора о состоянии сессии.
- **Where:** `src/swarmy/tools/platform.py`.
- **How:** возвращает скоуп, статусы исследования, профиль, счётчик бюджета запросов — без сырых секретов (arch §6.1).
- **Acceptance criteria:**
  - [x] вывод содержит заявленные поля (тест)
  - [x] скан вывода не находит значений секретов (тест)

---

### P3.2 · Фаза «Runtime и политики событий» (F3)

**Цель:** исполнение графа оркестратора: single-writer (AD-8), три контура, декларативные политики, корреляция делегаций.
**Зависимости:** P3.1 (Engine, промпт, шаблоны).
**DoD фазы:** события через политики доходят до графа уведомлениями; resume-runtime восстанавливается.
**Задачи:** T3.2.1–T3.2.4.

#### T3.2.1 — OrchestratorRuntime (`core/runtime.py`)
- **What:** владение исполнением графа: single-writer + три контура.
- **Where:** `src/swarmy/core/runtime.py`.
- **How:** `asyncio.Lock` на `ainvoke`/`astream` — не более одного вызова в граф в каждый момент (AD-8; параллелизм — субагентами внутри шага, D19); контуры arch §9.2: реактивный (подписка на шину → политика → уведомление-дайджест → очередь → инъекция на границе шага), проактивный (todos L0), интерактивный (`OperatorMessage` → human-сообщение); цитаты из контента цели в уведомлениях — через ContextProjector с untrusted-маркерами; resume: восстановить состояние из чекпойнтера, дочитать журнал, продолжить (arch §9.2).
- **Acceptance criteria:**
  - [x] конкурентные «уведомление + сообщение оператора» сериализуются (тест с инструментированным моком графа)
  - [x] инвариант ≤1 активного вызова графа (тест-монитор)
  - [x] инъекции содержат untrusted-маркеры для цитат цели (тест)

#### T3.2.2 — Политики событий
- **What:** декларативный конвейер «событие → реакция» (arch §9.3).
- **Where:** `src/swarmy/core/runtime.py` (механика), `src/swarmy/core/prompts.py` (шаблоны).
- **How:** конфиг `policies` (`on`, `action: notify_orchestrator | notify_tui | ignore`, `template`); встроенные дефолты arch §9.3: `FindingCandidate → notify_orchestrator(verify_finding)`, `FindingVerified/FindingRejected → notify_orchestrator(tree_proposal)`, `GuardrailBlocked → notify_orchestrator`, `ScopeChanged → notify_orchestrator`, `AttackTreeUpdated/Task* → notify_tui`; политика только инъектирует уведомление — никаких делегаций/инструментов из кода (анти-паттерн arch §17).
- **Acceptance criteria:**
  - [x] `FindingCandidate` порождает уведомление по шаблону `verify_finding` (тест)
  - [x] дефолты активны при отсутствии секции `policies` (тест)
  - [x] архитектурный тест: код политик не вызывает инструменты и `task()` напрямую

#### T3.2.3 — Корреляция делегаций
- **What:** `correlation_id` на цепочках задач субагентов (arch §9.4).
- **Where:** `src/swarmy/core/runtime.py`, `src/swarmy/events/emit.py` (contextvar из T1.3.4).
- **How:** runtime при входе в субагента задаёт `correlation_id` в contextvar; события/улики/метаданные несут его; `TaskRequested`/`TaskCompleted` публикуются платформой и связывают дерево вызовов; `JournalReader.by_correlation` восстанавливает трассу (основа панели Swarm Activity, arch §10.1).
- **Acceptance criteria:**
  - [x] события из делегации несут её correlation_id (интеграционный тест с dummy-модулем)
  - [x] дерево `task()` восстанавливается из журнала (тест `by_correlation`)

#### T3.2.4 — Resume-поведение runtime
- **What:** восстановление контура после перезапуска.
- **Where:** `src/swarmy/core/runtime.py`.
- **How:** на resume: восстановить состояние из чекпойнтера, дочитать журнал (`range(from_id)`), восстановить очередь прерываний (T3.3.3), продолжить исполнение (arch §9.2, §13.1).
- **Acceptance criteria:**
  - [x] интеграционный тест: прерывание → «перезапуск» → продолжение без потери событий (совместно с T3.3.3)

---

### P3.3 · Фаза «HITL: профили и очередь аппрувов» (F3)

**Цель:** персистентные врата `interrupt_on` по классам инструментов, FIFO-очередь решений, resume-цикл, режимы interactive/mission.
**Зависимости:** P3.2 (runtime), P2.3 (санитизированные дайджесты аргументов).
**DoD фазы:** destructive-вызов перехватывается очередью; решение доставляется адресно; прерывание переживает перезапуск (headless, RD-6).
**Задачи:** T3.3.1–T3.3.4.

#### T3.3.1 — Профили → interrupt_on (`core/hitl.py`)
- **What:** `build_interrupt_config(profile, module_overrides)` (arch §7.2).
- **Where:** `src/swarmy/core/hitl.py`.
- **How:** матрица «класс × профиль» (D5): `paranoid` — врата на всё, кроме `passive`; `normal` (дефолт) — на `verify` и `destructive`; `yolo` — только `destructive`; `allowed_decisions = [approve, edit, reject]` (`respond` L0 не используется — arch §7.2); merge: явные `interrupt_on` модуля заменяют профильные записи (поведение L0); смена профиля/режима — пересборка конфига и перекомпиляция графа (документированная операция L0).
- **Acceptance criteria:**
  - [x] матрица совпадает с таблицей arch §7.2 (параметризованный тест)
  - [x] merge-семантика: модульная запись выигрывает у профильной (тест)
  - [x] пересборка на другом профиле меняет состав врат (тест)

#### T3.3.2 — ApprovalQueue
- **What:** очередь прерываний и подача решений (arch §7.3).
- **Where:** `src/swarmy/core/hitl.py`.
- **How:** опрос `snapshot.interrupts` → FIFO `ApprovalRequest{request_id, interrupt_id, tool, args_digest (санитизированный), rule/profile, origin}`; эскалации судьи — с `origin="judge"` (T3.4.x); `submit_decision(request_id, decision, edited_args?)` → `Command(resume={interrupt_id: decision})`; при `edit` — подстановка изменённых аргументов; решение публикуется как `OperatorDecision` и попадает в журнал; очередь не блокирует остальных субагентов (arch §7.3, §9.2 spec).
- **Acceptance criteria:**
  - [x] FIFO при нескольких параллельных прерываниях (тест)
  - [x] решение доставляется адресному `interrupt_id` (тест)
  - [x] `edit` подменяет аргументы; `reject` возвращает агенту фидбек «отклонено оператором» (тесты)
  - [x] каждый шаг фиксируется `OperatorDecision` в журнале (тест)

#### T3.3.3 — Resume-цикл HITL
- **What:** персистентность прерываний и цикл решений (arch §7.1, §7.4).
- **Where:** `src/swarmy/core/hitl.py`.
- **How:** проверенный API L0: `graph.aget_state(config) → snapshot.interrupts` → `graph.ainvoke(Command(resume={...}))` → повторять, пока прерывания не пусты; состояние прерываний — в SQLite-чекпойнтере, переживает перезапуск процесса; инвариант arch §7.4: после resume инструмент проходит **тот же** GuardrailPipeline — approve не отменяет инварианты.
- **Acceptance criteria:**
  - [x] интеграционный тест: destructive-вызов прерван → «перезапуск» → approve → инструмент исполнен и повторно прошёл гардрейлы
  - [x] очередь пустеет; журнал содержит полную цепочку (interrupt → decision → исполнение)

#### T3.3.4 — Режимы interactive/mission
- **What:** врата режима поверх профиля и переключение на лету (arch §7.2, §9.5).
- **Where:** `src/swarmy/core/hitl.py`, `src/swarmy/core/runtime.py`.
- **How:** `interactive` — дополнительные врата на значимые развилки (запуск тестов класса уязвимостей, верификация, изменение скоупа) через `interrupt_on`; `mission` — только профильные врата; переключение — команда оператора в чате → пересборка `interrupt_on` → перекомпиляция графа → событие в журнал.
- **Acceptance criteria:**
  - [x] состав врат различается по режимам (тест матрицы режим × класс)
  - [x] переключение на лету применяет новые врата (интеграционный тест) и пишет событие в журнал

---

### P3.4 · Фаза «LLM-судья» (F3; RD-2)

**Цель:** асинхронный «второй взгляд» с асимметрией полномочий: судья добавляет ограничения, не снимает детерминированные запреты (D11).
**Зависимости:** P3.3 (HITL-очередь для эскалаций), P1.4 (judge-слот конвейера).
**DoD фазы:** обе полосы судьи покрыты тестами на мок-модели; эскалация доходит до оператора.
**Задачи:** T3.4.1–T3.4.3.

#### T3.4.1 — Pre-call полоса (`guardrails/judge.py`)
- **What:** проверка подозрительных вызовов отдельной моделью до исполнения.
- **Where:** `src/swarmy/guardrails/judge.py`.
- **How:** конфиг `judge.{tools, model, confidence_threshold, timeout_s}` (arch §12.1); вызов — только после разрешения детерминированных слоёв и только для классов из `judge.tools`; вердикты: `ok` → исполнение; `flag` → исполнение + заметка в журнал; `escalate_hitl` (или таймаут — **fail-closed**) → вызов не выполняется, постановка в HITL-очередь с `origin="judge"`; асимметрия: судья не может разрешить детерминированный запрет (arch §6.7, D11); LLM в критическом пути **запрета** отсутствует (анти-паттерн arch §17).
- **Acceptance criteria:**
  - [x] вердикт-матрица на мок-судье: ok/flag/escalate — три ветки (тесты)
  - [x] таймаут судьи → fail-closed в HITL (тест)
  - [x] вызов, заблокированный слоями 1–3, до судьи не доходит (spy-тест)

#### T3.4.2 — Post-call полоса и JudgeEscalationRegistry
- **What:** асинхронный разбор результатов и временные врата на класс инструментов.
- **Where:** `src/swarmy/guardrails/judge.py`.
- **How:** эвристики подозрения (конфигурируемые паттерны instruction-like контента в результатах) → асинхронный судья вне пути исполнения; `flag` — заметка в журнал/контекст; `escalate_hitl` — событие оркестратору + **временные врата** `JudgeEscalationRegistry` на класс инструмента до решения оператора; снятие — только `OperatorDecision` (arch §6.7).
- **Acceptance criteria:**
  - [x] эскалация включает временные врата: последующие вызовы класса становятся HITL (тест)
  - [x] `OperatorDecision` снимает реестр (тест approve/reject-веток)
  - [x] post-call разбор не блокирует исполнение (async-тест)

#### T3.4.3 — Интеграция судьи с HITL
- **What:** сквозной путь эскалации против эхо-приложения.
- **Where:** `tests/integration/guardrails/test_judge_hitl.py`.
- **How:** мок-судья возвращает `escalate_hitl` → запрос появляется в ApprovalQueue с `origin="judge"` → решение оператора → снятие временных врат; журнал содержит `judge:<verdict>` цепочку.
- **Acceptance criteria:**
  - [x] сценарий зелёный; путь «эскалация → очередь → решение → снятие» подтверждён интеграционно

---

### P3.5 · Фаза «Параллельные делегации и сценарий верификации» (F3)

**Цель:** подтверждение async-параллелизма (D19) и сквозного реактивного контура «находка → верификация» (критерий F3).
**Зависимости:** P3.2–P3.4 (runtime, HITL, судья), P1.5 (фикстурные модули).
**DoD фазы:** критерии F3 headless выполняются в интеграционном наборе.
**Задачи:** T3.5.1–T3.5.3.

#### T3.5.1 — Параллельные task() с глобальными лимитами
- **What:** интеграционное подтверждение D19 (arch §9.4).
- **Where:** `tests/integration/runtime/test_parallel_tasks.py`.
- **How:** N параллельных `task()` в одном шаге графа (фикстурные модули) против эхо-приложения с малыми лимитами; замер фактической конкурентности и суммарного давления; лимитёр глобальный — не знает о субагентах (T2.1.2).
- **Acceptance criteria:**
  - [x] фактическая конкурентность > 1 подтверждена замером
  - [x] суммарные rps/семафор не превышены ни в один момент (метрики теста)
  - [x] события всех задач несут индивидуальные correlation_id

#### T3.5.2 — Мультипрерывания (arch §19.2)
- **What:** уточнение поведения `snapshot.interrupts` при нескольких параллельных `task()`.
- **Where:** `tests/integration/hitl/test_multi_interrupts.py`.
- **How:** несколько задач с verify-классом прерываются одновременно; фактическое поведение L0 фиксируется в комментарии теста (открытый вопрос §19.2 arch); FIFO ApprovalQueue обслуживает все запросы.
- **Acceptance criteria:**
  - [x] тест документирует наблюдаемое поведение L0 (комментарий-ссылка на arch §19.2) и проходит
  - [x] все прерывания обслужены очередью без потерь

#### T3.5.3 — Сценарий «находка → верификация» (headless)
- **What:** сквозной реактивный контур — критерий F3.
- **Where:** `tests/integration/scenarios/test_finding_verification.py`.
- **How:** фикстурный crawler-подобный модуль → `EndpointsDiscovered` → политика `notify_orchestrator` → оркестратор (скриптованный LLM-мок) делегирует верификацию (RD-5: повторная задача детектор-модуля с безопасными пейлоадами) → `memory_save_finding`/`update_finding_status` (платформа) → `FindingVerified` → политика `tree_proposal`; трасса по correlation_id.
- **Acceptance criteria:**
  - [x] сценарий зелёный headless (без TUI); журнал содержит полную цепочку по correlation_id
  - [x] статус находки изменён платформенным `update_finding_status` (не агентом напрямую)
  - [x] критерий F3 «сценарий через события» выполняется (спец-формулировка)

---

## 8. Майлстоун 4 — «Консоль оператора» (F4)

**Состав:** P4.1 каркас TUI и фасад · P4.2 информационные панели · P4.3 HITL-модалки (UI) и приёмка F4 · P4.4 деревья атак и маскирование.

### M4 · Definition of Done

Наследует критерий F4 (spec §12.3):

- [x] **полная сессия управляется из TUI без CLI-ввода** (T4.3.2)
- [x] все 6 панелей MVP работают (D10): Chat, Swarm Activity, Findings & Endpoints, HITL Approvals, Attack Trees, Progress & Plans
- [x] модалки HITL модальны для оператора, но не блокируют рой; очередь FIFO видима (T4.3.1)
- [x] TUI получает данные только через `SessionView` и `events.models` (инвариант 8 arch §16)

---

### P4.1 · Фаза «Каркас TUI и фасад SessionView» (F4)

**Цель:** Textual-приложение, состояние UI, фасад ядра, боевой CLI.
**Зависимости:** P3.1–P3.5 (живая сессия; SessionView опирается на Session).
**DoD фазы:** приложение стартует на реальной сессии; CLI запускает и резюмирует сессию.
**Задачи:** T4.1.1–T4.1.3.

#### T4.1.1 — SessionView и TuiState (`tui/state.py`)
- **What:** фасад ядра для UI и владелец UI-состояния (arch §10.2).
- **Where:** `src/swarmy/tui/state.py`.
- **How:** `SessionView` — read-only запросы (память, статусы, очередь approvals, хвост журнала) над `Session`; `TuiState` — подписка на EventBus с coalescing-очередью (arch §5.3), кэш снапшотов; TUI импортирует **только** фасад и `events.models` — internals ядра недоступны (arch §2.5, §10.2); сохраняет тестируемость ядра без UI и взаимозаменяемость TUI (headless — post-MVP).
- **Acceptance criteria:**
  - [x] архитектурный тест: импорты `swarmy.tui` ограничены фасадом + `events.models` (+L0 запрет)
  - [x] coalescing UI-очереди не теряет событий (тест)
  - [x] интеграционный набор M3 проходит в окружении без импорта `swarmy.tui` (инверсия зависимости)

#### T4.1.2 — SwarmyTui (`tui/app.py`)
- **What:** каркас Textual-приложения: раскладка, workers, рендер.
- **Where:** `src/swarmy/tui/app.py`.
- **How:** контейнер шести панелей (arch §10.1); цикл сессии — workers внутри event loop Textual (arch §2.2: ядро не знает о Textual); rich-разметка (markdown, таблицы, деревья); key bindings навигации по панелям.
- **Acceptance criteria:**
  - [x] приложение стартует на реальной сессии; панели-заглушки на месте
  - [x] workers не блокируют UI: рендер тикает при потоке событий (тест Textual harness)

#### T4.1.3 — Боевой CLI (`cli.py`)
- **What:** полный синтаксис запуска и resume (arch §3.4).
- **Where:** `src/swarmy/cli.py`.
- **How:** `swarmy <session-config.yaml> [--agents-dir PATH]... [--profile paranoid|normal|yolo] [--mode interactive|mission] [--model provider:model] [--session-dir PATH]`; `swarmy --resume <session-dir>`; `swarmy --version`; CLI только готовит `SessionConfig` и запускает `SwarmyTui` (headless вне скоупа v0.1); ошибки конфига — fail-fast до старта UI.
- **Acceptance criteria:**
  - [x] все флаги работают; конфиг-ошибки не открывают UI
  - [x] `--resume` продолжает существующую сессию (интеграционный тест)
  - [x] `swarmy --help` показывает актуальный синтаксис

---

### P4.2 · Фаза «Информационные панели» (F4)

**Цель:** Chat, Swarm Activity, Findings & Endpoints, Progress & Plans.
**Зависимости:** P4.1 (каркас, фасад).
**DoD фазы:** четыре панели отображают живые данные сессии и проходят тесты harness.
**Задачи:** T4.2.1–T4.2.4.

#### T4.2.1 — Панель Chat (`tui/panels/chat.py`)
- **What:** диалог оператор ↔ оркестратор + инспекция субагента.
- **Where:** `src/swarmy/tui/panels/chat.py`.
- **How:** источники: `OperatorMessage`/ответы оркестратора из журнала; отправка → платформа → `OperatorMessage` в журнал → runtime (интерактивный контур); переключение на живого субагента — read-only снапшот сообщений из чекпойнтера (arch §10.1); снапшот — санитизированный.
- **Acceptance criteria:**
  - [x] сообщения round-trip: отправка → оркестратор → ответ отображён (тест harness)
  - [x] инспекция субагента показывает санитизированный снапшот (маскирование применено — тест)

#### T4.2.2 — Панель Swarm Activity (`tui/panels/activity.py`)
- **What:** живая лента событий, дерево делегаций, статусы очереди approvals.
- **Where:** `src/swarmy/tui/panels/activity.py`.
- **How:** лента — подписка EventBus (coalescing); дерево `task()` по `correlation_id` (`TaskRequested`/`TaskCompleted`); статусы очереди approvals (arch §10.1).
- **Acceptance criteria:**
  - [x] лента обновляется в реальном времени (тест harness)
  - [x] дерево делегаций соответствует журналу (сверка в тесте)

#### T4.2.3 — Панель Findings & Endpoints (`tui/panels/findings.py`)
- **What:** таблицы эндпоинтов/параметров и карточка находки.
- **Where:** `src/swarmy/tui/panels/findings.py`.
- **How:** данные — SessionView (read-only запросы к MemoryStore); карточка: severity, evidence-файлы (открытие из `evidence/`), шаги воспроизведения; находки показываются **сырыми** значениями (правило arch §6.8: верификация пентестером), ленты/чат — маскированные.
- **Acceptance criteria:**
  - [x] карточка открывает файлы улик (тест наличия и путей)
  - [x] сырые значения в карточке против маскированных в лентах (тест различия)

#### T4.2.4 — Панель Progress & Plans (`tui/panels/plans.py`)
- **What:** todos оркестратора и статистика сессии.
- **Where:** `src/swarmy/tui/panels/plans.py`.
- **How:** todos — состояние L0; статистика: эндпоинты по статусам, находки по классам/severity — из памяти+журнала через фасад (arch §10.1).
- **Acceptance criteria:**
  - [x] статистика сходится с MemoryStore (тест-сверка)
  - [x] todos отражают состояние графа (тест с фиксированным состоянием)

---

### P4.3 · Фаза «HITL-модалки и очередь (UI)» (F4)

**Цель:** панель Approvals + модалка решения; финальная приёмка F4 (RD-6).
**Зависимости:** P3.3 (ApprovalQueue), P4.1–P4.2.
**DoD фазы:** критерий F4 spec выполняется end-to-end.
**Задачи:** T4.3.1–T4.3.2.

#### T4.3.1 — Панель Approvals и модалка (`tui/approvals.py`)
- **What:** видимая FIFO-очередь и модалка решения.
- **Where:** `src/swarmy/tui/approvals.py`.
- **How:** модалка показывает: инструмент, `args_digest` (санитизированные аргументы), активное правило/профиль, источник врат (профиль / модуль / judge-эскалация / режим); решения `approve` / `reject` / `edit` (форма редактирования аргументов); модалка модальна для оператора, **не блокирует рой** — остальные субагенты продолжают, их запросы встают в очередь; решение → `ApprovalQueue.submit_decision` (arch §10.3).
- **Acceptance criteria:**
  - [x] очередь отображает N одновременных запросов; решение применяется адресному запросу (тест harness)
  - [x] рой продолжает работу при открытой модалке (тест конкурентности)
  - [x] форма `edit` валидирует изменённые аргументы (тест)

#### T4.3.2 — Приёмка F4
- **What:** критерий spec «полная сессия управляется из TUI без CLI-ввода».
- **Where:** `tests/integration/tui/test_full_session.py`.
- **How:** сценарий Textual harness (headless-режим Textual в CI): старт сессии → фиксурная активность роя → approve destructive через модалку → команда в чате → проверка журнала и панелей; закрывает оговорку RD-6.
- **Acceptance criteria:**
  - [x] критерий F4 выполняется end-to-end без CLI-ввода
  - [x] сценарий включён в CI (headless Textual) и стабилен

---

### P4.4 · Фаза «Деревья атак (панель) и маскирование» (F4)

**Цель:** интерактивный рендер деревьев; регресс границ «сырое/маскированное» по всему UI.
**Зависимости:** P4.2 (карточка находки для перехода); приёмка — на фикстурных данных дерева (RD-9).
**DoD фазы:** все 6 панелей MVP работают (D10); маскирование подтверждено сквозным сканом.
**Задачи:** T4.4.1–T4.4.2.

#### T4.4.1 — Панель Attack Trees (`tui/panels/trees.py`)
- **What:** интерактивный рендер деревьев атак.
- **Where:** `src/swarmy/tui/panels/trees.py`.
- **How:** данные — `AttackNode`/`AttackEdge` из памяти через фасад; раскрытие узлов; переход «узел → карточка находки» (arch §10.1); rich-деревья.
- **Acceptance criteria:**
  - [x] дерево рендерится из фикстурных данных памяти (тест; RD-9)
  - [x] переход «узел → находка» работает (тест harness)

#### T4.4.2 — Маскирование в TUI (регресс)
- **What:** границы «сырое/маскированное» по всем панелям.
- **Where:** `src/swarmy/tui/**`.
- **How:** правило arch §6.8: ленты событий/чат — маскированные; карточки находок — сырые; улики — сырые файлы; сквозной скан текстов UI.
- **Acceptance criteria:**
  - [x] сквозной тест-скан не находит значений секретов вне карточек находок и файлов улик

---

## 9. Майлстоун 5 — «Референсный рой и релиз v0.1» (F5 + F6)

**Состав:** P5.1 модуль crawler · P5.2 модуль xss-detector · P5.3 деревья атак и демо-сценарий · P5.4 отчёт (F6) · P5.5 релиз v0.1.

### M5 · Definition of Done

Наследует критерии F5 и F6 (spec §12.3):

- [x] **демо-сессия**: цель → эндпоинты → XSS-кандидат → верификация → узел дерева (T5.3.2)
- [x] **`report.md` генерируется из сессии F5** (T5.4.3)
- [x] оба модуля — эталоны контракта §4 spec (dogfooding); добавление модуля не требует правок движка (инвариант 9)
- [x] приёмка v0.1: установка из git, CI-матрица + Py3.15 зелёные, оба coverage-gate активны, чек-лист §14 закрыт

---

### P5.1 · Фаза «Модуль crawler» (F5)

**Цель:** встроенный модуль первичной рекогносцировки — эталон контракта (arch §8.7).
**Зависимости:** P1.5 (лоадер), P2.2 (http-инструменты), P3.5 (интеграционный каркас сценариев).
**DoD фазы:** crawler находит эндпоинты/параметры на эхо-приложении и не выходит за скоуп.
**Задачи:** T5.1.1–T5.1.3.

#### T5.1.1 — Каркас модуля crawler
- **What:** папка `AGENT.md` + `guardrails.yaml` + `tools/`.
- **Where:** `agents/crawler/`.
- **How:** фронтматтер: `name`, `description`, `events: [EndpointsDiscovered, EndpointUpdated]` (arch §8.7); системный промпт пассивного recon (robots.txt, sitemap, обход ссылок, формы/параметры, карта эндпоинтов — spec §4.6); `guardrails.yaml`: ограничение глубины обхода через `url_matches`; `tools/parsers.py` — robots/sitemap/forms/links с `swarmy_risk_class = passive`.
- **Acceptance criteria:**
  - [x] модуль загружается лоадером; объявления событий сверены с реестром
  - [x] правило глубины обхода срабатывает (тест правила из guardrails.yaml)

#### T5.1.2 — Логика обхода
- **What:** рекогносцировка и запись карты эндпоинтов.
- **Where:** `agents/crawler/tools/`.
- **How:** `http_get` через платформу; парсеры → `memory_upsert_endpoint` (дедуп, параметры append); события `EndpointsDiscovered`/`EndpointUpdated`; скоуп-гарантии — платформенные (вне скоупа блокируется инвариантом, `out_of_scope` помечается — T2.1.1).
- **Acceptance criteria:**
  - [x] против эхо-приложения: эндпоинты и параметры найдены и записаны в память (тест)
  - [x] события с корректным correlation_id (тест)
  - [x] обход не выходит за скоуп (интеграционный тест: ссылки наружу блокируются)

#### T5.1.3 — Референс-качество (dogfooding)
- **What:** crawler как канонический пример авторского модуля.
- **Where:** `agents/crawler/`, раздел README/docs.
- **How:** соответствие arch §8.5 (полная типизация, docstrings, запрет сетевых импортов); краткий туториал «как написать модуль» на реальном коде crawler.
- **Acceptance criteria:**
  - [x] лоадер и линтер не выдают замечаний к модулю
  - [x] туториал воспроизводим на коде crawler (сверка сниппетов)

---

### P5.2 · Фаза «Модуль xss-detector» (F5)

**Цель:** детектор отражённого XSS — второй эталон контракта.
**Зависимости:** P5.1 (эндпоинты в памяти), P2.3 (маскирование), P3.3 (HITL на network-write).
**DoD фазы:** детектор порождает обоснованных кандидатов с уликами; опасные пейлоады блокируются.
**Задачи:** T5.2.1–T5.2.2.

#### T5.2.1 — Каркас модуля xss-detector
- **What:** папка `AGENT.md` + `guardrails.yaml` + `tools/`.
- **Where:** `agents/xss-detector/`.
- **How:** события: `[FindingCandidate]` (arch §8.7); `guardrails.yaml`: блок TRUE-конструкций и известных опасных пейлоадов (пример spec §8.3); `tools/marker.py` (постановка маркеров), `tools/reflection.py` (контекстный анализ отражений); POST-зонды автоматически `network-write` (AD-7 → врата профиля).
- **Acceptance criteria:**
  - [x] модуль загружается; события сверены
  - [x] TRUE-пейлоады и опасные конструкции блокируются модульным гардрейлом (тест)

#### T5.2.2 — Логика детектора
- **What:** маркеры → отражения → безопасные пейлоады → кандидат находки.
- **Where:** `agents/xss-detector/tools/`.
- **How:** выбор параметров (`memory_search` по эндпоинтам crawler), `http_get` с маркерами, контекстный анализ отражений, верификация безопасными пейлоадами (spec §4.6); `memory_save_finding(candidate)` → `FindingCandidate`; улики — автоматически (`evidence=True`).
- **Acceptance criteria:**
  - [x] против эхо-приложения: отражения → кандидаты с уликами (тест)
  - [x] отсутствие отражения — не кандидат (негативный тест)
  - [x] POST-зонд при профиле `normal` → HITL-запрос (интеграционный тест со стыком T3.3.2)

---

### P5.3 · Фаза «Деревья атак и демо-сценарий» (F5)

**Цель:** минимальные деревья атак и сквозная демо-сессия §13.4 arch.
**Зависимости:** P5.1–P5.2 (модули), P4.4 (панель деревьев), P3.2 (политика tree_proposal).
**DoD фазы:** критерий F5 spec выполняется; сценарий документирован как quickstart.
**Задачи:** T5.3.1–T5.3.2.

#### T5.3.1 — Связывание узлов дерева
- **What:** минимальные деревья атак из верифицированных находок.
- **Where:** `agents/xss-detector/tools/` (link-вызовы), политики в `core/prompts.py` (tree_proposal).
- **How:** `FindingVerified` → политика `tree_proposal` → оркестратор делегирует связывание → `memory_link_attack_node` (узел находки + предусловия + цель, рёбра `requires`/`enables`/`leads_to`) → `AttackTreeUpdated` (arch §13.4).
- **Acceptance criteria:**
  - [x] демо-дерево: предусловие → находка → цель с типизированными рёбрами (тест данных памяти)
  - [x] `AttackTreeUpdated` доходит до TUI (стык T4.4.1)

#### T5.3.2 — Демо-сценарий F5
- **What:** сквозная демо-сессия (arch §13.4) — критерий F5.
- **Where:** `tests/integration/scenarios/test_demo_f5.py`, README quickstart.
- **How:** команда оператора «проверь цель X на XSS» → todos → `task(crawler)` → эндпоинты → `task(xss-detector)` → маркеры/отражения → HITL approve (POST, профиль normal) → `FindingCandidate` → политика verify_finding → верификация (RD-5) → `FindingVerified` → tree_proposal → `AttackTreeUpdated`; оператор видит ленту, находку, узел дерева.
- **Acceptance criteria:**
  - [x] критерий spec F5: цель → эндпоинты → XSS-кандидат → верификация → узел дерева (выполняется)
  - [x] журнал содержит трассу всей цепочки по correlation_id
  - [x] сценарий оформлен как воспроизводимый quickstart в README

---

### P5.4 · Фаза «Отчёт» (F6)

**Цель:** детерминированный markdown-отчёт сессии.
**Зависимости:** P5.3 (демо-сессия как источник данных), P3.1 (конфиг).
**DoD фазы:** `report.md` генерируется из сессии F5 (критерий F6).
**Задачи:** T5.4.1–T5.4.3.

#### T5.4.1 — ReportGenerator и инструмент `generate_report`
- **What:** генератор без LLM-генерации текста + platform tool оркестратора.
- **Where:** `src/swarmy/report/generator.py` (инструмент включается в tools движка — RD-7).
- **How:** вход — запросы к MemoryStore (находки по severity, эндпоинты, деревья, статистика журнала) + конфиг сессии; `report` импортирует только `memory.store` read-only (arch §2.5); выход — `<session-dir>/report.md`.
- **Acceptance criteria:**
  - [x] инструмент зарегистрирован и доступен оркестратору (тест сборки движка)
  - [x] генерация не выполняет LLM/сетевых вызовов (тест)
  - [x] отчёт пишется в каталог сессии (тест)

#### T5.4.2 — Шаблон отчёта (`report/templates/report.md.j2`)
- **What:** jinja2-шаблон по spec §10.
- **Where:** `src/swarmy/report/templates/report.md.j2`.
- **How:** структура: сводка (target, скоуп, период, статистика) → находки (сортировка по severity; описание, endpoint, evidence-ссылки, шаги воспроизведения) → деревья атак (текст + mermaid) → приложение (полный список исследованных эндпоинтов); первая строка — пометка «черновик, требует ревью пентестера»; mermaid — подмножество синтаксиса, совместимое с распространёнными рендерерами (закрытие arch §19.4).
- **Acceptance criteria:**
  - [x] отчёт из демо-сессии F5 содержит все секции (golden-file тест)
  - [x] mermaid-фрагмент проходит базовую синтаксическую проверку (решение §19.4 зафиксировано в комментарии шаблона)
  - [x] пометка черновика — первая строка файла

#### T5.4.3 — Критерий F6
- **What:** `report.md` генерируется из сессии F5.
- **Where:** `tests/integration/report/test_report_generation.py`.
- **How:** после демо-сценария T5.3.2 → `generate_report` → проверка структуры, ссылок на evidence-файлы и сортировки находок.
- **Acceptance criteria:**
  - [x] критерий spec F6 выполняется в CI
  - [x] evidence-ссылки отчёта указывают на существующие файлы улик (тест)

---

### P5.5 · Фаза «Релиз v0.1»

**Цель:** упаковка, документация, полная приёмка (D17: без PyPI, установка из git).
**Зависимости:** P5.4 (все критерии фаз закрыты).
**DoD фазы:** чек-лист §14 закрыт; тег v0.1.
**Задачи:** T5.5.1–T5.5.2.

#### T5.5.1 — Упаковка и пользовательская документация
- **What:** финальная сборка и документация пользователя.
- **Where:** `pyproject.toml`, `README.md`, `docs/development/*`.
- **How:** сборка sdist/wheel из `src/swarmy` (docs не входит в дистрибуцию — arch §3.1); установка из git: `uv tool install git+…` (D17: PyPI-публикация v0.1 не планируется; будущая дистрибуция — `swarmy-cli`); README: дисклеймер (D15), quickstart на демо-сценарии T5.3.2, раздел «написание модулей» (T5.1.3); кросс-ссылки spec/architecture/roadmap.
- **Acceptance criteria:**
  - [x] установка из git-источника даёт рабочий CLI (проверено на локальном пути/репозитории)
  - [x] sdist/wheel собираются; runtime-зависимости не тянут dev-группу (тест импортов установленного пакета)
  - [x] quickstart README воспроизводит демо-сессию по инструкции

#### T5.5.2 — Полная приёмка v0.1
- **What:** контрольный прогон всех критериев фаз F0–F6.
- **Where:** `.github/workflows/ci.yml`, чек-лист §14 этого документа.
- **How:** прохождение чек-листа трассировки §14; CI зелёный на матрице (4 платформы) + джоба Py3.15; оба coverage-gate активны; релизная метка `v0.1` (без PyPI — D17).
- **Acceptance criteria:**
  - [x] чек-лист §14 полностью отмечен
  - [x] CI-матрица + Py3.15 зелёные; оба gate активны
  - [x] тег `v0.1`; установка из git работает

---

## 10. Зависимости и порядок исполнения

### 10.1. Граф фаз

```
P1.1 ─▶ P1.2 ─▶ P1.3 ─▶ P1.4 ─▶ P1.5 ──┐
  (F0)  память   события  гардрейлы лоадер│
                                        ▼
                     P2.1 ─▶ P2.2 ─▶ P2.3 ─▶ P2.4 ──┐
                     скоуп/  http+  projector эхо+gate│
                     лимиты  улики                    │
                                                      ▼
        P3.1 ─▶ P3.2 ─▶ P3.3 ─▶ P3.4 ─▶ P3.5 ────────┤
        сессия/  runtime  HITL    судья   параллелизм │
        движок   политики                            │
                                                      ▼
        P4.1 ─▶ P4.2 ─▶ P4.3 ─▶ P4.4 ────────────────┤
        фасад/   панели  модалки деревья+            │
        CLI           +приёмка F4 маски              │
                                                      ▼
        P5.1 ─▶ P5.2 ─▶ P5.3 ─▶ P5.4 ─▶ P5.5
        crawler  xss-    демо    отчёт  релиз
                 детектор F5      F6    v0.1
```

### 10.2. Ключевые перекрёстные зависимости

| Фаза | Зависит от | Что потребляет |
|---|---|---|
| P1.3 | P1.2 | доменные id в payload-моделях; DDL `events` |
| P1.4 | P1.3 | событие `GuardrailBlocked` |
| P1.5 | P1.4, P1.3, P1.2 | GuardrailMiddleware, EventRegistry, платформенные `memory_*` |
| P2.1 | P1.4 | слой инвариантов (слоты T1.4.3) |
| P2.2 | P2.1, P1.4 | скоуп/лимиты в конвейере клиента |
| P2.3 | P2.2 | preview HTTP-ответов; P1.3 — дайджесты (RD-4) |
| P2.4 | P2.1–P2.3 | полный конвейер периметра |
| P3.1 | P1.5, P2.4 | SubAgent-словари; tools движка; конфиг секретов (T2.3.3) |
| P3.2 | P3.1 | Engine, шаблоны промпта |
| P3.3 | P3.2 | runtime-инъекции; P2.3 — санитизированные дайджесты |
| P3.4 | P3.3, P1.4 | HITL-очередь для эскалаций; judge-слот конвейера |
| P3.5 | P3.2–P3.4 | полный контур роя |
| P4.1 | P3.1–P3.5 | живая сессия, ApprovalQueue |
| P4.3 | P3.3, P4.1–P4.2 | ApprovalQueue API |
| P4.4 | P4.2 | карточка находки; фикстурные данные деревьев (acceptance, RD-9) |
| P5.1–P5.2 | P1.5, P2.2, P3.5 | лоадер, http-инструменты, интеграционный каркас |
| P5.3 | P5.1–P5.2, P3.2, P4.4 | модули, политика tree_proposal, панель деревьев |
| P5.4 | P5.3 | данные демо-сессии |
| P5.5 | P5.4 | все критерии F0–F6 |

### 10.3. Допустимый параллелизм

- **Внутри M1:** T1.2.1 (модели) и T1.3.1 (payload-модели по id — после фиксации моделей) стартуют параллельно; P1.4 не стартует до T1.3.1.
- **Внутри M2:** T2.3.1 (шаги проекции как чистые функции) параллелится с T2.2.2–T2.2.4; стыковка — T2.3.2.
- **Внутри M3:** T3.1.4 (промпт) и T3.1.1 (конфиг) параллельны после T3.1.3-каркаса; T3.4.1–T3.4.2 (судья на моках) параллелятся с T3.3.2 после T3.3.1.
- **Внутри M4:** панели T4.2.1–T4.2.4 независимы после T4.1.1.
- **Внутри M5:** T5.1.1 и T5.2.1 (каркасы модулей) параллельны.

---

## 11. Риски и смягчения

| # | Риск | Фаза | Смягчение |
|---|---|---|---|
| R1 | Дрейф API L0: имена middleware-хуков (`wrap_tool_call`/post-tool-call) отличаются от ожиданий (arch §19.1) | P1.4, P2.3 | сверка с исходниками пина 0.7.41 в T1.4.5/T2.3.2; типизированный враппер L0 — точка изоляции; отклонения — дефект-процедура §12 |
| R2 | Поведение `snapshot.interrupts` при множественных параллельных `task()` неизвестно (arch §19.2) | P3.5 | выделенный тест T3.5.2 фиксирует фактическое поведение; FIFO-очередь изолирует UI от деталей L0 |
| R3 | Совместимость deepagents/зависимостей с Py3.15 (классификаторы до 3.14) | P1.1 | smoke T1.1.4 в CI с первого дня; расхождение — ранний сигнал, до накопления кода |
| R4 | Single-writer runtime (AD-8) сужает пропускную способность оркестратора на границах шагов | P3.2 | замер в T3.5.1; уведомления — коалесцирующая очередь; при проблемах — пересмотр (как в D19: «пересмотреть при проблемах с давлением на цель») |
| R5 | Сериализация записей трёх подсистем в одном SQLite (AD-6) под параллельным роем | P3.5 | `busy_timeout` + WAL уже заложены; интеграционные тесты параллелизма (T3.5.1) как нагрузочный минимальный прогон |
| R6 | Пороги D22 (unit 85 %) замедляют ранние итерации | P1.5 | порог активируется в конце M1 (T1.5.6), когда ядро уже покрыто; исключения — только точечные |
| R7 | HITL-модалки в Textual: конкуренция UI-потока и workers роя | P4.3 | вся логика очереди оттестирована headless в P3.3; UI — тонкий слой над ApprovalQueue (T4.3.1) |
| R8 | Mermaid-рендеринг деревьев в отчёте ограничен рендерерами (arch §19.4) | P5.4 | выбор совместимого подмножества синтаксиса в T5.4.2; текстовый рендер — фолбэк |
| R9 | Неопределённость «верификатора» демо-сценария | P5.3 | решена RD-5: повторная делегация xss-detector + платформенный `update_finding_status`; отдельный модуль не вводится |
| R10 | Секреты оператора на Windows: chmod 600 неприменим | P2.3 | POSIX-тест + документированное ограничение Windows (T2.3.3); маскирование — основная гарантия, права — дополнительная |

---

## 12. Открытые вопросы реализации (привязка к фазам)

Из arch §19 — уточняются по ходу фаз против пина deepagents (процедура D18); новых блокирующих вопросов нет:

| # | Вопрос (arch §19) | Фаза | Задача |
|---|---|---|---|
| Q1 | Имена middleware-хуков L0 для Guardrail/Projector middleware | P1.4, P2.3 | T1.4.5, T2.3.2 |
| Q2 | Поведение `Snapshot.interrupts` при многих параллельных `task()` | P3.5 | T3.5.2 |
| Q3 | Минимальные версии зависимостей (кроме пина deepagents) | P1.1 | T1.1.1, T1.1.4 |
| Q4 | Формат mermaid-рендера деревьев в отчёте | P5.4 | T5.4.2 |

Планировочные неоднозначности, снятые этим документом: RD-1–RD-9 (§4). Если реализация обнаружит новое расхождение со spec/architecture — оно фиксируется как дефект дизайна и пополняет этот раздел.

---

## 13. Post-MVP и зарезервированные точки расширения

Вне скоупа v0.1 (spec §1.4, §12.3) — в порядке появления после релиза:

- **gRPC-инструменты** — `grpcio`; колёса под Python 3.15 отслеживаются по grpc#41010 (spec §7.5);
- **векторный поиск** — `VecSearchIndex` (sqlite-vec, пин версии из-за pre-v1 статуса) поверх интерфейса `SearchIndex` (arch §4.5; ключ `memory.search_backend` уже заложен);
- **Docker-сандбокс** исполнения — опциональная изоляция (D4);
- **интеграция с прокси** (Burp/mitm);
- **headless-режим** без TUI — `swarmy.core` уже не знает о Textual (arch §2.2), фасад `SessionView` готов (T4.1.1);
- **движок корреляции деревьев атак**;
- **не-HTTP улики** — `screenshot`/`har`/`grpc_file`: значения уже зарезервированы в `EvidenceKind` без миграции схем (D20).

Зарезервированные в v0.1 точки расширения сохраняют аддитивность Post-MVP: enum `EvidenceKind` (D20), интерфейс `SearchIndex` (arch §4.5), `action: review/allow` в DSL гардрейлов (v0.1 — только `block`, arch §6.6), `metadata.include_tools` скиллов (arch §8.6), MCP-серверы через конфиг сессии (arch §12.1).

---

## 14. Чек-лист трассировки и приёмки v0.1

Соответствие фаз spec §12.3 фазам роадмапа и задачам-носителям критериев:

| Фаза spec | Критерий spec (§12.3) | Фазы роадмапа | Носители критерия |
|---|---|---|---|
| F0 | `pip install -e .` + `swarmy --help` на всех платформах | P1.1 | T1.1.1–T1.1.5 |
| F1 | Юнит-тесты ядра зелёные; unit-gate ≥ 85 % в CI (D22); модуль-пустышка загружается | P1.2–P1.5 | T1.5.5 (пустышка), T1.5.6 (gate) |
| F2 | Эхо-приложение: вне скоупа блокируется, улики пишутся, бюджеты/маски работают; integration-gate ≥ 70 % | P2.1–P2.4 | T2.4.2 (сценарии), T2.4.3 (gate) |
| F3 | Сценарий «находка → верификация» через события; параллельные `task()` с глобальными лимитами; HITL перехватывает destructive, очередь работает | P3.1–P3.5 | T3.5.3 (сценарий), T3.5.1 (параллелизм), T3.3.3 (очередь, headless; модалка — T4.3.1, RD-6) |
| F4 | Полная сессия управляется из TUI без CLI-ввода | P4.1–P4.4 | T4.3.2 |
| F5 | Демо-сессия: цель → эндпоинты → XSS-кандидат → верификация → узел дерева | P5.1–P5.3 | T5.3.2 |
| F6 | `report.md` генерируется из сессии F5 | P5.4 | T5.4.3 |

Приёмка релиза (закрывается в T5.5.2):

- [x] все критерии фаз F0–F6 отмечены в таблице выше (через соответствующие задачи)
- [x] CI-матрица (windows/amd64, macos/arm64, linux/amd64, linux/arm64) зелёная
- [x] джоба Python 3.15 зелёная
- [x] unit-gate ≥ 85 % и integration-gate ≥ 70 % активны и зелёные
- [x] демо-сценарий F5 воспроизводится по quickstart README
- [x] установка из git даёт рабочий CLI; пакет собирается (sdist/wheel)
- [x] тег `v0.1` выставлен (без PyPI — D17)

---

*Источники: [spec.md](spec.md) v0.3-draft · [architecture.md](architecture.md) v0.1-draft. Документ сопровождается вместе с кодом: расхождение реализации со spec/architecture/roadmap — дефект.*
