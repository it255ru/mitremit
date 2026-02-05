# Docker Security Scanning Workflows

## Структура файлов

```
.github/
├── workflows/
│   ├── ci.yml              # Быстрые проверки на каждый push/PR
│   └── security.yml        # Полный security scan
├── actions/
│   └── setup-security-tools/
│       └── action.yml      # Composite action для установки инструментов
├── dependabot.yml          # Автообновление зависимостей
└── CODEOWNERS              # (опционально) Ревьюеры для workflows

# Корень проекта
├── .grype.yaml             # Конфиг Grype (игнорируемые CVE)
├── .trivyignore            # Игнорируемые CVE для Trivy
├── .dockerignore           # Файлы исключённые из Docker контекста
└── Dockerfile
```

## Workflows

### CI (`ci.yml`)

**Триггеры:** `push`, `pull_request`

**Что делает:**
1. Lint Dockerfile (Hadolint)
2. Build Docker image
3. Quick security check (Critical/High only)

**Время выполнения:** ~3-5 минут

**Блокирует merge:** Да (при ошибках lint или build)

---

### Security Scan (`security.yml`)

**Триггеры:** 
- `push` to main/master
- `schedule` (weekly Monday 6:00 UTC)
- `workflow_dispatch` (manual)

**Что делает:**
1. Build Docker image
2. Generate SBOM (CycloneDX + SPDX)
3. Grype vulnerability scan
4. Trivy vulnerability scan
5. Docker image analysis
6. Generate comprehensive report
7. Create GitHub issue

**Время выполнения:** ~10-15 минут

**Артефакты:**
- `sbom/` - SBOM в форматах CycloneDX и SPDX
- `grype-results/` - Результаты Grype
- `trivy-results/` - Результаты Trivy
- `image-analysis/` - Анализ Docker образа
- `security-report/` - Сводный отчёт

---

## Конфигурация

### Игнорирование CVE

**Grype** (`.grype.yaml`):
```yaml
ignore:
  - vulnerability: CVE-2025-60876
    reason: "Описание почему игнорируем"
```

**Trivy** (`.trivyignore`):
```
# Комментарий с причиной
CVE-2025-60876
```

### Версии инструментов

Версии зафиксированы в `env:` блоке каждого workflow:

```yaml
env:
  HADOLINT_VERSION: "2.12.0"
  GRYPE_VERSION: "0.84.0"
  SYFT_VERSION: "1.18.1"
  TRIVY_VERSION: "0.58.0"
```

Dependabot автоматически создаёт PR при выходе новых версий.

---

## 📊 Security Gates

| Gate | Условие | Действие |
|------|---------|----------|
| CI Quick Check | Critical/High CVE | Warning (не блокирует) |
| Security Gate | Critical CVE | Fail workflow |
| Build Gate | Build failed | Fail workflow |

Для изменения поведения используй `workflow_dispatch` inputs:
- `fail-on-critical`: Падать ли на Critical CVE
- `create-issue`: Создавать ли GitHub issue

---

## 🚀 Использование

### Локальный запуск

```bash
# Hadolint
docker run --rm -i hadolint/hadolint < Dockerfile

# Grype
grype dir:. --config .grype.yaml

# Trivy
trivy fs --ignorefile .trivyignore .

# Build и scan образа
docker build -t myapp:latest .
grype myapp:latest --config .grype.yaml
trivy image --ignorefile .trivyignore myapp:latest
```

### Ручной запуск Security Scan

```bash
gh workflow run security.yml \
  --field create-issue=true \
  --field fail-on-critical=false
```

---

## Добавление нового CVE в ignore

1. Проанализируй CVE — действительно ли она применима к твоему приложению
2. Добавь в `.grype.yaml`:
   ```yaml
   - vulnerability: CVE-XXXX-XXXXX
     reason: "Конкретная причина почему не применимо"
   ```
3. Добавь в `.trivyignore`:
   ```
   # Причина
   CVE-XXXX-XXXXX
   ```
4. Создай PR с описанием почему CVE игнорируется
5. Получи review от security team

---

## Ссылки

- [Grype Documentation](https://github.com/anchore/grype)
- [Trivy Documentation](https://aquasecurity.github.io/trivy/)
- [Hadolint Rules](https://github.com/hadolint/hadolint#rules)
- [CycloneDX Specification](https://cyclonedx.org/specification/overview/)
- [GitHub Actions Best Practices](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions)
