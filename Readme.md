# MITRE Mitigations Lookup Tool

Утилита для поиска всех техник и под-техник MITRE ATT&CK, которые смягчаются заданной контрмерой (mitigation).

## Возможности

- Поиск по идентификатору контрмеры (например, `M1037`) или по её названию
- Автоматическое скачивание и кэширование актуальной STIX-базы ATT&CK Enterprise
- Поддержка нескольких форматов вывода:
  - Таблица (по умолчанию)
  - JSON
  - CSV
  - nGQL-запросы для Nebula Graph

## Установка и сборка

```bash
go mod init mitremit
go build -o mitremit mitre-mitigates.go
```

## Использование

**Базовый пример (таблица):**
```bash
./mitremit -mitigation M1037
```

**JSON вывод:**
```bash
./mitremit -mitigation M1037 -json > output.json
```

**Поиск по названию:**
```bash
./mitremit -mitigation-name "Filter Network Traffic" -csv
```

**Генерация nGQL-запросов:**
```bash
./mitremit -mitigation M1037 -ngql > nebula_inserts.ngql
```

## Параметры командной строки

- `-mitigation` — идентификатор контрмеры ATT&CK (например, `M1037`)
- `-mitigation-name` — полное название контрмеры (регистронезависимый поиск)
- `-json` — вывод в формате JSON
- `-csv` — вывод в формате CSV
- `-ngql` — вывод INSERT-запросов для Nebula Graph
- `-debug` — дополнительная отладочная информация
- `-h` — справка

## Пример вывода (таблица)

```
MITIGATION       Filter Network Traffic (M1037)
----------------------------------------------------------------
TECHNIQUE ID     TECHNIQUE NAME
T1071            Application Layer Protocol
T1565            Data Manipulation
T1573            Encrypted Channel
```

## Технические детали

- Использует официальный STIX-бандл MITRE CTI
- Кэширует данные в директории `.mitre-cache/`
- Поддерживает как техники, так и под-техники
- Генерирует детерминированный вывод для удобства сравнения

## Лицензия

MIT (с)
