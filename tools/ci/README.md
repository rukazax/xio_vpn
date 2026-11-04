# CI для XIO

`ci.yml.template` — готовый workflow (jobs `flutter` и `server`). Он лежит здесь,
а не в `.github/workflows/`, потому что токен публикации без scope `workflow`
не может создавать файлы workflow (GitHub отклоняет push).

## Как включить

1. Скопировать `ci.yml.template` в `.github/workflows/ci.yml`.
2. Зарегистрировать self-hosted раннер на репозитории `rukazax/xio_vpn` с метками
   `self-hosted`, `Linux`, `X64`, `debian17` (сейчас работающие на хосте раннеры
   привязаны к другому репозиторию и носят метку устаревшего имени ранних сборок,
   поэтому workflow не подхватится).
3. Либо задать переменную репозитория `CI_RUNNER` с фактическими метками раннера —
   workflow возьмёт её через `vars.CI_RUNNER`.
4. Проверить baseline: `tools/ci/pytest-baseline.txt` (5 известных падений, с `--deselect`).

## Проверено

Синтаксис workflow (`yaml.safe_load`), `bash -n` всех shell-блоков, извлечение
`--deselect` из baseline, `release.py --dry-run/--verify-only` (см.
`docs/release-process.ru.md`). Реальный прогон CI не выполнялся — раннер к репозиторию не привязан.
