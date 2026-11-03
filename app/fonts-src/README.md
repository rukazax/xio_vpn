# Мастер-шрифт для сабсеттинга (в репозиторий не входит)

`app/assets/fonts/NotoSansCJKsc-Regular.otf` — сабсет, собранный `tools/subset-cjk-font.py`.
Полный мастер (16,4 МБ) в git не хранится: он нужен только для пересборки сабсета.

Скачать (Noto Sans CJK SC, Regular, OTF):

```sh
curl -L -o app/fonts-src/NotoSansCJKsc-Regular.otf \
  https://github.com/notofonts/noto-cjk/raw/main/Sans/OTF/SimplifiedChinese/NotoSansCJKsc-Regular.otf
```

Затем:

```sh
python tools/subset-cjk-font.py --master app/fonts-src/NotoSansCJKsc-Regular.otf \
    --out app/assets/fonts/NotoSansCJKsc-Regular.otf
python tools/subset-cjk-font.py --check
python tools/check-l10n.py      # пересобирает verification/l10n-catalogues-<version>.json
```

Сабсет детерминирован: два прогона дают один SHA-256.
