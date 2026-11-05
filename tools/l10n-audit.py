#!/usr/bin/env python3
"""Offline audit of the bundled catalogues for machine-translation damage.

Every catalogue is keyed by the Russian source string, so a value can be
checked against its key directly.  The audit looks for the defects that a
run-of-the-mill MT pass leaves behind:

1. **Toponyms / proper names** where the UI needs a plain word: a country or
   city name in a status cell ("Timor-Leste" for «Передано»).
2. **Foreign script**: Cyrillic left in a translated cell, Hangul in Chinese,
   Arabic in Hindi, and so on.
3. **Unmotivated Latin runs** inside Chinese, Japanese, Korean, Arabic or
   Hindi text: Latin is fine for product names (WireGuard, SSH, VPN, …) and
   for tokens that also occur in the key, but a bare Latin word that matches
   neither is almost always a transliteration ("リセビード", "सेंट").
4. **Transliteration instead of translation**: the value is the English or
   Russian word written in the target script, with no target-language stem.
5. **Lost lexical link**: for short labels the value shares no stem with the
   key at all (the case the reviewer asked to flag for manual reading).
6. **Morphological outliers**: a state cell rendered as a noun (or a country)
   while its siblings are participles — approximated by requiring the
   curated state rows to match a per-language pattern.
7. **Structural damage**: untranslated cells, placeholders, duplicates.

The script is intentionally dependency-free; it exits 1 on hard findings and
0 when the catalogues are clean.  It is *not* a substitute for a native
speaker: category 5 is a review list, printed but not fatal.
"""
from __future__ import annotations

import json
import re
import sys
import unicodedata
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FOLDER = ROOT / "app/assets/l10n"
CODES = "ru en de es fr it pt zh ja ko tr hi ar".split()
# Locales this task owns: Russian is the source, English is reference.
TARGETS = [c for c in CODES if c not in {"ru", "en"}]
NON_LATIN = {"zh", "ja", "ko", "ar", "hi"}
LATIN_TARGETS = {"en", "de", "es", "fr", "it", "pt", "tr"}

# ---------------------------------------------------------------------------
# 1. Words that never belong in this UI.
# ---------------------------------------------------------------------------
# Country / region / city names in the languages of the catalogue set.  A
# translation may mention a country only in a sentence that explains routing;
# none of the 744 rows does, so any hit is a defect.
TOPONYMS = {
    # English / Latin
    "timor", "leste", "east timor", "timor-leste", "indonesia", "australia",
    "germany", "deutschland", "france", "spain", "españa", "italy", "italia",
    "portugal", "turkey", "türkiye", "turkiye", "india", "china", "japan",
    "korea", "russia", "estonia", "latvia", "lithuania", "poland", "polska",
    "ukraine", "belarus", "finland", "sweden", "norway", "denmark", "greece",
    "egypt", "iraq", "iran", "israel", "saudi", "qatar", "emirates", "oman",
    "yemen", "lebanon", "syria", "morocco", "algeria", "tunisia",
    "libya", "sudan", "kenya", "nigeria", "brazil", "brasil", "mexico",
    "méxico", "argentina", "peru", "colombia", "canada", "america",
    "united states", "britain", "england", "london", "paris", "berlin",
    "madrid", "rome", "lisbon", "moscow", "beijing", "tokyo", "seoul",
    "delhi", "cairo", "istanbul", "ankara", "kiev", "kyiv", "minsk",
    "tallinn", "vilnius", "warsaw", "helsinki", "stockholm", "oslo",
    "copenhagen", "athens", "amsterdam", "brussels", "vienna", "prague",
    "budapest", "bucharest", "sofia", "zagreb", "belgrade", "sarajevo",
    # Chinese
    "东帝汶", "帝汶", "印度尼西亚", "澳大利亚", "德国", "法国", "西班牙",
    "意大利", "葡萄牙", "土耳其", "印度", "中国", "日本", "韩国", "俄罗斯",
    "爱沙尼亚", "拉脱维亚", "立陶宛", "波兰", "乌克兰", "白俄罗斯",
    "芬兰", "瑞典", "挪威", "丹麦", "希腊", "埃及", "伊拉克", "伊朗",
    "以色列", "沙特", "卡塔尔", "阿联酋", "也门", "约旦", "黎巴嫩",
    "叙利亚", "摩洛哥", "阿尔及利亚", "突尼斯", "利比亚", "苏丹",
    "肯尼亚", "尼日利亚", "巴西", "墨西哥", "阿根廷", "智利", "秘鲁",
    "哥伦比亚", "加拿大", "美国", "英国", "伦敦", "巴黎", "柏林",
    "马德里", "罗马", "里斯本", "莫斯科", "北京", "东京", "首尔", "德里",
    "开罗", "伊斯坦布尔", "安卡拉", "基辅", "明斯克", "塔林", "里加",
    "维尔纽斯", "华沙", "赫尔辛基", "斯德哥尔摩", "奥斯陆", "哥本哈根",
    "雅典", "阿姆斯特丹", "布鲁塞尔", "维也纳", "布拉格", "布达佩斯",
    "布加勒斯特", "索非亚", "萨格勒布", "贝尔格莱德", "萨拉热窝",
    # Japanese
    "東ティモール", "ティモール", "インドネシア", "オーストラリア", "ドイツ",
    "フランス", "スペイン", "イタリア", "ポルトガル", "トルコ", "インド",
    "中国", "日本", "韓国", "ロシア", "エストニア", "ラトビア",
    "リトアニア", "ポーランド", "ウクライナ", "ベラルーシ", "フィンランド",
    "スウェーデン", "ノルウェー", "デンマーク", "ギリシャ", "エジプト",
    "イラク", "イラン", "イスラエル", "サウジ", "カタール", "アラブ首長国",
    "イエメン", "ヨルダン", "レバノン", "シリア", "モロッコ",
    "アルジェリア", "チュニジア", "リビア", "スーダン", "ケニア",
    "ナイジェリア", "ブラジル", "メキシコ", "アルゼンチン", "チリ",
    "ペルー", "コロンビア", "カナダ", "アメリカ", "イギリス", "ロンドン",
    "パリ", "ベルリン", "マドリード", "ローマ", "リスボン", "モスクワ",
    "北京", "東京", "ソウル", "デリー", "カイロ", "イスタンブール",
    "アンカラ", "キーウ", "ミンスク", "タリン", "リガ", "ビリニュス",
    "ワルシャワ", "ヘルシンキ", "ストックホルム", "オスロ",
    "コペンハーゲン", "アテネ", "アムステルダム", "ブリュッセル",
    "ウィーン", "プラハ", "ブダペスト", "ブカレスト", "ソフィア",
    "ザグレブ", "ベオグラード", "サラエボ",
    # Korean
    "동티모르", "티모르", "인도네시아", "호주", "독일", "프랑스", "스페인",
    "이탈리아", "포르투갈", "터키", "인도", "중국", "일본", "한국",
    "러시아", "에스토니아", "라트비아", "리투아니아", "폴란드",
    "우크라이나", "벨라루스", "핀란드", "스웨덴", "노르웨이", "덴마크",
    "그리스", "이집트", "이라크", "이란", "이스라엘", "사우디", "카타르",
    "아랍에미리트", "예멘", "요르단", "레바논", "시리아", "모로코",
    "알제리", "튀니지", "리비아", "수단", "케냐", "나이지리아",
    "브라질", "멕시코", "아르헨티나", "칠레", "페루", "콜롬비아",
    "캐나다", "미국", "영국", "런던", "파리", "베를린", "마드리드",
    "로마", "리스본", "모스크바", "베이징", "도쿄", "서울", "델리",
    "카이로", "이스탄불", "앙카라", "키이우", "민스크", "탈린", "리가",
    "빌뉴스", "바르샤바", "헬싱키", "스톡홀름", "오슬로", "코펜하겐",
    "아테네", "암스테르담", "브뤼셀", "비엔나", "프라하", "부다페스트",
    "부쿠레슈티", "소피아", "자그레브", "베오그라드", "사라예보",
    # Arabic
    "تيمور", "إندونيسيا", "أستراليا", "ألمانيا", "فرنسا", "إسبانيا",
    "إيطاليا", "البرتغال", "تركيا", "الهند", "الصين", "اليابان",
    "كوريا", "روسيا", "إستونيا", "لاتفيا", "ليتوانيا", "بولندا",
    "أوكرانيا", "بيلاروسيا", "فنلندا", "السويد", "النرويج", "الدنمارك",
    "اليونان", "مصر", "العراق", "إيران", "إسرائيل", "السعودية", "قطر",
    "الإمارات", "اليمن", "الأردن", "لبنان", "سوريا", "المغرب",
    "الجزائر", "تونس", "ليبيا", "السودان", "كينيا", "نيجيريا",
    "البرازيل", "المكسيك", "الأرجنتين", "تشيلي", "بيرو", "كولومبيا",
    "كندا", "أمريكا", "بريطانيا", "لندن", "باريس", "برلين", "مدريد",
    "روما", "لشبونة", "موسكو", "بكين", "طوكيو", "سيول", "دلهي",
    "القاهرة", "اسطنبول", "أنقرة", "كييف", "مينسك", "تالين", "ريغا",
    "فيلنيوس", "وارسو", "هلسنكي", "ستوكهولم", "أوسلو", "كوبنهاغن",
    "أثينا", "أمستردام", "بروكسل", "فيينا", "براغ", "بودابست",
    "بوخارست", "صوفيا", "زغرب", "بلغراد", "سراييفو",
    # Hindi
    "तिमोर", "इंडोनेशिया", "ऑस्ट्रेलिया", "जर्मनी", "फ्रांस", "स्पेन",
    "इटली", "पुर्तगाल", "तुर्की", "भारत", "चीन", "जापान", "कोरिया",
    "रूस", "एस्टोनिया", "लातविया", "लिथुआनिया", "पोलैंड", "यूक्रेन",
    "बेलारूस", "फ़िनलैंड", "स्वीडन", "नॉर्वे", "डेनमार्क", "ग्रीस",
    "मिस्र", "इराक", "ईरान", "इज़राइल", "सऊदी", "कतर", "अमीरात",
    "यमन", "जॉर्डन", "लेबनान", "सीरिया", "मोरक्को", "अल्जीरिया",
    "ट्यूनीशिया", "लीबिया", "सूडान", "केन्या", "नाइजीरिया",
    "ब्राज़ील", "मेक्सिको", "अर्जेंटीना", "चिली", "पेरू", "कोलंबिया",
    "कनाडा", "अमेरिका", "ब्रिटेन", "लंदन", "पेरिस", "बर्लिन",
    "मैड्रिड", "रोम", "लिस्बन", "मास्को", "बीजिंग", "टोक्यो", "सियोल",
    "दिल्ली", "काहिरा", "इस्तांबुल", "अंकारा", "कीव", "मिन्स्क",
    "तालिन", "रिगा", "विल्नियस", "वारसॉ", "हेलसिंकी", "स्टॉकहोम",
    "ओस्लो", "कोपेनहेगन", "एथेंस", "एम्स्टर्डम", "ब्रुसेल्स",
    "वियना", "प्राग", "बुडापेस्ट", "बुखारेस्ट", "सोफिया", "ज़ाग्रेब",
    "बेलग्रेड", "साराजेवो",
}
# Substring forms that are safe to match inside a sentence (word boundaries
# are unusable for scripts without spaces).
TOPONYM_SUBSTRINGS = {
    "Timor", "Leste", "东帝汶", "ティモール", "동티모르", "تيمور",
    "तिमोर",
}

# Product names and technical tokens that are *expected* in Latin script even
# inside Chinese, Japanese, Korean, Arabic and Hindi text.
LATIN_ALLOW = {
    "xio", "vpn", "wireguard", "amneziawg", "amnezia", "tailscale", "headscale",
    "ssh", "sshd", "mtproto", "udp", "tcp", "quic", "tls", "websocket", "http",
    "https", "dns", "ip", "ipv4", "ipv6", "cidr", "sha256", "sha", "base64",
    "pem", "openssh", "android", "ubuntu", "windows", "linux", "ios", "vps",
    "conf", "json", "yaml", "api", "url", "id", "uid", "mtu", "jmin", "jmax",
    "postup", "predown", "endpoint", "address", "allowedips", "interface",
    "peer", "privatekey", "publickey", "presharedkey", "listenport", "mtproto",
    "connect", "udp", "cdn", "sni", "exit", "node", "mesh", "nat", "keystore",
    "google", "cloudflare", "github", "docker", "nginx", "systemd", "sudo",
    "root", "pem", "ocserv", "xray", "vless", "vmess", "trojan", "shadowsocks",
    "reality", "hysteria", "sing-box", "singbox", "naive", "tor", "socks",
    "socks5", "http2", "http3", "icmp", "rtt", "bgp", "asn", "cidr", "ttl",
    "getrandom", "token", "redirect", "proxytv", "app", "web", "os", "pc",
    "mac", "macos", "sim", "sms", "qr", "gui", "cli", "sdk", "jni", "go",
    "golang", "rust", "kotlin", "dart", "flutter", "java", "gradle", "npm",
    "pwa", "ipv6", "ipv4", "tun", "tap", "wg", "awg", "mtu", "keepalive",
    "rekey", "handshake", "psk", "pk", "hex", "utf", "xml", "csv", "sha1",
    "md5", "base32", "epoch", "unix", "tty", "pty", "cron", "daemon",
    "kernel", "netns", "iptables", "nftables", "systemctl", "journalctl", "cloak",
    "var", "log", "opt", "etc", "usr", "bin", "dev", "proc", "sys", "tmp",
}

# Curated expected values for the status rows: a translator must use a
# participle (or the idiomatic noun) of the target language, never a country
# name and never a Russian/English transliteration.
STATE_KEYS = [
    "ПОЛУЧЕНО",
    "ПЕРЕДАНО",
    "ДОСТУПЕН",
    "В РАЗРАБОТКЕ",
    "ПРОТОКОЛ",
]
# Values that are intentionally identical in every language: units follow
# international notation («B», «kB», «MB», «s», «ms»), so a bare unit cell is
# not a missing translation.
UNIT_KEYS = {"{0} Б", "{0} КБ", "{0} МБ", "{0} с", "{0} мс", "{0} GB"}
STATE_EXPECTED = {
    "de": {
        "ПОЛУЧЕНО": {"EMPFANGEN"},
        "ПЕРЕДАНО": {"GESENDET", "ÜBERTRAGEN"},
        "ДОСТУПЕН": {"VERFÜGBAR"},
        "В РАЗРАБОТКЕ": {"IN ENTWICKLUNG"},
        "ПРОТОКОЛ": {"PROTOKOLL", "PROTOKOL"},
    },
    "es": {
        "ПОЛУЧЕНО": {"RECIBIDO"},
        "ПЕРЕДАНО": {"ENVIADO"},
        "ДОСТУПЕН": {"DISPONIBLE"},
        "В РАЗРАБОТКЕ": {"EN DESARROLLO"},
        "ПРОТОКОЛ": {"PROTOCOLO"},
    },
    "fr": {
        "ПОЛУЧЕНО": {"REÇU", "RECU"},
        "ПЕРЕДАНО": {"ENVOYÉ", "ENVOYE"},
        "ДОСТУПЕН": {"DISPONIBLE"},
        "В РАЗРАБОТКЕ": {"EN DÉVELOPPEMENT", "EN DEVELOPPEMENT"},
        "ПРОТОКОЛ": {"PROTOCOLE"},
    },
    "it": {
        "ПОЛУЧЕНО": {"RICEVUTO"},
        "ПЕРЕДАНО": {"INVIATO"},
        "ДОСТУПЕН": {"DISPONIBILE"},
        "В РАЗРАБОТКЕ": {"IN SVILUPPO"},
        "ПРОТОКОЛ": {"PROTOCOLLO"},
    },
    "pt": {
        "ПОЛУЧЕНО": {"RECEBIDO"},
        "ПЕРЕДАНО": {"ENVIADO"},
        "ДОСТУПЕН": {"DISPONÍVEL", "DISPONIVEL"},
        "В РАЗРАБОТКЕ": {"EM DESENVOLVIMENTO"},
        "ПРОТОКОЛ": {"PROTOCOLO"},
    },
    "zh": {
        "ПОЛУЧЕНО": {"收到", "已接收", "接收"},
        "ПЕРЕДАНО": {"已发送", "发送"},
        "ДОСТУПЕН": {"可用", "可用"},
        "В РАЗРАБОТКЕ": {"开发中"},
        "ПРОТОКОЛ": {"协议"},
    },
    "ja": {
        "ПОЛУЧЕНО": {"受信", "受信済み"},
        "ПЕРЕДАНО": {"送信", "送信済み"},
        "ДОСТУПЕН": {"利用可能", "使用可能", "可能"},
        "В РАЗРАБОТКЕ": {"開発中"},
        "ПРОТОКОЛ": {"プロトコル"},
    },
    "ko": {
        "ПОЛУЧЕНО": {"수신", "수신됨"},
        "ПЕРЕДАНО": {"송신", "송신됨"},
        "ДОСТУПЕН": {"사용 가능"},
        "В РАЗРАБОТКЕ": {"개발 중"},
        "ПРОТОКОЛ": {"프로토콜"},
    },
    "tr": {
        "ПОЛУЧЕНО": {"ALINAN", "ALINDI"},
        "ПЕРЕДАНО": {"GÖNDERİLEN", "GÖNDERİLDİ"},
        "ДОСТУПЕН": {"KULLANILABİLİR", "MEVCUT"},
        "В РАЗРАБОТКЕ": {"GELİŞTİRİLİYOR"},
        "ПРОТОКОЛ": {"PROTOKOL"},
    },
    "hi": {
        "ПОЛУЧЕНО": {"प्राप्त"},
        "ПЕРЕДАНО": {"भेजा गया", "प्रेषित"},
        "ДОСТУПЕН": {"उपलब्ध"},
        "В РАЗРАБОТКЕ": {"विकास में"},
        "ПРОТОКОЛ": {"प्रोटोकॉल"},
    },
    "ar": {
        "ПОЛУЧЕНО": {"المستلم", "تم الاستلام", "مستلم"},
        "ПЕРЕДАНО": {"المرسل", "تم الإرسال", "مرسل"},
        "ДОСТУПЕН": {"متاح"},
        "В РАЗРАБОТКЕ": {"قيد التطوير"},
        "ПРОТОКОЛ": {"البروتوكول", "بروتوكول"},
    },
}

# A whole-cell language fingerprint was tried and dropped: Spanish, Portuguese
# and Italian share too many function words to separate reliably, so every hit
# was a false positive.  The script, toponym and status-cell rules below catch
# the real damage.

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
CYRILLIC = re.compile(r"[\u0400-\u04FF]")
HAN = re.compile(r"[\u3400-\u4DBF\u4E00-\u9FFF\uF900-\uFAFF]")
KANA = re.compile(r"[\u3040-\u30FF]")
HANGUL = re.compile(r"[\u1100-\u11FF\u3130-\u318F\uAC00-\uD7AF]")
ARABIC = re.compile(r"[\u0600-\u06FF\u0750-\u077F\u08A0-\u08FF\uFB50-\uFDFF\uFE70-\uFEFF]")
DEVANAGARI = re.compile(r"[\u0900-\u097F]")
LATIN = re.compile(r"[A-Za-z]")
PLACEHOLDER = re.compile(r"\{\d+\}")
WORD = re.compile(r"[^\W\d_]+", re.UNICODE)

# Cyrillic → Latin, close enough to catch transliterations ("Получено" →
# "polucheno" vs. Spanish "recibido": no shared stem).
_TRANSLIT = {
    "а": "a", "б": "b", "в": "v", "г": "g", "д": "d", "е": "e", "ё": "e",
    "ж": "zh", "з": "z", "и": "i", "й": "i", "к": "k", "л": "l", "м": "m",
    "н": "n", "о": "o", "п": "p", "р": "r", "с": "s", "т": "t", "у": "u",
    "ф": "f", "х": "h", "ц": "ts", "ч": "ch", "ш": "sh", "щ": "sch",
    "ъ": "", "ы": "y", "ь": "", "э": "e", "ю": "yu", "я": "ya",
}


def translit(text: str) -> str:
    return "".join(_TRANSLIT.get(ch.lower(), ch) for ch in text)


def stem(word: str) -> str:
    word = word.lower()
    for suffix in ("ing", "ed", "es", "s", "en", "er", "e"):
        if len(word) > 5 and word.endswith(suffix):
            word = word[: -len(suffix)]
            break
    return word[:6]


def letter_scripts(text: str) -> set[str]:
    found = set()
    for ch in text:
        if HAN.match(ch):
            found.add("han")
        elif KANA.match(ch):
            found.add("kana")
        elif HANGUL.match(ch):
            found.add("hangul")
        elif ARABIC.match(ch):
            found.add("arabic")
        elif DEVANAGARI.match(ch):
            found.add("devanagari")
        elif CYRILLIC.match(ch):
            found.add("cyrillic")
        elif LATIN.match(ch):
            found.add("latin")
    return found


def latin_runs(text: str) -> list[str]:
    # A URL is a literal, not a translated word: `https://your-server` keeps
    # its Latin host in every catalogue by design.
    text = re.sub(r"\b[A-Za-z][A-Za-z0-9+.-]*://\S+", " ", text)
    return re.findall(r"[A-Za-z][A-Za-z0-9_.\-]*", text)


def load() -> dict[str, dict[str, str]]:
    return {
        code: json.loads((FOLDER / f"{code}.json").read_text(encoding="utf-8"))
        for code in CODES
    }


def audit(catalogues: dict[str, dict[str, str]]) -> list[dict]:
    source = catalogues["ru"]
    english = catalogues["en"]
    findings: list[dict] = []

    def add(severity, code, key, value, rule, note):
        findings.append(
            {
                "severity": severity,
                "language": code,
                "key": key,
                "value": value,
                "rule": rule,
                "note": note,
            }
        )

    for code in CODES:
        catalogue = catalogues[code]
        if code != "ru":
            if catalogue.keys() != source.keys():
                add("error", code, "*", "", "structure",
                    "key set differs from ru.json")
                continue
        for key, value in catalogue.items():
            if code == "ru":
                continue
            expected_placeholders = sorted(PLACEHOLDER.findall(key))
            actual_placeholders = sorted(PLACEHOLDER.findall(value))
            if expected_placeholders != actual_placeholders:
                add("error", code, key, value, "placeholder",
                    f"expected {expected_placeholders}, got {actual_placeholders}")
            if not value.strip():
                add("error", code, key, value, "empty", "empty translation")
                continue
            if value == key:
                add("error", code, key, value, "untranslated",
                    "value equals the Russian key")
                continue
            # A value identical to English is *not* reported here: the Flutter
            # test owns that rule (units, version banners and cognates are
            # legitimate), so duplicating it with a second allowlist would only
            # produce noise.
            if CYRILLIC.search(value):
                add("error", code, key, value, "cyrillic",
                    "Cyrillic left in a translated cell")

            # 1. toponyms
            for name in TOPONYMS:
                if name.isascii():
                    if re.search(rf"(?<![^\W_]){re.escape(name)}(?![^\W_])",
                                 value, re.IGNORECASE):
                        add("error", code, key, value, "toponym", f"«{name}»")
                elif name in value:
                    add("error", code, key, value, "toponym", f"«{name}»")
            for name in TOPONYM_SUBSTRINGS:
                if name in value:
                    add("error", code, key, value, "toponym", f"«{name}»")

            # 2. script sanity
            scripts = letter_scripts(value)
            # Product names may carry a suffix («youtube.com», «Telegram-»);
            # compare the bare stem so a legitimately kept name is not reported.
            key_latin = {
                part.lower().strip(".-_,;:。、")
                for token in latin_runs(key)
                for part in token.split(".")
                if part
            }
            if code in NON_LATIN:
                target_script = {
                    "zh": {"han", "kana"},
                    "ja": {"han", "kana"},
                    "ko": {"hangul", "han"},
                    "ar": {"arabic"},
                    "hi": {"devanagari"},
                }[code]
                if not (scripts & target_script) and key not in UNIT_KEYS:
                    add("error", code, key, value, "script",
                        f"no {sorted(target_script)} letter in the value")
                foreign = scripts - target_script - {"latin"}
                if foreign:
                    add("error", code, key, value, "script",
                        f"foreign script(s) {sorted(foreign)}")
                if code == "zh" and "hangul" in scripts:
                    add("error", code, key, value, "script", "Hangul in Chinese")
                if code == "ko" and "hangul" not in scripts and key not in UNIT_KEYS:
                    add("error", code, key, value, "script", "no Hangul")
                if (code == "ja" and "kana" not in scripts and "han" not in scripts
                        and key not in UNIT_KEYS):
                    add("error", code, key, value, "script", "not Japanese")
                # 3. unmotivated Latin runs
                key_latin = {t.lower() for t in latin_runs(key)}
                value_latin = latin_runs(value)
                english_latin = {t.lower() for t in latin_runs(english[key])}
                for token in value_latin:
                    low = token.lower().strip(".-_,;:")
                    if not low or low in LATIN_ALLOW:
                        continue
                    if low in key_latin or low in english_latin:
                        continue
                    if re.fullmatch(r"[0-9.]+", token):
                        continue
                    add("warning", code, key, value, "latin-run",
                        f"«{token}» is not in the key, English cell or allowlist")

            # 4/5. lexical link between key and value
            key_words = [w for w in WORD.findall(key) if len(w) >= 4]
            value_words = [w for w in WORD.findall(value) if len(w) >= 4]
            key_stems = {stem(w) for w in key_words}
            key_stems |= {stem(translit(w)) for w in key_words}
            value_stems = {stem(w) for w in value_words}
            latin_key = {t.lower() for t in latin_runs(key)}
            latin_value = {t.lower() for t in latin_runs(value)}
            overlap = (key_stems & value_stems) | (latin_key & latin_value)
            # Short labels in a Latin-script language must keep a recognisable
            # stem; CJK/Arabic/Devanagari have no shared alphabet, so they are
            # covered by the script and status-cell checks instead.
            if (code in LATIN_TARGETS and key_words and not overlap
                    and len(key_words) <= 4):
                add("review", code, key, value, "no-lexical-link",
                    "no stem shared with the key; read it by hand")
            # A bare transliteration: the value is Latin-only script for a
            # non-Latin target, or it contains the transliterated key.
            if code in NON_LATIN and scripts == {"latin", "cyrillic"}:
                add("error", code, key, value, "transliteration",
                    "Latin-only value in a non-Latin catalogue")
            # Only Cyrillic words are transliterated: Latin product names in
            # the key («WireGuard», «install») must not look like a
            # transliteration of themselves.
            transl = " ".join(
                translit(w) for w in WORD.findall(key) if CYRILLIC.search(w)
            ).lower()
            # Internationalisms («сервер» → «Server», «туннель» → «Tunnel»)
            # also appear in the English cell and are not transliterations.
            english_words = {w.lower() for w in WORD.findall(english[key])}
            for w in (value_words if code in NON_LATIN else []):
                wl = w.lower().strip(".-_,;:。、")
                if (len(w) >= 6 and wl in transl and wl not in key_latin
                        and wl not in english_words):
                    add("warning", code, key, value, "transliteration",
                        f"«{w}» is the Russian word in Latin letters")

            # 4b. (removed) whole-cell language detection: Spanish, Portuguese
            # and Italian share too many function words to separate reliably,
            # so the check produced only false positives; the script, toponym
            # and status-cell rules cover the real damage.

            # 6. curated status rows
            if key in STATE_EXPECTED.get(code, {}):
                allowed = STATE_EXPECTED[code][key]
                if value.strip() not in allowed:
                    add("error", code, key, value, "status-cell",
                        f"expected one of {sorted(allowed)}")

        # 7. duplicates inside one catalogue (different keys, same value)
        seen: dict[str, str] = {}
        for key, value in catalogue.items():
            if code == "ru" or len(value) < 4:
                continue
            if value in seen:
                add("review", code, key, value, "duplicate",
                    f"same value as «{seen[value]}»")
            else:
                seen[value] = key

    return findings


def report(findings: list[dict], out: Path | None = None) -> int:
    order = {"error": 0, "warning": 1, "review": 2}
    findings = sorted(
        findings,
        key=lambda f: (order[f["severity"]], f["language"], f["rule"], f["key"]),
    )
    counts = {s: sum(1 for f in findings if f["severity"] == s)
              for s in order}
    for f in findings:
        print(
            f"{f['severity']:7} {f['language']:2} [{f['rule']:15}] "
            f"«{f['key']}» → «{f['value']}»  {f['note']}"
        )
    print(
        f"\n{counts['error']} errors, {counts['warning']} warnings, "
        f"{counts['review']} rows for manual review "
        f"({len(findings)} findings over {len(CODES)} catalogues)"
    )
    if out is not None:
        out.write_text(
            json.dumps(findings, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        print(f"wrote {out}")
    return 1 if counts["error"] else 0


def main(argv: list[str]) -> int:
    out = None
    if "--json" in argv:
        out = Path(argv[argv.index("--json") + 1])
    catalogues = load()
    return report(audit(catalogues), out)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
