#!/usr/bin/env python3
"""Masa denetimi: hub/task-board.md ve hub/memory/interfaces.md.

Bu betik dosyanın içine gömülü DEĞİLDİR ve bu bilinçlidir. Gömülü betik
koşmaz, yalnız koşuyormuş gibi görünür; masanın Durum sütunu dört kez tam
olarak bu yüzden kaydı: sayı gözle sayıldı, kimse denetimi koşturmadı.

Koşumu:

    python3 scripts/audit-board.py            # iki dosyayı da denetler
    python3 scripts/audit-board.py --sessiz   # yalnız özet satırları

Çıkış kodu:
    0  biçimsiz satır yok, kural dışı durum yok
    1  en az bir biçimsiz satır veya kural dışı durum var

Açık satır sayısı çıkış kodunu ETKİLEMEZ: açık iş bir kusur değil, ölçülmesi
gereken bir sayıdır. Kusur, ölçülemeyen satırdır.
"""

import re
import sys
from pathlib import Path

KOK = Path(__file__).resolve().parent.parent

# --------------------------------------------------------------------------
# Masa (hub/task-board.md) kuralları
# --------------------------------------------------------------------------

# Kanonik sütun dizisi. Sıra normatiftir; tablodan tabloya değişmez.
MASA_BASLIK = ["ID", "Görev", "Sahip", "Durum", "Kilitli dosyalar", "Kanıt"]

# Kapalı durum kümesi. Beş değer, fazlası yok.
MASA_ACIK = {"beklemede", "çalışıyor", "bloke"}
MASA_KAPALI = {"tamam", "düştü"}
MASA_KUME = MASA_ACIK | MASA_KAPALI

# Not tablosunu görev tablosundan ayıran açık işaret. Sezgi kullanılmaz.
NOT_ISARETI = "<!-- not-tablosu -->"

# Görev kimliği kalıbı: F4-CON1, D-23/T1, CL4-KG1, FX-F2R/N-02 gibi.
# Not tablosunda bu kalıba uyan bir ilk hücre görülürse satır biçimsizdir:
# görev satırı, Durum sütunu olmayan bir tabloya yapışıp denetimden kaçamaz.
RE_GOREV_KIMLIGI = re.compile(r"^~*[A-ZÇĞİÖŞÜ][A-Za-z0-9]{0,6}([-/][A-Za-z0-9./-]+)+~*$")

# Kanıt kalıpları: dosya:satır, test yolu, commit hash'i.
RE_DOSYA_SATIR = re.compile(r"[\w./-]+\.\w+:\d+")
RE_TEST = re.compile(r"\w::\w")
RE_COMMIT = re.compile(r"\b[0-9a-f]{7,40}\b")
RE_DIPNOT_BAGI = re.compile(r"\[\^([^\]]+)\]")

# --------------------------------------------------------------------------
# Arayüz dosyası (hub/memory/interfaces.md) kuralları
# --------------------------------------------------------------------------

# Bu dosya talep taşır, görev değil; kendi normatif biçimi vardır ve beş
# sütunludur. Sütun adları iki varyantla yazılmış (Zaman/Tarih,
# Talep eden/Kim, İlgili sözleşme/Ne, İhtiyaç/Talep), anlam ve sıra aynı.
ARAYUZ_SUTUN = 5
ARAYUZ_ACIK = {"açık", "ertelendi"}
ARAYUZ_KAPALI = {"kapandı", "kod"}   # "kod fazına aktarıldı"
ARAYUZ_KUME = ARAYUZ_ACIK | ARAYUZ_KAPALI


def tr_kucult(s):
    """Türkçe duyarlı küçültme.

    Python'un lower() fonksiyonu 'KAPANDI' kelimesini 'kapandi' yapar ve
    büyük harfle yazılmış kapalı satırlar bu yüzden bir tur boyunca
    geçersiz göründü. I ve İ elle çevrilir."""
    return s.replace("I", "ı").replace("İ", "i").lower()


def hucrele(satir):
    """Boru satırını hücrelere ayırır. Kaçırılmış boru (\\|) bölmez."""
    t = satir.strip()
    if t.startswith("|"):
        t = t[1:]
    if t.endswith("|"):
        t = t[:-1]
    return [h.strip() for h in re.split(r"(?<!\\)\|", t)]


def ayrac_mi(satir):
    return bool(re.match(r"^\|[-\s|:]+\|?\s*$", satir.strip()))


def tablolari_bul(satirlar):
    """Tablo bloklarını çıkarır.

    Ters tırnaklı kod bloklarının içi atlanır: örnek tablo taşıyan bir kod
    bloğu denetime girmemelidir."""
    bloklar = []
    icinde_kod = False
    i = 0
    while i < len(satirlar):
        s = satirlar[i]
        if s.strip().startswith("```"):
            icinde_kod = not icinde_kod
            i += 1
            continue
        if icinde_kod or not s.startswith("|"):
            i += 1
            continue
        bas = i
        while i < len(satirlar) and satirlar[i].startswith("|"):
            i += 1
        # İşaret, tablonun hemen üstündeki boş olmayan satırdır.
        j = bas - 1
        while j >= 0 and satirlar[j].strip() == "":
            j -= 1
        isaretli = j >= 0 and satirlar[j].strip() == NOT_ISARETI
        bloklar.append((bas, i, isaretli))
    return bloklar


def kanit_var_mi(metin):
    """Kanıt hücresi gerçekten kaynağa götürüyor mu?

    '27 test var' gibi sayı beyanı kanıt değildir: doğrulayan kişiyi
    kaynağa götürmez. Kabul edilenler dosya:satır, test yolu, commit."""
    return bool(RE_DOSYA_SATIR.search(metin)
                or RE_TEST.search(metin)
                or RE_COMMIT.search(metin))


class Rapor:
    def __init__(self, ad):
        self.ad = ad
        self.acik = 0
        self.bicimsiz = 0
        self.kural_disi = 0
        self.kanitsiz_kapali = 0
        self.satir = 0
        self.bulgular = []

    def yaz(self, n, sinif, kimlik, aciklama=""):
        self.bulgular.append((n, sinif, kimlik, aciklama))


def masa_denetle(yol):
    r = Rapor(yol.name)
    satirlar = yol.read_text(encoding="utf-8").split("\n")
    bloklar = tablolari_bul(satirlar)

    dipnot_tanimlari = set()
    for s in satirlar:
        m = re.match(r"^\[\^([^\]]+)\]:", s)
        if m:
            dipnot_tanimlari.add(m.group(1))
    kullanilan_dipnotlar = set()

    for bas, son, isaretli in bloklar:
        veri = [(bas + k + 1, satirlar[bas + k])
                for k in range(son - bas) if not ayrac_mi(satirlar[bas + k])]
        if not veri:
            continue
        basliklar = hucrele(veri[0][1])

        if isaretli:
            # Not tablosu: sayılmaz. Tek kural, içine görev satırı
            # kaçmamasıdır. Bu, dördüncü nüksün doğrudan kilididir.
            for n, ham in veri[1:]:
                h = hucrele(ham)
                if h and RE_GOREV_KIMLIGI.match(h[0]):
                    r.bicimsiz += 1
                    r.yaz(n, "BİÇİMSİZ", h[0],
                          "görev kimliği not tablosunda; Durum sütunu yok")
            continue

        # İşaretsiz her tablo görev tablosudur ve başlığı kanonik olmalıdır.
        if basliklar != MASA_BASLIK:
            r.bicimsiz += 1
            r.yaz(veri[0][0], "BİÇİMSİZ BAŞLIK", "|".join(basliklar)[:60],
                  "beklenen: " + " | ".join(MASA_BASLIK))
            continue

        for n, ham in veri[1:]:
            h = hucrele(ham)
            r.satir += 1
            kimlik = h[0] if h else "?"

            if len(h) != 6:
                r.bicimsiz += 1
                r.acik += 1     # biçimsiz satır AÇIK sayılır
                r.yaz(n, "BİÇİMSİZ", kimlik, "%d sütun, 6 olmalı" % len(h))
                continue

            durum_ham = h[3]
            durum = tr_kucult(durum_ham.strip())

            if durum not in MASA_KUME:
                # Kural dışı durum hem sayılır hem açık kabul edilir.
                r.kural_disi += 1
                r.acik += 1
                r.yaz(n, "KURAL DIŞI DURUM", kimlik,
                      "%r kapalı kümede yok" % durum_ham[:40])
                continue

            for etiket in RE_DIPNOT_BAGI.findall(h[5]):
                kullanilan_dipnotlar.add(etiket)

            if durum in MASA_ACIK:
                r.acik += 1
                r.yaz(n, "AÇIK", kimlik, durum)
            elif durum == "tamam":
                if not kanit_var_mi(h[5]):
                    r.kanitsiz_kapali += 1
                    r.yaz(n, "KANITSIZ KAPALI", kimlik, "Kanıt: %s" % h[5][:40])
            elif durum == "düştü":
                # Gerekçesiz düşürme sessiz silmedir; gerekçe dipnotta durur.
                if not RE_DIPNOT_BAGI.search(h[5]):
                    r.bicimsiz += 1
                    r.yaz(n, "GEREKÇESİZ DÜŞTÜ", kimlik, "dipnot bağı yok")

    # Dipnot bütünlüğü: bağı olup tanımı olmayan not, kaybolmuş bilgidir.
    for etiket in sorted(kullanilan_dipnotlar - dipnot_tanimlari):
        r.bicimsiz += 1
        r.yaz(0, "KAYIP DİPNOT", etiket, "bağ var, tanım yok")

    return r


def arayuz_denetle(yol):
    """interfaces.md kendi normatif biçimine göre denetlenir.

    Bu dosya görev değil sözleşme talebi taşır; kendi dört değerlik kapalı
    kümesi ve beş sütunu vardır. Masayla aynı kalıp uygulanır: biçimsiz
    satır açık sayılır ve çıkış kodunu düşürür."""
    r = Rapor(yol.name)
    satirlar = yol.read_text(encoding="utf-8").split("\n")

    for bas, son, _ in tablolari_bul(satirlar):
        veri = [(bas + k + 1, satirlar[bas + k])
                for k in range(son - bas) if not ayrac_mi(satirlar[bas + k])]
        if len(veri) < 2:
            continue
        basliklar = hucrele(veri[0][1])
        if len(basliklar) != ARAYUZ_SUTUN:
            r.bicimsiz += 1
            r.yaz(veri[0][0], "BİÇİMSİZ BAŞLIK", "|".join(basliklar)[:60],
                  "%d sütun, %d olmalı" % (len(basliklar), ARAYUZ_SUTUN))
            continue

        for n, ham in veri[1:]:
            h = hucrele(ham)
            r.satir += 1
            kimlik = (h[1] if len(h) > 1 else h[0] if h else "?")[:36]

            if len(h) != ARAYUZ_SUTUN:
                r.bicimsiz += 1
                r.acik += 1
                r.yaz(n, "BİÇİMSİZ", kimlik,
                      "%d sütun, %d olmalı" % (len(h), ARAYUZ_SUTUN))
                continue

            d = tr_kucult(h[4].replace("*", "").strip())
            ilk = d.split()[0].rstrip(":,.()") if d.split() else ""

            if d.startswith("kısmen"):
                # 'kısmen kapandı' geçerli bir değer değildir ve açık sayılır.
                r.kural_disi += 1
                r.acik += 1
                r.yaz(n, "KURAL DIŞI DURUM", kimlik, "kısmen kapandı")
            elif ilk not in ARAYUZ_KUME:
                r.kural_disi += 1
                r.acik += 1
                r.yaz(n, "KURAL DIŞI DURUM", kimlik, "%r kapalı kümede yok" % ilk[:30])
            elif ilk in ARAYUZ_ACIK:
                r.acik += 1
                r.yaz(n, "AÇIK", kimlik, ilk)
            elif not kanit_var_mi(h[4]):
                r.kanitsiz_kapali += 1
                r.yaz(n, "KANITSIZ KAPALI", kimlik, ilk)

    return r


def bas(r, sessiz):
    print("=== %s ===" % r.ad)
    if not sessiz:
        for n, sinif, kimlik, aciklama in r.bulgular:
            if sinif == "AÇIK":
                continue
            yer = ("satır %d" % n) if n else "dosya sonu"
            print("  %-18s %-14s %s  (%s)" % (sinif, kimlik[:14], aciklama, yer))
    print("  denetlenen satır      : %d" % r.satir)
    print("  açık                  : %d" % r.acik)
    print("  biçimsiz              : %d" % r.bicimsiz)
    print("  kural dışı durum      : %d" % r.kural_disi)
    print("  kanıtsız kapalı (borç): %d" % r.kanitsiz_kapali)
    print()


def main():
    sessiz = "--sessiz" in sys.argv

    masa = KOK / "hub" / "task-board.md"
    arayuz = KOK / "hub" / "memory" / "interfaces.md"

    # `hub/` yayımlanan ağaçta yoktur ve olmaması normaldir: `.gitignore` onu
    # bilerek dışarıda tutuyor. Bu betik bu yüzden bir CI kapısı değil, yerel bir
    # araçtır ve öyle davranması gerekir. Traceback ile düşmek yanlış sinyaldi;
    # bir kapı sanılıp CI'a bağlanırsa da denetleyecek dosya bulamaz ve sessizce
    # geçerdi, ki CLAUDE.md O6b tam olarak onu yasaklıyor.
    eksik = [yol for yol in (masa, arayuz) if not yol.exists()]
    if eksik:
        if not (KOK / "hub").exists():
            print("hub/ yok: bu yayımlanan bir ağaç, denetlenecek kayıt taşımıyor.")
            print("Bu betik depo çalışma kopyasında koşar; CI kapısı değildir.")
            return 2
        for yol in eksik:
            print("EKSİK: %s bulunamadı, ama hub/ duruyor." % yol.relative_to(KOK))
        print("DENETİM DÜŞTÜ: hub/ var ve kayıt dosyası yok, yani dosya taşınmış.")
        return 1

    raporlar = [
        masa_denetle(masa),
        arayuz_denetle(arayuz),
    ]
    for r in raporlar:
        bas(r, sessiz)

    acik = sum(r.acik for r in raporlar)
    bicimsiz = sum(r.bicimsiz for r in raporlar)
    kural_disi = sum(r.kural_disi for r in raporlar)
    borc = sum(r.kanitsiz_kapali for r in raporlar)

    print("--- TOPLAM: açık %d | biçimsiz %d | kural dışı durum %d | "
          "kanıtsız kapalı %d" % (acik, bicimsiz, kural_disi, borc))

    if bicimsiz or kural_disi:
        print("DENETİM DÜŞTÜ: biçimsiz satır ve kural dışı durum sıfır olmalı.")
        return 1
    print("DENETİM GEÇTİ.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
