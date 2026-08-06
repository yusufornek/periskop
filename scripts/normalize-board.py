#!/usr/bin/env python3
"""Tek seferlik göç: hub/task-board.md tablolarını tek biçime indirir.

Neden betik: masa 167 KB ve 264 görev satırı taşıyor; satırların çoğunun Durum
hücresinde 200 ila 2000 karakterlik gerekçe metni duruyor. Bu metni elle
taşımak, taşınan her satırda bilgi kaybı riski demektir. Görevin birinci
kuralı "hiçbir bilgi kaybolmasın, satır silme" olduğu için dönüşüm
determinist bir betikle yapılır ve betik depoda kalır: ne yapıldığı
okunabilir, gerekirse geri sarılabilir.

Betik iki şey üretir:
  1. Her görev tablosu için tek ve aynı sütun dizisi.
  2. Hücreye sığmayan metin için dosya sonunda dipnot bölümü.

Bir kez koşar. Sonuç `scripts/audit-board.py` ile denetlenir.
"""

import re
import sys
import unicodedata
from pathlib import Path

KOK = Path(__file__).resolve().parent.parent
MASA = KOK / "hub" / "task-board.md"
ARAYUZ = KOK / "hub" / "memory" / "interfaces.md"

# Kanonik görev tablosu sütunları. Sıra normatiftir, değişmez.
KANONIK = ["ID", "Görev", "Sahip", "Durum", "Kilitli dosyalar", "Kanıt"]

# Not tablolarını denetimden ayıran işaret. Sezgiye bırakılmaz: dördüncü
# nüksün sebebi, bir görev satırının başlıksız tabloya yapışıp denetime
# hiç girmemesiydi. İşaret açıkça yazılır.
NOT_ISARETI = "<!-- not-tablosu -->"

# Kapalı durum kümesi. Beşten fazlası yok.
DURUMLAR = ("beklemede", "çalışıyor", "tamam", "düştü", "bloke")

# Eski dokuz değerin yenisine eşlemesi. Açık/kapalı anlamı korunur.
ESLEME = {
    "beklemede": "beklemede",
    "açık": "beklemede",
    "atandı": "beklemede",
    "çalışıyor": "çalışıyor",
    "inceleme": "çalışıyor",
    "izleniyor": "çalışıyor",
    "kısmen": "çalışıyor",
    "bloke": "bloke",
    "tamam": "tamam",
    "kapandı": "tamam",
    "düştü": "düştü",
    "bölündü": "düştü",
}

# Başlık adlarının kanonik sütuna eşlemesi. Sıfırıncı sütun her zaman ID'dir,
# adı ne olursa olsun (ID, Dalga, Kriter hepsi kimlik taşıyor).
GOREV_ADLARI = {"görev", "bulgu", "iş", "boşluk", "çelişki", "ölçüm",
                "neden ölçülemiyor", "neden kalktı"}
SAHIP_ADLARI = {"sahip", "kim ölçer"}
KILIT_ADLARI = {"kilitli dosyalar"}
KANIT_ADLARI = {"kanıt", "dosya:satır"}

# Kanıt kalıpları: dosya:satır, test yolu, commit hash'i.
RE_TIK = re.compile(r"`([^`]+)`")
RE_DOSYA_SATIR = re.compile(r"[\w./-]+\.\w+:\d+")
RE_TEST = re.compile(r"\w::\w")
RE_COMMIT = re.compile(r"^[0-9a-f]{7,40}$")


def tr_kucult(s):
    """Türkçe duyarlı küçültme. Python'un lower()'ı 'KAPANDI'yı 'kapandi'
    yapar; büyük harfle yazılmış kapalı satırlar bu yüzden bir tur boyunca
    geçersiz göründü. I/İ elle çevrilir."""
    return s.replace("I", "ı").replace("İ", "i").lower()


def tik_koru(satir):
    """Ters tırnak içindeki kaçırılmamış boru işaretlerini kaçırır.

    `dedup_by(|a, b| ...)` gibi bir kapanış, hücreyi üçe böler ve satırı
    biçimsiz yapar. Bölmeden önce onarılır."""
    parcalar = satir.split("`")
    # tek indisli parçalar ters tırnak içi
    for i in range(1, len(parcalar), 2):
        parcalar[i] = re.sub(r"(?<!\\)\|", r"\\|", parcalar[i])
    return "`".join(parcalar)


def hucrele(satir):
    """Boru satırını hücrelere ayırır. Kaçırılmış boru bölmez."""
    s = tik_koru(satir.strip())
    if s.startswith("|"):
        s = s[1:]
    if s.endswith("|"):
        s = s[:-1]
    return [h.strip() for h in re.split(r"(?<!\\)\|", s)]


def kacir(metin):
    """Hücreye girecek metindeki boru işaretlerini kaçırır."""
    return re.sub(r"(?<!\\)\|", r"\\|", metin).replace("\n", " ").strip()


# Dipnot etiketi ASCII olmak zorunda. Türkçe harfler karşılıklarına
# katlanır; tr_kucult burada KULLANILMAZ, çünkü 'FIX' -> 'fıx' -> 'f-x'
# gibi okunmaz etiketler üretir.
KATLAMA = str.maketrans({
    "ı": "i", "İ": "i", "I": "i", "ş": "s", "Ş": "s", "ğ": "g", "Ğ": "g",
    "ü": "u", "Ü": "u", "ö": "o", "Ö": "o", "ç": "c", "Ç": "c",
})


def slug(kimlik):
    """Dipnot etiketi üretir: `D-24/T14b` -> `d-24-t14b`."""
    t = kimlik.translate(KATLAMA).lower()
    t = unicodedata.normalize("NFKD", t).encode("ascii", "ignore").decode()
    t = re.sub(r"[^a-z0-9]+", "-", t).strip("-")
    return t or "satir"


def durum_coz(ham):
    """Ham durum hücresinden kanonik anahtar sözcüğü çıkarır."""
    d = tr_kucult(ham.replace("*", "").replace("~", "").strip())
    if not d.split():
        return None
    ilk = d.split()[0].rstrip(":,.()")
    return ESLEME.get(ilk)


def kanit_topla(*metinler):
    """Metinlerden kanıt belirteci toplar: dosya:satır, test, commit."""
    bulunan = []
    for m in metinler:
        for span in RE_TIK.findall(m or ""):
            s = span.strip()
            if RE_DOSYA_SATIR.search(s) or RE_TEST.search(s) or RE_COMMIT.match(s):
                if s not in bulunan:
                    bulunan.append(s)
    return bulunan


def tablolari_bul(satirlar):
    """Tablo bloklarını döndürür: (bas, son, baslik_hucreleri, ayrac_var)."""
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
        bloklar.append((bas, i))
    return bloklar


def masa_gocur():
    ham = MASA.read_text(encoding="utf-8")
    satirlar = ham.split("\n")

    # 1-104 arası eski normatif başlık + gömülü betik. Yenisiyle değişir.
    # 105'ten itibaren düzyazı korunur.
    govde = satirlar[104:]

    bloklar = tablolari_bul(govde)
    dipnotlar = []
    kullanilan = {}
    sayac = {"gorev_tablosu": 0, "not_tablosu": 0, "gorev_satiri": 0,
             "not_satiri": 0, "onarilan_boru": 0}

    # Sondan başa işlenir ki indisler kaymasın. Dipnotlar blok blok
    # toplanır ve baştaki listeye önden eklenir; böylece blok içi sıra
    # bozulmadan dosya sırası korunur.
    for bas, son in reversed(bloklar):
        blok_dipnot = []
        blok = govde[bas:son]
        veri = [b for b in blok if not re.match(r"^\|[-\s|:]+\|?\s*$", b.strip())]
        if not veri:
            continue
        basliklar = hucrele(veri[0])
        satir_ham = veri[1:]

        alt = [tr_kucult(b) for b in basliklar]
        gorev_tablosu = "durum" in alt

        if not gorev_tablosu:
            # Not tablosu: olduğu gibi kalır, sadece işaretlenir ve
            # hücreleri boru bakımından onarılır.
            sayac["not_tablosu"] += 1
            sayac["not_satiri"] += len(satir_ham)
            yeni = [NOT_ISARETI]
            yeni.append("| " + " | ".join(basliklar) + " |")
            yeni.append("|" + "---|" * len(basliklar))
            for r in satir_ham:
                h = hucrele(r)
                h = (h + ["—"] * len(basliklar))[:len(basliklar)]
                yeni.append("| " + " | ".join(kacir(x) or "—" for x in h) + " |")
            govde[bas:son] = yeni
            continue

        sayac["gorev_tablosu"] += 1
        di = alt.index("durum")

        # Başlık indisi -> kanonik alan eşlemesi
        harita = {}
        ekstra = []
        for idx, ad in enumerate(alt):
            if idx == 0:
                harita["ID"] = idx
            elif ad in GOREV_ADLARI and "Görev" not in harita:
                harita["Görev"] = idx
            elif ad in SAHIP_ADLARI and "Sahip" not in harita:
                harita["Sahip"] = idx
            elif ad == "durum":
                harita["Durum"] = idx
            elif ad in KILIT_ADLARI and "Kilitli dosyalar" not in harita:
                harita["Kilitli dosyalar"] = idx
            elif ad in KANIT_ADLARI and "Kanıt" not in harita:
                harita["Kanıt"] = idx
            else:
                ekstra.append((basliklar[idx], idx))

        yeni = ["| " + " | ".join(KANONIK) + " |", "|" + "---|" * 6]

        for r in satir_ham:
            h = hucrele(r)
            if len(h) != len(basliklar):
                sayac["onarilan_boru"] += 1
            # eksikse doldur, fazlaysa fazlalık ekstraya düşsün
            h = (h + ["—"] * len(basliklar))[:max(len(basliklar), len(h))]

            def al(alan):
                idx = harita.get(alan)
                return h[idx].strip() if idx is not None and idx < len(h) else ""

            kimlik = al("ID") or "—"
            gorev_tam = al("Görev") or "—"
            sahip = al("Sahip") or "—"
            ham_durum = al("Durum")
            kilit = al("Kilitli dosyalar") or "—"
            kanit_hucre = al("Kanıt")

            kanon = durum_coz(ham_durum)
            if kanon is None:
                # Çözülemeyen durum, satırı sessizce kapatmak yerine
                # beklemede bırakılır ve dipnotta ham hâli durur.
                kanon = "beklemede"

            # Kanıt: durum hücresinden ve kanıt sütunundan toplanır. Kapanmış
            # satırda buradan kanıt çıkmazsa görev metnine de bakılır: bazı
            # satırlarda kapanış anlatısı Durum'a değil Görev hücresine
            # yazılmış ve kanıt orada kalmış.
            belirtec = kanit_topla(kanit_hucre, ham_durum)
            if not belirtec and kanon == "tamam":
                belirtec = kanit_topla(gorev_tam)
            kanit = ", ".join("`%s`" % b for b in belirtec[:3]) if belirtec else "—"

            # Dipnot gerekiyor mu: durum hücresinde anahtar sözcük dışında
            # metin varsa, ya da ekstra sütun varsa, ya da kanıt sütunu
            # belirteçten fazlasını taşıyorsa.
            ham_sade = ham_durum.replace("*", "").strip()
            ilk_kelime = tr_kucult(ham_sade).split()[0].rstrip(":,.()") if ham_sade.split() else ""
            fazla_metin = len(ham_sade) > len(ilk_kelime) + 2

            # Görev hücresi de paragraf taşıyabiliyor. 300 karakteri aşarsa
            # hücrede kelime sınırında kısaltılır, tamamı dipnota gider.
            parcalar = []
            gorev = gorev_tam
            if len(gorev_tam) > 300:
                kes = gorev_tam[:300].rsplit(" ", 1)[0]
                gorev = kes + " …"
                parcalar.append("**Görev (tam metin):** %s" % kacir(gorev_tam))

            if fazla_metin or ilk_kelime != kanon:
                # Dipnota HAM metin gider, yıldızı sökülmüş hâli değil:
                # ham_sade yalnız anahtar sözcük çözmek için üretilir,
                # vurgu işaretleri metnin parçasıdır ve kaybolmamalıdır.
                parcalar.append("**Özgün durum:** %s" % kacir(ham_durum.strip() or "—"))
            if kanit_hucre and kanit_hucre != "—":
                parcalar.append("**Kanıt sütunu:** %s" % kacir(kanit_hucre))
            for ad, idx in ekstra:
                if idx < len(h) and h[idx] and h[idx] != "—":
                    parcalar.append("**%s:** %s" % (ad, kacir(h[idx])))
            if len(h) > len(basliklar):
                parcalar.append("**Artık hücreler:** " +
                                kacir(" ¦ ".join(h[len(basliklar):])))

            if parcalar:
                etiket = slug(kimlik)
                kullanilan[etiket] = kullanilan.get(etiket, 0) + 1
                if kullanilan[etiket] > 1:
                    etiket = "%s-%d" % (etiket, kullanilan[etiket])
                blok_dipnot.append((etiket, kimlik, " · ".join(parcalar)))
                kanit = (kanit + " [^%s]" % etiket) if kanit != "—" else "[^%s]" % etiket

            sayac["gorev_satiri"] += 1
            yeni.append("| %s | %s | %s | %s | %s | %s |" % (
                kacir(kimlik), kacir(gorev), kacir(sahip),
                kanon, kacir(kilit) or "—", kanit))

        govde[bas:son] = yeni
        dipnotlar = blok_dipnot + dipnotlar

    yeni_ham = BASLIK + "\n".join(govde).rstrip("\n") + "\n"
    if dipnotlar:
        yeni_ham += DIPNOT_BASLIGI
        for etiket, kimlik, metin in dipnotlar:
            yeni_ham += "[^%s]: **%s** — %s\n\n" % (etiket, kimlik, metin)

    MASA.write_text(yeni_ham, encoding="utf-8")
    return sayac, len(dipnotlar)


def arayuz_gocur():
    """interfaces.md: tabloyu bölen boş satırları kaldırır.

    Markdown'da boş satır tabloyu bitirir. 572-597 aralığındaki satırlar
    boş satırlarla ayrıldığı için tablo satırı olarak hiç render edilmiyor
    ve hiçbir denetime girmiyordu. Bu, masadaki dördüncü nüksün aynısıdır."""
    satirlar = ARAYUZ.read_text(encoding="utf-8").split("\n")
    cikti = []
    i = 0
    kaldirilan = 0
    while i < len(satirlar):
        s = satirlar[i]
        # Boş satır, öncesi boru satırı, sonrası boru satırı ise: boş satır düşer.
        if (s.strip() == "" and cikti and cikti[-1].startswith("|")
                and i + 1 < len(satirlar) and satirlar[i + 1].startswith("|")):
            kaldirilan += 1
            i += 1
            continue
        cikti.append(s)
        i += 1
    ARAYUZ.write_text("\n".join(cikti), encoding="utf-8")
    return kaldirilan


BASLIK = """# Görev masası

## Satır biçimi (normatif)

Bu bölüm kuraldır, açıklama değildir. Denetim `scripts/audit-board.py` ile
koşar ve buradaki her cümleyi makine tarafından uygular.

### 1. Görev tablosu tam altı sütundur

Sütun sırası şudur ve tablodan tabloya değişmez:

`ID` · `Görev` · `Sahip` · `Durum` · `Kilitli dosyalar` · `Kanıt`

Başlık satırı bu altı adı bu sırayla yazar. Veri satırının hücre sayısı
altıdır. Beşi de altıyı da olmayan satır **biçimsizdir**.

Sütun sırasının sabitlenmesi keyfi değil: bu dosyada Durum sütunu bir zaman
üçüncü, bir zaman dördüncü, bir zaman beşinci konumdaydı ve bazı tablolarda
hiç yoktu. Denetim sabit bir konum varsaydığı için yanlış hücreyi okudu.

### 2. Durum kapalı bir kümedir, tam beş değer

`beklemede` · `çalışıyor` · `tamam` · `düştü` · `bloke`

Durum hücresi **yalnız bu kelimelerden birini** taşır. Parantez, tarih,
gerekçe, yıldız, tırnak yoktur. Altıncı bir değer icat edilmez.

Açık sayılanlar: `beklemede`, `çalışıyor`, `bloke`.
Kapalı sayılanlar: `tamam`, `düştü`.

`kısmen kapandı` diye bir değer yoktur. Yarısı biten iş `çalışıyor` kalır.

### 3. Biçime uymayan satır AÇIK sayılır

Altı hücresi olmayan, Durum hücresi boş olan veya Durum'u yukarıdaki beş
kelimeden biri **olmayan** satır kapalı sayılamaz. Gerekçe olguya dayanır:
denetim Durum hücresini okur; hücre yoksa satır denetime hiç girmez ve açık
bir iş "açık iş yok" diye raporlanır. Bu dosyada dört kez oldu.

Biçimsiz satır sayısı her turda **sıfır** olmalıdır. Sıfır değilse denetim
çıkış kodu 1 verir.

### 4. Kapatan satır kanıt taşır

`tamam` yazan satırın `Kanıt` hücresi doldurulur. Kanıt üç biçimden biridir:
`dosya:satır`, test yolu (`dosya.rs::test_adı`) veya commit hash'i. "27 test
var" gibi sayı beyanı kanıt değildir, çünkü doğrulayanı kaynağa götürmez.

`düştü` yazan satırın gerekçesi dipnotta durur. Gerekçesiz düşürme sessiz
silmedir.

### 5. Satır silmek yasaktır

Uygulanmamış maddeyi silmek de uygulanmış bırakmak da masayı yalancı yapar.
Bir madde ancak `tamam` veya `düştü` ile kapanır ve satırı yerinde kalır.

### 6. Hücreye sığmayan metin dipnota gider

Gerekçe, ölçüm anlatısı, kanıt paragrafı satırın hücresine yazılmaz;
`Kanıt` hücresine bir dipnot bağı (`[^kimlik]`) konur ve metin dosyanın
sonundaki **Satır notları** bölümünde durur. Hücreye paragraf yazmak
sütun hizasını bozar ve satırı okunamaz yapar.

### 7. Not tabloları işaretlenir

Görev taşımayan tablolar (öncelik listesi, indeks, ölçüm beyanı) tablonun
hemen üstüne yazılan `<!-- not-tablosu -->` işaretiyle ayrılır. İşaret
sezgiye bırakılmaz: dördüncü nüksün sebebi, bir görev satırının başlığı
olmayan bir tabloya yapışıp denetimden kaçmasıydı. İşaretsiz ve altı
sütunlu olmayan her tablo denetimde hata verir.

### 8. Hücre içindeki boru işareti kaçırılır

`|` karakteri hücre içinde `\\|` olarak yazılır. Ters tırnak içinde de
geçerlidir: `dedup_by(|a, b| ...)` gibi bir kapanış üç hücre üretir ve
satırı biçimsiz yapar.

### 9. Denetim

Depo kökünde:

    python3 scripts/audit-board.py

Betik dört sayı basar ve biçimsiz satır veya kural dışı durum varsa çıkış
kodu 1 verir: açık satır, biçimsiz satır, kural dışı durum, kanıtsız
kapatılmış satır. Betik dosyanın içine gömülmez; gömülü betik koşmaz,
yalnız koşuyormuş gibi görünür.

"""

DIPNOT_BASLIGI = """

## Satır notları

Aşağıdaki notlar, tablo hücrelerine sığmayan gerekçe ve kanıt metinleridir.
Göç sırasında Durum hücresinden buraya taşındılar; hiçbiri silinmedi.

"""


if __name__ == "__main__":
    sayac, dn = masa_gocur()
    kaldirilan = arayuz_gocur()
    print("task-board.md:")
    print("  görev tablosu   :", sayac["gorev_tablosu"])
    print("  not tablosu     :", sayac["not_tablosu"])
    print("  görev satırı    :", sayac["gorev_satiri"])
    print("  not satırı      :", sayac["not_satiri"])
    print("  onarılan boru   :", sayac["onarilan_boru"])
    print("  dipnot          :", dn)
    print("interfaces.md:")
    print("  kaldırılan boş satır (tabloyu bölen):", kaldirilan)
