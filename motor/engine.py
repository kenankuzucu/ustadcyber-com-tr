#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ÜSTAD KENAN — SİBER GÜVENLİK 3D MERKEZ  ·  YEREL TARAMA MOTORU
==============================================================
Bu küçük sunucu, tarayıcının yapamadığı GERÇEK işleri yapar:

  1) Gerçek TCP port taraması        (bağlantı denemesi, süre ölçümü)
  2) Gerçek HTTP başlık okuma        (yönlendirme zinciri ile birlikte)
  3) Açıkta kalan hassas dosya kontrolü (.env, .git/config, yedekler…)
  4) Gerçek SSL sertifikası okuma    (konu, veren, tarihler, SAN, TLS sürümü)
  5) Sitenin kendisini http://127.0.0.1:8080 adresinde yayınlar
     (böylece tarayıcının "güvenli bağlam" isteyen araçları da çalışır)

Yalnızca 127.0.0.1 (kendi bilgisayarın) dinlenir; dışarıya açılmaz.
Yetkisi olmadığın sistemlere karşı kullanmak suçtur. Kendi cihazların ve
izinli hedefler için tasarlandı.

Çalıştırma:  python engine.py     (ya da BASLAT-MOTOR.bat dosyasına çift tıkla)
Durdurma :  Bu pencerede CTRL + C
"""

import json
import os
import re
import socket
import ssl
import sys
import threading
import time
import urllib.request
import urllib.error
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer, SimpleHTTPRequestHandler
from urllib.parse import urlparse, parse_qs, unquote

SURUM = "1.0"
API_PORT = 8877
SITE_PORT = 8080
KOK_KLASOR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # sitenin bulunduğu klasör
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")

# Taranacak yaygın portlar (adlarıyla)
PORT_LISTESI = [
    (21, "FTP"), (22, "SSH"), (23, "Telnet"), (25, "SMTP"), (53, "DNS"),
    (80, "HTTP"), (110, "POP3"), (135, "RPC"), (139, "NetBIOS"), (143, "IMAP"),
    (443, "HTTPS"), (445, "SMB"), (587, "SMTP-TLS"), (993, "IMAPS"), (995, "POP3S"),
    (1433, "MSSQL"), (1521, "Oracle"), (2082, "cPanel"), (2083, "cPanel-SSL"),
    (3000, "Dev"), (3306, "MySQL"), (3389, "UzakMasaüstü"), (4443, "HTTPS-alt"),
    (5432, "PostgreSQL"), (5900, "VNC"), (6379, "Redis"), (8000, "HTTP-alt"),
    (8080, "HTTP-alt"), (8443, "HTTPS-alt"), (8888, "HTTP-alt"), (9200, "Elastic"),
    (27017, "MongoDB")
]

# Kontrol edilecek hassas dosya yolları
DOSYA_LISTESI = [
    ("robots.txt", "normal"),
    ("sitemap.xml", "normal"),
    (".well-known/security.txt", "normal"),
    (".git/config", "KRITIK"),
    (".git/HEAD", "KRITIK"),
    (".env", "KRITIK"),
    (".env.local", "KRITIK"),
    ("config.php", "kritik"),
    ("wp-config.php", "kritik"),
    ("backup.zip", "kritik"),
    ("yedek.zip", "kritik"),
    ("db.sql", "kritik"),
    ("phpinfo.php", "kritik"),
    ("adminer.php", "kritik"),
    (".DS_Store", "dusuk"),
    ("server-status", "dusuk"),
]


def cors(handler):
    handler.send_header("Access-Control-Allow-Origin", "*")
    handler.send_header("Access-Control-Allow-Headers", "*")
    handler.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
    handler.send_header("Cache-Control", "no-store")


def port_tara(host, portlar, zaman_asimi=1.2):
    """Gerçek TCP bağlantı testi. Paket göndermez, sadece bağlantı dener."""
    sonuc = []
    for p, ad in portlar:
        t0 = time.time()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(zaman_asimi)
        try:
            s.connect((host, p))
            sonuc.append({"port": p, "ad": ad, "acik": True,
                          "ms": round((time.time() - t0) * 1000)})
        except Exception:
            sonuc.append({"port": p, "ad": ad, "acik": False,
                          "ms": round((time.time() - t0) * 1000)})
        finally:
            try:
                s.close()
            except Exception:
                pass
    return sonuc


def baslik_oku(url):
    """HTTP başlıklarını okur; yönlendirmeleri takip etmeden ilk yanıtı raporlar."""
    if not url.startswith("http"):
        url = "https://" + url
    istek = urllib.request.Request(url, headers={"User-Agent": UA})
    baglam = ssl.create_default_context()
    baglam.check_hostname = False
    baglam.verify_mode = ssl.CERT_NONE
    sonuc = {"url": url, "kod": None, "basliklar": {}, "yonlendirme": None, "hata": None}
    try:
        with urllib.request.urlopen(istek, timeout=15, context=baglam) as r:
            sonuc["kod"] = r.status
            sonuc["basliklar"] = {k: v for k, v in r.headers.items()}
    except urllib.error.HTTPError as e:
        sonuc["kod"] = e.code
        sonuc["basliklar"] = {k: v for k, v in (e.headers or {}).items()}
    except Exception as e:
        sonuc["hata"] = str(e)[:200]
        return sonuc
    konum = sonuc["basliklar"].get("Location") or sonuc["basliklar"].get("location")
    sonuc["yonlendirme"] = {"kod": str(sonuc["kod"]), "yer": konum,
                            "https": bool(konum and konum.strip().lower().startswith("https"))}
    return sonuc


def dosya_kontrol(taban):
    """Hassas dosyalar gerçekten erişilebilir mi? Sadece GET/HEAD denemesi."""
    if not taban.startswith("http"):
        taban = "https://" + taban
    taban = taban.rstrip("/")
    baglam = ssl.create_default_context()
    baglam.check_hostname = False
    baglam.verify_mode = ssl.CERT_NONE
    sonuclar = []
    for yol, risk in DOSYA_LISTESI:
        url = taban + "/" + yol
        kod = "?"
        notu = ""
        try:
            istek = urllib.request.Request(url, headers={"User-Agent": UA})
            with urllib.request.urlopen(istek, timeout=10, context=baglam) as r:
                kod = str(r.status)
                boyut = r.headers.get("Content-Length") or "?"
                notu = "AÇIK · %s bayt" % boyut if r.status == 200 else "erişilebilir"
        except urllib.error.HTTPError as e:
            kod = str(e.code)
            notu = "yok / kapalı"
        except Exception as e:
            kod = "?"
            notu = "hata: " + str(e)[:60]
        riskli = (kod == "200" and risk.lower() == "kritik")
        sonuclar.append({"yol": yol, "kod": kod, "not": notu, "risk": risk, "riskli": riskli})
    return sonuclar


def yerel_ip_bul():
    """Bu bilgisayarın yerel ağ adresini bulur (dışarıya paket göndermez, sadece soket bilgisi)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(1.5)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            return None


def ozel_ag_mi(ip):
    try:
        p = [int(x) for x in ip.split(".")]
    except Exception:
        return False
    if len(p) != 4:
        return False
    if p[0] == 10:
        return True
    if p[0] == 192 and p[1] == 168:
        return True
    if p[0] == 172 and 16 <= p[1] <= 31:
        return True
    return False


def _arp_tablosu():
    """Windows 'arp -a' çıktısından IP -> MAC eşlemesi."""
    esleme = {}
    try:
        import subprocess
        cikti = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=15,
                               encoding="utf-8", errors="replace").stdout
        for satir in cikti.splitlines():
            m = satir.strip().split()
            if len(m) >= 2 and m[0].count(".") == 3 and "-" in m[1]:
                esleme[m[0]] = m[1]
    except Exception:
        pass
    return esleme


def ag_tara(aralik="", zaman_asimi=0.45):
    """Yerel ağdaki cihazları bulur (yalnızca özel ağ aralıkları).

    Yöntem: bilinen portlara kısa TCP bağlantı denemesi (ICMP yetkisi gerekmez).
    Hiçbir paket internetе gitmez; yalnızca yerel ağ içinde kalır.
    """
    from concurrent.futures import ThreadPoolExecutor

    hedef = (aralik or "").strip()
    if not hedef:
        yerel = yerel_ip_bul()
        if not yerel:
            return {"hata": "yerel IP bulunamadı"}
        hedef = ".".join(yerel.split(".")[:3])
    hedef = hedef.replace("/24", "").rstrip(".")
    parcalar = hedef.split(".")
    if len(parcalar) != 3:
        return {"hata": "aralık 'a.b.c' biçiminde olmalı (örn: 192.168.1)"}
    taban = ".".join(parcalar)
    if not ozel_ag_mi(taban + ".1"):
        return {"hata": "Yalnızca kendi özel ağ aralığın taranabilir (10.x · 172.16-31.x · 192.168.x)"}

    portlar = [80, 443, 22, 23, 445, 3389, 8080, 53]
    bulunanlar = []
    kilit = threading.Lock()

    def kontrol(son):
        ip = taban + "." + str(son)
        acik = []
        for p in portlar:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(zaman_asimi)
            try:
                s.connect((ip, p))
                acik.append(p)
            except Exception:
                pass
            finally:
                try:
                    s.close()
                except Exception:
                    pass
        if acik:
            with kilit:
                bulunanlar.append({"ip": ip, "portlar": sorted(acik)})

    with ThreadPoolExecutor(max_workers=96) as havuz:
        list(havuz.map(kontrol, range(1, 255)))

    arp = _arp_tablosu()
    for c in bulunanlar:
        c["mac"] = arp.get(c["ip"], "")
        try:
            c["ad"] = socket.gethostbyaddr(c["ip"])[0]
        except Exception:
            c["ad"] = ""
    bulunanlar.sort(key=lambda x: [int(y) for y in x["ip"].split(".")])
    return {"aralik": taban + ".0/24", "cihazlar": bulunanlar, "cihaz_sayisi": len(bulunanlar)}


PS_BASI = "$ErrorActionPreference='SilentlyContinue'; [Console]::OutputEncoding=[Text.Encoding]::UTF8; $OutputEncoding=[Text.Encoding]::UTF8; "


def ps(komut, zaman=45):
    """PowerShell komutunu çalıştırır, metni döndürür (JSON ise çözümlemeye çalışır)."""
    import subprocess
    try:
        r = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", PS_BASI + komut],
                           capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=zaman)
        cikti = (r.stdout or "").strip()
        if not cikti and r.stderr:
            return None, r.stderr.strip()[:200]
        return cikti, None
    except Exception as e:
        return None, str(e)[:200]


def ps_json(komut, zaman=45):
    """Komut çıktısını JSON olarak döndürür (tek nesne ya da liste)."""
    cikti, hata = ps(komut, zaman)
    if cikti is None:
        return None, hata
    if not cikti:
        return None, "boş yanıt"
    try:
        return json.loads(cikti), None
    except Exception as e:
        return None, "JSON çözümlenemedi: " + str(e)[:80]


def tarih_donustur(v):
    """PowerShell/CIM tarihlerini okunabilir metne çevirir (/Date(ms)/, ISO, {'value':...})."""
    if v is None:
        return None
    if isinstance(v, dict):
        for k in ("value", "Value", "DateTime"):
            if k in v:
                return tarih_donustur(v[k])
        return None
    s = str(v).strip()
    m = re.match(r"^/Date\((-?\d+)", s)
    if m:
        try:
            import datetime
            return datetime.datetime.fromtimestamp(int(m.group(1)) / 1000).strftime("%d.%m.%Y %H:%M")
        except Exception:
            return s
    if re.match(r"^\d{4}-\d{2}-\d{2}T", s):
        return s[:16].replace("T", " ")
    if re.match(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}", s):
        return s[:16]
    if re.match(r"^\d{14}\.\d", s):  # CIM datetime
        try:
            return s[6:8] + "." + s[4:6] + "." + s[0:4] + " " + s[8:10] + ":" + s[10:12]
        except Exception:
            return s
    return s


def pc_saglik():
    """Windows PC sağlık ve güvenlik denetimi. Yalnızca OKUMA amaçlı komutlar çalıştırır."""
    sonuc = {"sistem": {}, "guvenlik": {}, "guncellemeler": [], "paylasimlar": [],
             "portlar": [], "baslangic": [], "diskler": [], "wifi": {}, "hatalar": []}

    # --- sistem bilgisi ---
    d, h = ps_json("Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,BuildNumber,"
                   "LastBootUpTime,@{n='Acilis';e={try{$_.LastBootUpTime.ToString('dd.MM.yyyy HH:mm')}catch{''}}},"
                   "TotalVisibleMemorySize,FreePhysicalMemory,CSName,RegisteredUser | ConvertTo-Json -Compress")
    if d:
        def mb(x):
            try:
                return round(int(x) / 1024)
            except Exception:
                return None
        toplam, bos = mb(d.get("TotalVisibleMemorySize")), mb(d.get("FreePhysicalMemory"))
        sonuc["sistem"] = {
            "makine": d.get("CSName"), "isletim": d.get("Caption"), "surum": d.get("Version"),
            "kullanici": d.get("RegisteredUser"),
            "acilis": tarih_donustur(d.get("Acilis") or d.get("LastBootUpTime")),
            "ram_toplam_mb": toplam, "ram_bos_mb": bos,
            "ram_yuzde": (round((toplam - bos) * 100 / toplam) if toplam and bos is not None else None)
        }
    else:
        sonuc["hatalar"].append("sistem bilgisi: " + str(h))

    c, _ = ps("(Get-CimInstance Win32_Processor).LoadPercentage")
    try:
        sonuc["sistem"]["cpu_yuzde"] = int((c or "0").strip().splitlines()[0])
    except Exception:
        pass

    # --- Defender / antivirüs ---
    d, h = ps_json("Get-MpComputerStatus | Select-Object AntivirusEnabled,RealTimeProtectionEnabled,"
                   "AntispywareEnabled,AntivirusSignatureLastUpdated,"
                   "@{n='ImzaTarihi';e={try{$_.AntivirusSignatureLastUpdated.ToString('dd.MM.yyyy HH:mm')}catch{''}}},"
                   "QuickScanAge,AMServiceEnabled | ConvertTo-Json -Compress")
    if d:
        imza = tarih_donustur(d.get("ImzaTarihi") or d.get("AntivirusSignatureLastUpdated"))
        sonuc["guvenlik"]["defender"] = {k: (str(v) if v is not None else None) for k, v in d.items()}
        sonuc["guvenlik"]["defender"]["ImzaTarihi"] = imza
    else:
        sonuc["guvenlik"]["defender"] = {"hata": str(h)[:120]}

    d, h = ps_json("Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct | "
                   "Select-Object displayName,productState | ConvertTo-Json -Compress")
    av = []
    if d:
        av = d if isinstance(d, list) else [d]
    sonuc["guvenlik"]["antivirusler"] = [{"ad": x.get("displayName"), "durum": x.get("productState")} for x in av]

    # --- güvenlik duvarı ---
    d, h = ps_json("Get-NetFirewallProfile | Select-Object Name,Enabled | ConvertTo-Json -Compress")
    sonuc["guvenlik"]["guvenlik_duvari"] = d if d else [{"hata": str(h)[:100]}]

    # --- SMB1, RDP, BitLocker ---
    d, h = ps_json("Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol,EnableSMB2Protocol | ConvertTo-Json -Compress")
    sonuc["guvenlik"]["smb"] = d if d else {"hata": str(h)[:80]}

    d, h = ps_json("Get-ItemProperty 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' | "
                   "Select-Object fDenyTSConnections | ConvertTo-Json -Compress")
    sonuc["guvenlik"]["rdp"] = d if d else {"hata": str(h)[:80]}

    d, h = ps_json("Get-BitLockerVolume | Select-Object MountPoint,ProtectionStatus,EncryptionPercentage | ConvertTo-Json -Compress")
    sonuc["guvenlik"]["bitlocker"] = d if d else [{"hata": "okunamadı (yönetici izni gerekebilir)"}]

    # --- kullanıcılar ve yöneticiler ---
    d, h = ps_json("Get-LocalUser | Select-Object Name,Enabled,LastLogon | ConvertTo-Json -Compress")
    sonuc["guvenlik"]["kullanicilar"] = d if d else []
    for ku in sonuc["guvenlik"]["kullanicilar"]:
        ku["LastLogon"] = tarih_donustur(ku.get("LastLogon"))
    d, h = ps_json("Get-LocalGroup | Where-Object { $_.SID -like 'S-1-5-32-544' } | "
                   "Get-LocalGroupMember | Select-Object Name,PrincipalSource | ConvertTo-Json -Compress")
    sonuc["guvenlik"]["yoneticiler"] = d if d else []

    # --- güncellemeler ---
    d, h = ps_json("Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 6 HotFixID,Description,"
                   "@{n='Tarih';e={if($_.InstalledOn){$_.InstalledOn.ToString('dd.MM.yyyy')}else{'-'}}} | ConvertTo-Json -Compress")
    if d:
        sonuc["guncellemeler"] = d if isinstance(d, list) else [d]
        for gt in sonuc["guncellemeler"]:
            gt["Tarih"] = tarih_donustur(gt.get("Tarih") or gt.get("InstalledOn"))

    # --- paylaşımlar ---
    d, h = ps_json("Get-SmbShare | Select-Object Name,Path,Description | ConvertTo-Json -Compress")
    if d:
        sonuc["paylasimlar"] = d if isinstance(d, list) else [d]

    # --- dinlenen portlar (dışa açık olanlar) + program adı ---
    d, h = ps_json("Get-NetTCPConnection -State Listen | Where-Object { $_.LocalAddress -eq '0.0.0.0' -or $_.LocalAddress -eq '::' } | "
                   "Select-Object LocalPort,@{n='Program';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}},"
                   "@{n='PID';e={$_.OwningProcess}} | Sort-Object LocalPort -Unique | ConvertTo-Json -Compress", 60)
    if d:
        sonuc["portlar"] = d if isinstance(d, list) else [d]

    # --- başlangıç programları ---
    d, h = ps_json("Get-CimInstance Win32_StartupCommand | Select-Object Name,Command,Location | ConvertTo-Json -Compress")
    if d:
        sonuc["baslangic"] = d if isinstance(d, list) else [d]

    # --- diskler ---
    d, h = ps_json("Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Used -gt 0 } | "
                   "Select-Object Name,@{n='KullanilanGB';e={[math]::Round($_.Used/1GB,1)}},@{n='BosGB';e={[math]::Round($_.Free/1GB,1)}} | ConvertTo-Json -Compress")
    if d:
        sonuc["diskler"] = d if isinstance(d, list) else [d]

    # --- Wi-Fi durumu ---
    c, _ = ps("netsh wlan show interfaces")
    if c:
        wifi = {}
        for satir in c.splitlines():
            if ":" in satir:
                k, _, v = satir.partition(":")
                k, v = k.strip(), v.strip()
                if k and v:
                    wifi[k] = v
        sonuc["wifi"]["arayuz"] = wifi
    c, _ = ps("netsh wlan show profiles")
    if c:
        profiller = []
        for satir in c.splitlines():
            if ":" in satir and ("All User Profile" in satir or "Tüm Kullanıcı Profili" in satir):
                profiller.append(satir.split(":", 1)[1].strip())
        sonuc["wifi"]["kayitli_aglar"] = profiller
    c, _ = ps("netsh wlan show settings")
    if c:
        sonuc["wifi"]["ayarlar"] = c.strip()[:600]

    return sonuc


# ==================== CANLI VERİ KAYNAKLARI (SALDIRI · UÇAK · GEMİ) ====================
# Hepsi ÜCRETSİZ ve anahtarsız açık kaynaklar. Motor yalnızca okuma yapar.

KULLANICI_ARACI = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                   "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")
_BAGLAM = ssl.create_default_context()
_BAGLAM.check_hostname = False
_BAGLAM.verify_mode = ssl.CERT_NONE
_ONBELLEK = {}


def http_metin(url, zaman=30):
    """Basit HTTP GET (gzip destekli). Dış servisler için."""
    import gzip as _gzip
    istek = urllib.request.Request(url, headers={
        "User-Agent": KULLANICI_ARACI, "Accept": "*/*", "Accept-Encoding": "gzip"})
    with urllib.request.urlopen(istek, timeout=zaman, context=_BAGLAM) as y:
        ham = y.read()
        if y.headers.get("Content-Encoding") == "gzip" or ham[:2] == b"\x1f\x8b":
            try:
                ham = _gzip.decompress(ham)
            except Exception:
                pass
        return ham.decode("utf-8", "replace")


def http_json(url, zaman=30):
    return json.loads(http_metin(url, zaman))


def _onbellekli(anahtar, saniye, uret):
    simdi = time.time()
    kayit = _ONBELLEK.get(anahtar)
    if kayit and simdi - kayit[0] < saniye:
        return kayit[1]
    veri = uret()
    _ONBELLEK[anahtar] = (simdi, veri)
    return veri


def ucak_bilgi(lat=37.06, lon=37.38, nm=250, mil=False):
    """adsb.lol açık ADS-B verisi → canlı uçak listesi (Gaziantep varsayılan)."""
    try:
        lat = float(lat); lon = float(lon); nm = max(20, min(250, int(float(nm))))
    except Exception:
        lat, lon, nm = 37.06, 37.38, 250
    sonuc = {"ok": False, "kaynak": "adsb.lol (açık ADS-B topluluğu)",
             "zaman": time.strftime("%d.%m.%Y %H:%M:%S"), "sayi": 0, "ucaklar": [],
             "merkez": [lat, lon], "yaricap_nm": nm, "askeri_mod": bool(mil)}
    yol = ("https://api.adsb.lol/v2/mil" if mil else
           "https://api.adsb.lol/v2/point/%.4f/%.4f/%d" % (lat, lon, nm))
    try:
        j = http_json(yol, 35)
        for u in (j.get("ac") or [])[:160]:
            irtifa = u.get("alt_baro")
            yerde = (irtifa == "ground")
            if isinstance(irtifa, str):
                irtifa = 0 if yerde else None
            sonuc["ucaklar"].append({
                "cagri": (u.get("flight") or "").strip() or (u.get("hex") or "").upper(),
                "tescil": u.get("r"), "tip": u.get("t"),
                "irtifa_ft": irtifa, "hiz_kt": u.get("gs"), "yon": u.get("track"),
                "lat": u.get("lat"), "lon": u.get("lon"), "yerde": yerde,
                "askeri": bool(u.get("dbFlags") and int(u.get("dbFlags") or 0) & 1) or bool(mil),
                "isletmeci": u.get("ownOp") or "",
                "squawk": u.get("squawk"),                       # 7500 kaçırma · 7600 telsiz · 7700 acil
                "acil": (u.get("emergency") not in (None, "none")) or (str(u.get("squawk") or "") in ("7500", "7600", "7700")),
                "acil_tur": (str(u.get("emergency")) if u.get("emergency") not in (None, "none") else
                             ({'7500': 'KAÇIRMA', '7600': 'TELSİZ ARIZASI', '7700': 'GENEL ACİL'}.get(str(u.get("squawk") or ""), None))),
                "pos_yasi_sn": u.get("seen_pos")})               # pozisyon tazeliği (GPS karıştırma göstergesi)
        sonuc["sayi"] = len(sonuc["ucaklar"])
        sonuc["ok"] = True
    except Exception as e:
        sonuc["hata"] = str(e)[:150]
    return sonuc


def gemi_bilgi(adet=240):
    """Digitraffic açık AIS yayını → gerçek gemi konumları (Finlandiya/Baltık)."""
    sonuc = {"ok": False, "kaynak": "Digitraffic açık AIS (Finlandiya/Baltık)",
             "zaman": time.strftime("%d.%m.%Y %H:%M:%S"), "sayi": 0, "gemiler": []}
    try:
        j = http_json("https://meri.digitraffic.fi/api/ais/v1/locations", 40)
        toplanan = []
        for f in (j.get("features") or []):
            ko = (f.get("geometry") or {}).get("coordinates") or []
            oz = f.get("properties") or {}
            if len(ko) >= 2 and oz.get("sog") is not None:
                toplanan.append((oz.get("timestampExternal") or 0, ko[0], ko[1], oz))
        toplanan.sort(key=lambda x: x[0], reverse=True)
        for _, lon, lat, oz in toplanan[:adet]:
            sonuc["gemiler"].append({
                "mmsi": oz.get("mmsi"), "lon": lon, "lat": lat,
                "hiz_kn": round(float(oz.get("sog") or 0), 1),
                "yon": oz.get("cog"), "durum": oz.get("navStat"),
                "liman": (oz.get("destination") or "").strip()})
        sonuc["sayi"] = len(sonuc["gemiler"])
        sonuc["ok"] = True
    except Exception as e:
        sonuc["hata"] = str(e)[:150]
    return sonuc


def saldiri_besle(zorla=False):
    """Canlı zararlı IP listelerini toplar ve birleştirir (10 dk önbellek)."""
    if zorla:
        _ONBELLEK.pop("saldiri", None)
    def uret():
        kaynaklar = [
            ("ipsum", "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt"),
            ("blocklist.de", "https://lists.blocklist.de/lists/all.txt"),
            ("EmergingThreats", "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"),
            ("CINS", "http://cinsscore.com/list/ci-badguys.txt"),
        ]
        skor, durum = {}, []
        for ad, url in kaynaklar:
            try:
                ham = http_metin(url, 35)
                sayi = 0
                for satir in ham.splitlines():
                    satir = satir.strip()
                    if not satir or satir.startswith("#"):
                        continue
                    parca = satir.split()
                    ip = parca[0].strip()
                    if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
                        continue
                    kayit = skor.setdefault(ip, {"ip": ip, "kaynaklar": [], "guc": 0})
                    if ad not in kayit["kaynaklar"]:
                        kayit["kaynaklar"].append(ad)
                    if len(parca) > 1 and parca[1].isdigit():
                        kayit["guc"] += min(int(parca[1]), 40)
                    sayi += 1
                durum.append({"ad": ad, "durum": "ok", "satir": sayi})
            except Exception as e:
                durum.append({"ad": ad, "durum": "hata", "mesaj": str(e)[:80]})
        liste = sorted(skor.values(), key=lambda x: (len(x["kaynaklar"]), x["guc"]), reverse=True)
        return {"ok": True, "zaman": time.strftime("%d.%m.%Y %H:%M:%S"), "kaynaklar": durum,
                "toplam_ip": len(liste), "ip_listesi": liste[:150]}
    return _onbellekli("saldiri", 600, uret)


# ==================== PAKET A/B/C UÇLARI (etik hacker · OSINT · sistem izleme) ====================

def _http_yanit(url, zaman=20, yonlendir=True):
    """GET isteği yapıp durum, başlık ve gövde döndürür."""
    class YonlendirmeKapali(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k):
            return None
    acici = urllib.request.build_opener() if yonlendir else urllib.request.build_opener(YonlendirmeKapali)
    acici.addheaders = [("User-Agent", KULLANICI_ARACI), ("Accept", "*/*"), ("Accept-Encoding", "gzip")]
    try:
        y = acici.open(url, timeout=zaman)
    except urllib.error.HTTPError as h:
        y = h
    ham = y.read() if hasattr(y, "read") else b""
    if ham[:2] == b"\x1f\x8b":
        try:
            import gzip as _g
            ham = _g.decompress(ham)
        except Exception:
            pass
    bas = {k.lower(): v for k, v in (y.headers.items() if y.headers else [])}
    return {"kod": getattr(y, "status", getattr(y, "code", 0)), "basliklar": bas,
            "govde": ham.decode("utf-8", "replace"), "adres": y.geturl() if hasattr(y, "geturl") else url}


def teknoloji_tespit(host):
    """Sitede kullanılan teknolojileri (CMS, sunucu, altyapı) bulur."""
    host = re.sub(r"^[a-z]+://", "", (host or "").strip()).split("/")[0]
    sonuc = {"ok": False, "host": host, "kod": None, "sunucu": None, "baslik": None, "teknolojiler": [], "notlar": []}
    if not host:
        sonuc["hata"] = "host gerekli"
        return sonuc
    yanit = None
    for sema in ("https://", "http://"):
        try:
            yanit = _http_yanit(sema + host + "/", 20)
            break
        except Exception as e:
            sonuc["notlar"].append(sema + " bağlanamadı: " + str(e)[:60])
    if not yanit:
        sonuc["hata"] = "siteye bağlanılamadı"
        return sonuc
    bas = yanit["basliklar"]
    sonuc["kod"] = yanit["kod"]
    sonuc["sunucu"] = bas.get("server")
    govde = yanit["govde"] or ""
    m = re.search(r"<title[^>]*>(.*?)</title>", govde, re.S | re.I)
    sonuc["baslik"] = re.sub(r"\s+", " ", m.group(1)).strip()[:140] if m else None
    kontrol = [
        ("WordPress", r"(wp-content|wp-includes|wp-json)"),
        ("WooCommerce", r"woocommerce"),
        ("Elementor", r"elementor"),
        ("Drupal", r"(sites/default/files|Drupal\.settings)"),
        ("Joomla", r"(/components/com_|joomla)"),
        ("Magento", r"(Magento|mage/cookies)"),
        ("PrestaShop", r"prestashop"),
        ("Shopify", r"cdn\.shopify\.com"),
        ("Wix", r"(wix\.com|wixstatic)"),
        ("Squarespace", r"squarespace"),
        ("Next.js", r"/_next/static"),
        ("React", r"(react(-dom)?[.\-][\d.]*\.(min\.)?js|data-reactroot)"),
        ("Vue.js", r"(vue(@|\.)[\d.]*|v-cloak)"),
        ("Angular", r"(ng-version|angular[.\-][\d.]*\.js)"),
        ("Bootstrap", r"bootstrap[.\-](min\.)?(css|js)"),
        ("jQuery", r"jquery[.\-](min\.)?(js|v?[\d.]+)"),
        ("Tailwind", r"tailwind"),
        ("Cloudflare", r"cloudflare"),
        ("Font Awesome", r"font-?awesome"),
        ("Google Analytics", r"(googletagmanager|gtag\()"),
        ("hls.js", r"hls(\.min)?\.js"),
        ("Laravel", r"(laravel|XSRF-TOKEN)"),
        ("PHP", r"\.php"),
    ]
    govde_kucuk = govde.lower()
    for ad, kalip in kontrol:
        if re.search(kalip, govde_kucuk, re.I):
            sonuc["teknolojiler"].append(ad)
    meta = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', govde, re.I)
    if meta:
        sonuc["generator"] = meta.group(1)[:80]
    for h in ("x-powered-by", "x-generator", "x-drupal-cache", "x-aspnet-version", "x-litespeed-cache",
              "cf-ray", "x-cache", "via", "x-served-by", "x-amz-cf-id"):
        if bas.get(h):
            sonuc["notlar"].append(h + ": " + str(bas[h])[:90])
    if bas.get("set-cookie"):
        sonuc["notlar"].append("çerez: " + str(bas["set-cookie"])[:110])
    if bas.get("strict-transport-security"):
        sonuc["notlar"].append("HSTS: " + str(bas["strict-transport-security"])[:60])
    else:
        sonuc["notlar"].append("HSTS başlığı YOK (https zorlaması zayıf)")
    sonuc["ok"] = True
    return sonuc


DIZIN_YOLLARI = [
    "robots.txt", "sitemap.xml", "security.txt", ".well-known/security.txt", "admin/", "administrator/", "login/",
    "wp-admin/", "wp-login.php", "wp-config.php", "wp-content/uploads/", "phpmyadmin/", "mysql/", "pma/",
    "backup/", "backups/", "yedek/", "db/", "sql/", "database/", "dump.sql", "backup.zip", "backup.tar.gz",
    "site.zip", "www.zip", "yedek.zip", "1.zip", "index.php.bak", "index.html.bak", ".git/", ".svn/", ".env",
    ".env.bak", ".htaccess", "config.php", "config.php.bak", "wp-config.php.bak", "phpinfo.php", "info.php",
    "test.php", "test/", "dev/", "staging/", "old/", "eski/", "yeni/", "log/", "logs/", "error.log", "access.log",
    "cgi-bin/", "server-status", "server-info", "ftp/", "mail/", "webmail/", "cpanel/", "panel/", "xmlrpc.php",
    "readme.html", "license.txt", "composer.json", "package.json", "Dockerfile", "docker-compose.yml", "api/",
    "v1/", "swagger/", "graphql", "assets/", "uploads/", "files/", "temp/", "tmp/", "cache/",
]


def dizin_tara(host, yollar=None, isci=8):
    """Kendi sitende açıkta kalmış dosya/klasör arar (kibar tarama)."""
    host = re.sub(r"^[a-z]+://", "", (host or "").strip()).split("/")[0]
    yollar = yollar or DIZIN_YOLLARI
    sonuc = {"ok": False, "host": host, "denenen": len(yollar), "bulunanlar": []}
    if not host:
        sonuc["hata"] = "host gerekli"
        return sonuc
    taban = None
    for sema in ("https://", "http://"):
        try:
            t = _http_yanit(sema + host + "/", 12)
            taban = sema + host + "/"
            sonuc["tarama_kodu"] = t["kod"]
            break
        except Exception:
            continue
    if not taban:
        sonuc["hata"] = "siteye bağlanılamadı"
        return sonuc
    kilit = threading.Lock()

    def bir(yol):
        try:
            y = _http_yanit(taban + yol, 7, True)
            kod = y["kod"]
            uzunluk = len(y["govde"] or "")
            if kod in (200, 201, 204, 301, 302, 307, 401, 403):
                kayit = {"yol": yol, "kod": kod, "boyut": uzunluk}
                govde = y["govde"] or ""
                if kod in (200, 204) and uzunluk > 0:
                    if re.search(r"(Güvenlik Doğrulaması|Just a moment|cf-chl|checking your browser|Doğrulama|robot kontrol|Attention Required)", govde[:6000], re.I):
                        kayit["onem"] = "waf"
                        kayit["not"] = "barındırma/bot koruması sayfası — gerçek dosya değil"
                    elif re.search(r"(cPanel|Webmail|WHM)", govde[:3000], re.I) and re.search(r"(Redirect|yönlendir|Redirecting)", govde[:3000], re.I):
                        kayit["onem"] = "normal"
                        kayit["not"] = "barındırma paneli yönlendirmesi (ortak hosting'de normal)"
                    elif re.search(r"(404|bulunamadı|not found)", govde[:2000], re.I) and len(govde) < 3000:
                        kayit["onem"] = "normal"
                        kayit["not"] = "site 404 sayfası döndürdü"
                    else:
                        kayit["onem"] = "yüksek" if re.search(r"\.(sql|zip|tar|gz|bak|env|log|old)$|^\.(git|env|svn)", yol) else "orta"
                elif kod in (401, 403):
                    kayit["onem"] = "bilgi"
                    kayit["not"] = "erişim engelli (iyi haber: dosya var ama korunuyor)"
                else:
                    kayit["onem"] = "düşük"
                with kilit:
                    sonuc["bulunanlar"].append(kayit)
        except Exception:
            pass

    isler = []
    for yol in yollar:
        while len(isler) >= isci:
            time.sleep(0.05)
            isler = [t for t in isler if t.is_alive()]
        t = threading.Thread(target=bir, args=(yol,), daemon=True)
        t.start()
        isler.append(t)
    for t in isler:
        t.join(timeout=8)
    sonuc["bulunanlar"].sort(key=lambda x: ({"yüksek": 0, "orta": 1, "bilgi": 2, "düşük": 3, "waf": 4, "normal": 5}.get(x["onem"], 6), x["yol"]))
    sonuc["ok"] = True
    return sonuc


def ssl_derin(host, port=443):
    """Kendi sunucunun TLS sürümlerini, şifreleme setini ve sertifikasını denetler."""
    host = re.sub(r"^[a-z]+://", "", (host or "").strip()).split("/")[0].split(":")[0]
    sonuc = {"ok": False, "host": host, "surumler": [], "sertifika": {}, "bulgular": []}
    if not host:
        sonuc["hata"] = "host gerekli"
        return sonuc
    surumler = [("TLS 1.0", getattr(ssl.TLSVersion, "TLSv1", None), "KAPATILMALI"),
                ("TLS 1.1", getattr(ssl.TLSVersion, "TLSv1_1", None), "KAPATILMALI"),
                ("TLS 1.2", getattr(ssl.TLSVersion, "TLSv1_2", None), "gerekli"),
                ("TLS 1.3", getattr(ssl.TLSVersion, "TLSv1_3", None), "ideal")]
    for ad, sur, not_ in surumler:
        if sur is None:
            continue
        try:
            baglam = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            baglam.check_hostname = False
            baglam.verify_mode = ssl.CERT_NONE
            baglam.minimum_version = sur
            baglam.maximum_version = sur
            with socket.create_connection((host, port), timeout=7) as s:
                with baglam.wrap_socket(s, server_hostname=host) as ss:
                    sifre = ss.cipher()
                    sonuc["surumler"].append({"surum": ad, "acik": True, "sifre": sifre[0] if sifre else None})
                    if ad in ("TLS 1.0", "TLS 1.1"):
                        sonuc["bulgular"].append(ad + " AÇIK — kapatılmalı (eski/zayıf protokol)")
        except Exception:
            sonuc["surumler"].append({"surum": ad, "acik": False})
    try:
        baglam = ssl.create_default_context()
        baglam.check_hostname = False
        baglam.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=8) as s:
            with baglam.wrap_socket(s, server_hostname=host) as ss:
                sert = ss.getpeercert() or {}
                sifre = ss.cipher()
                sonuc["sertifika"] = {
                    "konu": ", ".join("%s=%s" % (k, v) for part in (sert.get("subject") or ()) for k, v in part),
                    "veren": ", ".join("%s=%s" % (k, v) for part in (sert.get("issuer") or ()) for k, v in part),
                    "baslangic": sert.get("notBefore"), "bitis": sert.get("notAfter"),
                    "san_sayisi": len((sert.get("subjectAltName") or ())),
                    "protokol": ss.version(), "sifre": sifre[0] if sifre else None}
                sonuc["ok"] = True
    except Exception as e:
        sonuc["hata"] = "sertifika okunamadı: " + str(e)[:90]
    # sertifika alanlarını çalışan yerli okuyucudan tamamla (CERT_NONE ile alanlar boş gelir)
    try:
        s = sertifika_oku(host, port)
        if isinstance(s, dict) and not s.get("hata"):
            for k in ("konu", "veren", "baslangic", "bitis", "san", "kalanGun", "tls", "sifre"):
                if s.get(k) is not None and k not in ("sifre",):
                    sonuc["sertifika"][k] = s.get(k)
    except Exception:
        pass
    # HSTS ve güvenlik başlıkları
    try:
        y = _http_yanit("https://" + host + "/", 15)
        bas = y["basliklar"]
        zorunlu = ["strict-transport-security", "content-security-policy", "x-content-type-options",
                   "x-frame-options", "referrer-policy", "permissions-policy"]
        eksik = [b for b in zorunlu if b not in bas]
        sonuc["basliklar"] = {b: (bas.get(b)[:70] if bas.get(b) else None) for b in zorunlu}
        sonuc["eksik_basliklar"] = eksik
        if eksik:
            sonuc["bulgular"].append("Eksik güvenlik başlıkları: " + ", ".join(eksik))
    except Exception:
        pass
    return sonuc


def cname_zinciri(host):
    """CNAME zincirini çıkarır ve 'sahipsiz hedef' (alt alan ele geçirme) riskini arar."""
    host = re.sub(r"^[a-z]+://", "", (host or "").strip()).split("/")[0]
    sonuc = {"ok": False, "host": host, "zincir": [], "risk": [], "hedef_ip": None}
    if not host:
        sonuc["hata"] = "host gerekli"
        return sonuc
    suanki, gorulen = host, set()
    for _ in range(6):
        try:
            j = http_json("https://dns.google/resolve?name=%s&type=CNAME" % urllib.parse.quote(suanki), 12)
        except Exception as e:
            sonuc["zincir"].append({"ad": suanki, "hata": str(e)[:60]})
            break
        cevaplar = [a.get("data", "").rstrip(".") for a in (j.get("Answer") or []) if a.get("type") == 5]
        if not cevaplar:
            break
        hedef = cevaplar[0]
        sonuc["zincir"].append({"ad": suanki, "cname": hedef})
        if hedef in gorulen:
            break
        gorulen.add(hedef)
        suanki = hedef
    try:
        j = http_json("https://dns.google/resolve?name=%s&type=A" % urllib.parse.quote(suanki), 12)
        cev = [a.get("data") for a in (j.get("Answer") or []) if a.get("type") == 1]
        sonuc["hedef_ip"] = cev[0] if cev else None
    except Exception:
        pass
    hizmetler = {"herokuapp.com": "Heroku", "github.io": "GitHub Pages", "s3.amazonaws.com": "AWS S3",
                 "azurewebsites.net": "Azure", "cloudfront.net": "CloudFront", "netlify.app": "Netlify",
                 "vercel.app": "Vercel", "surge.sh": "Surge", "wordpress.com": "WordPress.com",
                 "myshopify.com": "Shopify", "fastly.net": "Fastly", "readthedocs.io": "ReadTheDocs",
                 "ghost.io": "Ghost", "trafficmanager.net": "Azure TM", "azureedge.net": "Azure CDN",
                 "zendesk.com": "Zendesk", "statuspage.io": "Statuspage"}
    for adim in sonuc["zincir"]:
        hedef = adim.get("cname", "")
        for kalip, ad2 in hizmetler.items():
            if hedef.endswith(kalip):
                sonuc["risk"].append({"hedef": hedef, "hizmet": ad2,
                                      "aciklama": "Bu hizmetin aboneliği kapatıldıysa alan adın ele geçirilebilir. "
                                                  "Hizmet panelinde adın hâlâ kayıtlı olduğunu doğrula."})
    if not sonuc["zincir"]:
        sonuc["risk"].append({"hedef": host, "hizmet": "-", "aciklama": "CNAME yok (doğrudan A kaydı kullanılıyor) — ele geçirme riski düşük."})
    sonuc["ok"] = True
    return sonuc


def mac_uretici(mac):
    mac = (mac or "").strip().replace("-", ":")
    try:
        return {"ok": True, "mac": mac, "uretici": http_metin("https://api.macvendors.com/" + urllib.parse.quote(mac), 15).strip()[:120]}
    except Exception as e:
        return {"ok": False, "mac": mac, "hata": str(e)[:100]}


def urlscan_ara(hedef):
    hedef = re.sub(r"^[a-z]+://", "", (hedef or "").strip()).split("/")[0]
    try:
        j = http_json("https://urlscan.io/api/v1/search/?q=domain%%3A%s&size=20" % urllib.parse.quote(hedef), 25)
        kayitlar = []
        for k in (j.get("results") or [])[:20]:
            kayitlar.append({"adres": (k.get("page") or {}).get("url"),
                             "zaman": k.get("task", {}).get("time"),
                             "skor": (k.get("verdicts", {}).get("overall", {}) or {}).get("score"),
                             "ulke": (k.get("page") or {}).get("country"),
                             "sunucu": (k.get("page") or {}).get("server"),
                             "tarayan": (k.get("task") or {}).get("source"),
                             "sonuc_link": "https://urlscan.io/result/%s/" % k.get("_id")})
        return {"ok": True, "hedef": hedef, "sayi": len(kayitlar), "kayitlar": kayitlar,
                "toplam": j.get("total", len(kayitlar))}
    except Exception as e:
        return {"ok": False, "hedef": hedef, "hata": str(e)[:120]}


def olay_gunlugu(adet=30):
    """Windows olay günlüklerinden güvenlikle ilgili kayıtları çıkarır."""
    sonuc = {"ok": True, "zaman": time.strftime("%d.%m.%Y %H:%M:%S"), "gruplar": [], "yönetici": True}
    sorgular = [
        ("Hizmet kurulumu (System 7045)", "Get-WinEvent -LogName System -MaxEvents 400 | Where-Object { $_.Id -eq 7045 } | Select-Object -First %d TimeCreated,Id,@{n='Ad';e={($_.Message -split \"`n\")[0]}},@{n='Yol';e={($_.Message -split \"`n\")[1]}} | ConvertTo-Json -Compress" % adet),
        ("Başarısız oturum açma (Security 4625)", "Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -MaxEvents %d | Select-Object TimeCreated,Id,@{n='Kullanici';e={$_.Properties[5].Value}},@{n='Kaynak';e={$_.Properties[19].Value}} | ConvertTo-Json -Compress" % adet),
        ("Yeni kullanıcı / grupa ekleme (Security 4720/4732)", "Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4720,4722,4726,4732} -MaxEvents %d | Select-Object TimeCreated,Id,@{n='Hedef';e={$_.Properties[0].Value}} | ConvertTo-Json -Compress" % adet),
        ("Aygıt takma/çıkarma (Kernel-PnP)", "Get-WinEvent -LogName 'Microsoft-Windows-Kernel-PnP/Configuration' -MaxEvents 300 | Where-Object { $_.Id -in 400,410,430 } | Select-Object -First %d TimeCreated,Id,@{n='Aygit';e={($_.Message -split \"`n\")[0]}} | ConvertTo-Json -Compress" % adet),
    ]
    for ad, komut in sorgular:
        d, h = ps_json(komut, 90)
        if d is None:
            mesaj = str(h)[:110]
            if "Security" in ad and ("erişim" in mesaj.lower() or "denied" in mesaj.lower() or "yetki" in mesaj.lower()):
                sonuc["yönetici"] = False
                mesaj = "Yönetici yetkisi gerekiyor (motoru 'Yönetici olarak çalıştır' ile aç)"
            sonuc["gruplar"].append({"ad": ad, "kayitlar": [], "hata": mesaj})
            continue
        kayitlar = d if isinstance(d, list) else [d]
        temiz = []
        for k in kayitlar[:adet]:
            yeni = {}
            for kk, vv in k.items():
                if kk == "TimeCreated" and isinstance(vv, dict):
                    vv = vv.get("value") or (vv.get("DateTime") and str(vv["DateTime"]))
                yeni[kk] = tarih_donustur(vv) if kk == "TimeCreated" else (str(vv)[:120] if vv is not None else None)
            temiz.append(yeni)
        sonuc["gruplar"].append({"ad": ad, "kayitlar": temiz, "hata": None})
    return sonuc


def defender_bilgi(tara=False):
    sonuc = {"ok": True, "zaman": time.strftime("%d.%m.%Y %H:%M:%S"), "tarama_baslatildi": False}
    d, h = ps_json("Get-MpComputerStatus | Select-Object AntivirusEnabled,RealTimeProtectionEnabled,"
                   "AntivirusSignatureVersion,AntivirusSignatureLastUpdated,QuickScanStartTime,QuickScanAge,"
                   "FullScanAge,LastQuickScanSource,AMServiceEnabled,IsTamperProtected | ConvertTo-Json -Compress")
    if d:
        for k in ("AntivirusSignatureLastUpdated", "QuickScanStartTime"):
            if k in d:
                d[k] = tarih_donustur(d[k])
        sonuc["durum"] = d
    else:
        sonuc["durum"] = {"hata": str(h)[:110]}
    d2, _ = ps_json("Get-MpThreatDetection | Sort-Object InitialDetectionTime -Descending | "
                    "Select-Object -First 8 @{n='Zaman';e={$_.InitialDetectionTime}},ThreatID,"
                    "@{n='Kaynak';e={$_.Resources}} | ConvertTo-Json -Compress")
    if d2:
        kayitlar = d2 if isinstance(d2, list) else [d2]
        for k in kayitlar:
            if "Zaman" in k:
                k["Zaman"] = tarih_donustur(k["Zaman"])
        sonuc["tespitler"] = kayitlar
    else:
        sonuc["tespitler"] = []
    if tara:
        threading.Thread(target=lambda: ps("Start-MpScan -ScanType QuickScan", 900), daemon=True).start()
        sonuc["tarama_baslatildi"] = True
    return sonuc


def disk_saglik():
    sonuc = {"ok": True, "zaman": time.strftime("%d.%m.%Y %H:%M:%S"), "diskler": [], "birimler": []}
    d, h = ps_json("Get-PhysicalDisk | Select-Object FriendlyName,MediaType,BusType,HealthStatus,OperationalStatus,"
                   "@{n='GB';e={[math]::Round($_.Size/1GB,1)}} | ConvertTo-Json -Compress")
    if d:
        sonuc["diskler"] = d if isinstance(d, list) else [d]
    else:
        sonuc["diskler_hata"] = str(h)[:110]
    d2, _ = ps_json("Get-PhysicalDisk | ForEach-Object { $r = $_ | Get-StorageReliabilityCounter; "
                    "[pscustomobject]@{ Disk=$_.FriendlyName; Sicaklik=$r.Temperature; Asinma=$r.Wear; "
                    "CalismaSaati=$r.PowerOnHours; OkumaHatasi=$r.ReadErrorsTotal; YazmaHatasi=$r.WriteErrorsTotal } } | ConvertTo-Json -Compress")
    if d2:
        sonuc["dayaniklilik"] = d2 if isinstance(d2, list) else [d2]
    d3, _ = ps_json("Get-Volume | Where-Object { $_.DriveLetter } | Select-Object DriveLetter,FileSystemLabel,FileSystem,"
                    "@{n='BosGB';e={[math]::Round($_.SizeRemaining/1GB,1)}},@{n='TopGB';e={[math]::Round($_.Size/1GB,1)}},HealthStatus | ConvertTo-Json -Compress")
    if d3:
        sonuc["birimler"] = d3 if isinstance(d3, list) else [d3]
    return sonuc


def gorev_listesi():
    sonuc = {"ok": True, "zaman": time.strftime("%d.%m.%Y %H:%M:%S"), "gorevler": [], "baslangic": []}
    d, h = ps_json("Get-ScheduledTask | Where-Object { $_.State -eq 'Ready' -and $_.TaskPath -notlike '\\Microsoft\\*' } | "
                   "ForEach-Object { [pscustomobject]@{ Ad=$_.TaskName; Yol=$_.TaskPath; Yazan=$_.Author; "
                   "Komut=($_.Actions | ForEach-Object { $_.Execute }) -join ' | '; "
                   "Arguman=($_.Actions | ForEach-Object { $_.Arguments }) -join ' ' } } | ConvertTo-Json -Compress", 90)
    if d:
        sonuc["gorevler"] = d if isinstance(d, list) else [d]
    else:
        sonuc["gorev_hata"] = str(h)[:110]
    d2, _ = ps_json("Get-CimInstance Win32_StartupCommand | Select-Object Name,Command,Location,User | ConvertTo-Json -Compress", 60)
    if d2:
        sonuc["baslangic"] = d2 if isinstance(d2, list) else [d2]
    return sonuc


def kasirga_bilgi():
    """NOAA aktif kasırga/tropikal fırtına listesi (tarayıcıdan erişim kapalı → motor)."""
    sonuc = {"ok": False, "kaynak": "NOAA Ulusal Kasırga Merkezi", "zaman": time.strftime("%d.%m.%Y %H:%M:%S"), "firtinalar": []}
    try:
        j = http_json("https://www.nhc.noaa.gov/CurrentStorms.json", 30)
        for s in (j.get("activeStorms") or []):
            sonuc["firtinalar"].append({
                "ad": s.get("name"), "tur": s.get("classification"), "basinc": s.get("pressure"),
                "ruzgar_mph": s.get("intensity"), "hareket": s.get("movement"),
                "konum": s.get("latitude") and (str(s.get("latitude")) + s.get("longitude", "")),
                "havza": s.get("binNumber"), "guncelleme": s.get("lastUpdate"),
                "uyari": s.get("publicAdvisory", {}).get("url") if isinstance(s.get("publicAdvisory"), dict) else None})
        sonuc["ok"] = True
        sonuc["sayi"] = len(sonuc["firtinalar"])
    except Exception as e:
        sonuc["hata"] = str(e)[:150]
    return sonuc


def radyasyon_bilgi(adet=40):
    """Safecast açık radyasyon ölçümleri (tarayıcıdan erişim kapalı → motor)."""
    sonuc = {"ok": False, "kaynak": "Safecast (açık ölçüm ağı)", "zaman": time.strftime("%d.%m.%Y %H:%M:%S"), "olcumler": []}
    try:
        j = http_json("https://api.safecast.org/measurements.json?limit=%d&order=captured_at+desc" % adet, 35)
        for o in (j if isinstance(j, list) else []):
            sonuc["olcumler"].append({
                "deger": o.get("value"), "birim": o.get("unit"),
                "enlem": o.get("latitude"), "boylam": o.get("longitude"),
                "yer": (o.get("location_name") or "").strip(), "zaman": (o.get("captured_at") or "")[:19],
                "cihaz": o.get("device_id")})
        sonuc["ok"] = True
        sonuc["sayi"] = len(sonuc["olcumler"])
    except Exception as e:
        sonuc["hata"] = str(e)[:150]
    return sonuc


def sertifika_oku(host, port=443):
    """Gerçek TLS el sıkışması yapıp sertifikayı ve şifreleme bilgisini okur."""
    baglam = ssl.create_default_context()
    baglam.check_hostname = False
    baglam.verify_mode = ssl.CERT_NONE
    sonuc = {"host": host, "hata": None}
    try:
        with socket.create_connection((host, port), timeout=12) as ham:
            with baglam.wrap_socket(ham, server_hostname=host) as s:
                der = s.getpeercert(binary_form=True)
                sonuc["tls"] = s.version()
                sifre = s.cipher()
                sonuc["sifre"] = (sifre[0] if sifre else "—")
                pem = ssl.DER_cert_to_PEM_cert(der)
                import tempfile
                with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as f:
                    f.write(pem)
                    yol = f.name
                try:
                    bilgi = ssl._ssl._test_decode_cert(yol)
                finally:
                    try:
                        os.unlink(yol)
                    except Exception:
                        pass
                def birlestir(x):
                    try:
                        parcalar = []
                        for rdn in (x or []):
                            for kv in rdn:
                                if isinstance(kv, (list, tuple)) and len(kv) == 2:
                                    parcalar.append(str(kv[0]) + "=" + str(kv[1]))
                                else:
                                    parcalar.append(str(kv))
                        return " / ".join(parcalar) if parcalar else "—"
                    except Exception:
                        return str(x)[:200]
                sonuc["konu"] = birlestir(bilgi.get("subject"))
                sonuc["veren"] = birlestir(bilgi.get("issuer"))
                sonuc["baslangic"] = bilgi.get("notBefore")
                sonuc["bitis"] = bilgi.get("notAfter")
                san = []
                for tip, deger in (bilgi.get("subjectAltName") or []):
                    san.append(deger)
                sonuc["san"] = san
                try:
                    import datetime
                    b = datetime.datetime.strptime(bilgi.get("notAfter"), "%b %d %H:%M:%S %Y %Z")
                    sonuc["kalanGun"] = (b - datetime.datetime.utcnow()).days
                except Exception:
                    sonuc["kalanGun"] = None
    except Exception as e:
        sonuc["hata"] = str(e)[:200]
    return sonuc


class ApiHandler(BaseHTTPRequestHandler):
    server_version = "UK-Motor/" + SURUM
    allow_reuse_address = False

    def log_message(self, fmt, *args):  # sessiz günlük
        pass
    def _gonder(self, veri, kod=200, tip="application/json; charset=utf-8"):
        ham = veri.encode("utf-8") if isinstance(veri, str) else veri
        self.send_response(kod)
        self.send_header("Content-Type", tip)
        self.send_header("Content-Length", str(len(ham)))
        cors(self)
        self.end_headers()
        try:
            self.wfile.write(ham)
        except Exception:
            pass

    def do_OPTIONS(self):
        self.send_response(204)
        cors(self)
        self.end_headers()

    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        yol = u.path.rstrip("/") or "/"

        if yol == "/ping":
            self._gonder(json.dumps({"ok": True, "surum": SURUM, "python": sys.version.split()[0],
                                     "site": "http://127.0.0.1:%d" % SITE_PORT}, ensure_ascii=False))
            return

        if yol == "/port":
            host = (q.get("host", [""])[0] or "").strip()
            if not host:
                self._gonder(json.dumps({"hata": "host gerekli"}, ensure_ascii=False), 400)
                return
            try:
                socket.gethostbyname(host)
            except Exception:
                self._gonder(json.dumps({"hata": "adres çözümlenemedi"}, ensure_ascii=False), 400)
                return
            liste = PORT_LISTESI
            if q.get("hizli", [""])[0]:
                liste = [p for p in PORT_LISTESI if p[0] in (21, 22, 23, 25, 80, 443, 3306, 3389, 8080)]
            self._gonder(json.dumps({"host": host, "portlar": port_tara(host, liste)}, ensure_ascii=False))
            return

        if yol == "/baslik":
            url = unquote(q.get("url", [""])[0])
            if not url:
                self._gonder(json.dumps({"hata": "url gerekli"}, ensure_ascii=False), 400)
                return
            self._gonder(json.dumps(baslik_oku(url), ensure_ascii=False))
            return

        if yol == "/dosya":
            taban = unquote(q.get("url", [""])[0])
            if not taban:
                self._gonder(json.dumps({"hata": "url gerekli"}, ensure_ascii=False), 400)
                return
            self._gonder(json.dumps({"taban": taban, "sonuclar": dosya_kontrol(taban)}, ensure_ascii=False))
            return

        if yol == "/sertifika":
            host = (q.get("host", [""])[0] or "").strip()
            if not host:
                self._gonder(json.dumps({"hata": "host gerekli"}, ensure_ascii=False), 400)
                return
            self._gonder(json.dumps(sertifika_oku(host), ensure_ascii=False))
            return

        if yol == "/pcsaglik":
            try:
                self._gonder(json.dumps(pc_saglik(), ensure_ascii=False), 200)
            except Exception as e:
                self._gonder(json.dumps({"hata": "denetim hatası: " + str(e)[:200]}, ensure_ascii=False), 200)
            return

        if yol == "/ucak":
            try:
                mil = (q.get("mil", ["0"])[0] or "") in ("1", "true", "evet")
                s = ucak_bilgi(q.get("lat", ["37.06"])[0], q.get("lon", ["37.38"])[0],
                               q.get("nm", ["250"])[0], mil)
                self._gonder(json.dumps(s, ensure_ascii=False), 200)
            except Exception as e:
                self._gonder(json.dumps({"hata": "uçak verisi alınamadı: " + str(e)[:160]}, ensure_ascii=False), 200)
            return

        if yol == "/gemi":
            try:
                adet = int(float(q.get("adet", ["240"])[0]))
            except Exception:
                adet = 240
            try:
                self._gonder(json.dumps(gemi_bilgi(adet), ensure_ascii=False), 200)
            except Exception as e:
                self._gonder(json.dumps({"hata": "gemi verisi alınamadı: " + str(e)[:160]}, ensure_ascii=False), 200)
            return

        if yol == "/saldiri":
            try:
                self._gonder(json.dumps(saldiri_besle(bool(q.get("zorla", [""])[0])), ensure_ascii=False), 200)
            except Exception as e:
                self._gonder(json.dumps({"hata": "saldırı listesi alınamadı: " + str(e)[:160]}, ensure_ascii=False), 200)
            return

        if yol == "/teknoloji":
            h = (q.get("host", [""])[0] or "").strip()
            self._gonder(json.dumps(teknoloji_tespit(h) if h else {"ok": False, "hata": "host gerekli"}, ensure_ascii=False))
            return

        if yol == "/dizin":
            h = (q.get("host", [""])[0] or "").strip()
            self._gonder(json.dumps(dizin_tara(h) if h else {"ok": False, "hata": "host gerekli"}, ensure_ascii=False))
            return

        if yol == "/ssl":
            h = (q.get("host", [""])[0] or "").strip()
            self._gonder(json.dumps(ssl_derin(h) if h else {"ok": False, "hata": "host gerekli"}, ensure_ascii=False))
            return

        if yol == "/cname":
            h = (q.get("host", [""])[0] or "").strip()
            self._gonder(json.dumps(cname_zinciri(h) if h else {"ok": False, "hata": "host gerekli"}, ensure_ascii=False))
            return

        if yol == "/mac":
            m = (q.get("mac", [""])[0] or "").strip()
            self._gonder(json.dumps(mac_uretici(m) if m else {"ok": False, "hata": "mac gerekli"}, ensure_ascii=False))
            return

        if yol == "/urlscan":
            h = (q.get("host", [""])[0] or "").strip()
            self._gonder(json.dumps(urlscan_ara(h) if h else {"ok": False, "hata": "host gerekli"}, ensure_ascii=False))
            return

        if yol == "/olay":
            try:
                adet = int(float(q.get("adet", ["30"])[0]))
            except Exception:
                adet = 30
            try:
                self._gonder(json.dumps(olay_gunlugu(adet), ensure_ascii=False))
            except Exception as e:
                self._gonder(json.dumps({"ok": False, "hata": "olay günlüğü okunamadı: " + str(e)[:150]}, ensure_ascii=False))
            return

        if yol == "/defender":
            try:
                self._gonder(json.dumps(defender_bilgi(bool(q.get("tara", [""])[0])), ensure_ascii=False))
            except Exception as e:
                self._gonder(json.dumps({"ok": False, "hata": "Defender bilgisi alınamadı: " + str(e)[:150]}, ensure_ascii=False))
            return

        if yol == "/disk":
            try:
                self._gonder(json.dumps(disk_saglik(), ensure_ascii=False))
            except Exception as e:
                self._gonder(json.dumps({"ok": False, "hata": "disk bilgisi alınamadı: " + str(e)[:150]}, ensure_ascii=False))
            return

        if yol == "/gorevler":
            try:
                self._gonder(json.dumps(gorev_listesi(), ensure_ascii=False))
            except Exception as e:
                self._gonder(json.dumps({"ok": False, "hata": "görev listesi alınamadı: " + str(e)[:150]}, ensure_ascii=False))
            return

        if yol == "/kasirga":
            try:
                self._gonder(json.dumps(_onbellekli("kasirga", 900, kasirga_bilgi), ensure_ascii=False), 200)
            except Exception as e:
                self._gonder(json.dumps({"ok": False, "hata": "kasırga verisi alınamadı: " + str(e)[:150]}, ensure_ascii=False), 200)
            return

        if yol == "/radyo":
            try:
                self._gonder(json.dumps(_onbellekli("radyo", 900, radyasyon_bilgi), ensure_ascii=False), 200)
            except Exception as e:
                self._gonder(json.dumps({"ok": False, "hata": "radyasyon verisi alınamadı: " + str(e)[:150]}, ensure_ascii=False), 200)
            return

        if yol == "/ag":
            aralik = (q.get("aralik", [""])[0] or "").strip()
            self._gonder(json.dumps(ag_tara(aralik), ensure_ascii=False))
            return

        if yol == "/dns":
            host = (q.get("host", [""])[0] or "").strip()
            try:
                ip = socket.gethostbyname_ex(host)
                self._gonder(json.dumps({"host": host, "ip": ip[2], "takma": ip[1]}, ensure_ascii=False))
            except Exception as e:
                self._gonder(json.dumps({"hata": str(e)[:120]}, ensure_ascii=False))
            return

        self._gonder(json.dumps({"hata": "bilinmeyen uç nokta",
                                 "uclar": ["/ping", "/port?host=", "/baslik?url=", "/dosya?url=",
                                           "/sertifika?host=", "/ag?aralik=", "/dns?host="]}, ensure_ascii=False), 404)


class SiteHandler(SimpleHTTPRequestHandler):
    """Sitenin kendisini http://127.0.0.1:8080 üzerinden yayınlar."""

    allow_reuse_address = False
    protocol_version = "HTTP/1.0"

    def __init__(self, *a, **kw):
        super().__init__(*a, directory=KOK_KLASOR, **kw)

    def log_message(self, fmt, *args):
        pass

    def end_headers(self):
        self.send_header("Cache-Control", "no-store")
        super().end_headers()


def basla():
    print("=" * 68)
    print("  ÜSTAD KENAN — SİBER GÜVENLİK 3D MERKEZ · YEREL TARAMA MOTORU v" + SURUM)
    print("=" * 68)
    print("  SİTE  : http://127.0.0.1:%d/index.html   (buradan aç, tam güç)" % SITE_PORT)
    print("  MOTOR : http://127.0.0.1:%d/ping         (site bunu otomatik bulur)" % API_PORT)
    print("  Klasör: " + KOK_KLASOR)
    print("-" * 68)
    print("  Yalnızca bu bilgisayar (127.0.0.1) dinleniyor. Dışarıya açık değil.")
    print("  Durdurmak için: CTRL + C")
    print("=" * 68)

    try:
        api = ThreadingHTTPServer(("127.0.0.1", API_PORT), ApiHandler)
        site = ThreadingHTTPServer(("127.0.0.1", SITE_PORT), SiteHandler)
    except OSError as hata:
        print("  !! MOTOR BAŞLATILAMADI:", hata)
        print("  Sebep: " + str(API_PORT) + " ya da " + str(SITE_PORT) + " portu başka bir programda kullanılıyor.")
        print("  Çözüm: Daha önce açtığın motor penceresini kapat (ya da bilgisayarı yeniden başlat) ve tekrar dene.")
        if not os.environ.get("UK_NO_BROWSER"):
            input("  Kapatmak için Enter'a bas...")
        return
    threading.Thread(target=api.serve_forever, daemon=True).start()
    threading.Thread(target=site.serve_forever, daemon=True).start()

    adres = "http://127.0.0.1:%d/index.html" % SITE_PORT
    if os.environ.get("UK_NO_BROWSER") != "1":
        try:
            webbrowser.open(adres)
        except Exception:
            pass
    print("  ✔ Motor çalışıyor. Pencereyi KAPATMA. (Açılan tarayıcı sekmesi hazır.)")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n  Motor durduruldu. Görüşürüz Üstad.")
        try:
            api.shutdown()
            site.shutdown()
        except Exception:
            pass


if __name__ == "__main__":
    basla()
