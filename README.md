# ArgusAI — Final integration

URL, fayl və IMAP e-poçt analizi. Orijinal rənglər, şriftlər və yuxarı skan bölməsinin quruluşu saxlanılıb. Nəticə paneli avtomatik açılır. Nümunə düymələri və saxta API cavabları tətbiqə daxil edilməyib.

## Vacib: hansı faylları yerləşdirməli?

ZIP-dəki `phishinghub/` qovluğunun **daxilində olan bütün faylları** GitHub repo kökünə yerləşdirin. Köhnə `main.py`, `index.html`, `static/app.js`, `static/styles.css` və `requirements.txt` əvəz olunmalıdır. Yeni `analysis.py`, `intelligence.py`, `mail_analysis.py`, `reports.py` faylları da mütləq repo kökündə olmalıdır. Tək HTML dəyişmək kifayət deyil.

## Nə işləyir?

- **URL:** beş mənbə — VirusTotal, PhishTank, URLhaus, AbuseIPDB, Pulsedive. Hər mənbənin sorğu statusu, nəticəsi və vaxtı ayrıca görünür. `not_configured`, `rate_limited`, `error`, `completed`, `skipped` ayrıdır.
- **Fayl:** maksimum **200 MiB / 209,715,200 bayt**. Fayl bu serverdə emal olunur, icra edilmir. SHA-256 serverdə hissələrlə hesablanır. Xarici xidmətlərə faylın məzmunu deyil, hash və çıxarılan URL-lər göndərilir.
- **Statik fayl yoxlamaları:** Office Open XML (`docx/docm/xlsx/xlsm/pptx/pptm`) paket strukturu, makro komponenti, daxil edilmiş obyektlər, xarici template, linklər, Word sənədində görünən link/hədəf fərqi; HTML link və şifrə forması; TXT link çıxarışı; PDF-də məhdud xam marker yoxlaması; uzantı və MZ başlığı.
- **Linklər:** sənəddən çıxan ilk 5 unikal URL ayrıca beş mənbə ilə yoxlanılır. Nəticədəki seçimdən həmin linkin panelinə keçmək olur. Əsas faylın VirusTotal nəticəsi ilə linkin nəticəsi qarışdırılmır.
- **IMAP:** ən son 5 oxunmamış məktub; readonly və `BODY.PEEK[]`, oxunma statusu dəyişmir. Göndərən / Reply-To / mövzu yalnız məktubda göstərilir. Hər məktubda ən çox 2 MiB mətn, 5 xarici URL yoxlaması və 3 əlavə analizi. Xam məktub üçün ayrıca 25 MiB həddi var — bu, 200 MiB fayl yükləmə həddindən fərqlidir.
- **Risk balı:** qayda əsaslı, izahlı 0–100. Eyni qayda bir dəfə sayılır; lokal əlamətlər maksimum 70, ən güclü reputasiya siqnalı maksimum 90; yekun maksimum 100. Əlaqəli mənbələrin balları toplanmır. Fayldan çıxarılan linkin ən güclü reputasiya siqnalı ayrıca mənşə ilə sənədin qiymətinə daxil ola bilər. Heç bir mənalı analiz yoxdursa rəqəm verilmir.
- **Tövsiyə:** 0–30, 31–69, 70–100 pillələri və istifadəçinin “yalnız aldım / klik etdim / şifrə yazdım” seçimi cavabı dəyişir.
- **Hesabat:** ingiliscə TXT, JSON, çap/PDF. Mənbə-mənbə nəticələr, vaxtlar, real hesabatdan gələn vendor nəticələri, sübutlar, model və tədbirlər daxildir. Malwarebytes və digər vendorların adı yalnız API hesabatında həmin nəticə varsa görünür; ayrıca Malwarebytes API-si qoşulduğu iddia edilmir.
- **AI:** ayrıca chat yoxdur. “Generate AI English summary” düyməsi nəticələrin azaldılmış xülasəsini OpenRouter-ə göndərir. Fayl məzmunu və e-poçt mətni göndərilmir; URL query dəyərləri və userinfo çıxarılır. AI əsas balı dəyişmir. Açar yoxdursa və ya servis işləmirsə, standart hesabat yenə yüklənir.

## Tarixçə və tam ədədli ballar — yeni

- Header-də **History** düyməsi var. Analizlər və yüklənən TXT/JSON hesabatları ayrı siyahılarda saxlanılır; ümumi analiz və export sayları görünür.
- Tarixçə **bu brauzer və cihaz** üçündür, komanda üzrə ortaq hesab deyil. IndexedDB-də saxlanır, səhifə yenilənəndə və server restartında qalır. Brauzer məlumatlarını silmək, gizli pəncərəni bağlamaq və ya başqa domenə keçmək onu əlçatmaz edə bilər.
- Son 200 analiz və 200 hesabat export-u saxlanır. Ümumi sayğaclar “Clear history” edilənədək artmağa davam edir. Eyni analizi yenidən açmaq və AI xülasəsini yeniləmək yeni analiz sayılmır.
- Hesabat export-u brauzerə yükləmə əmri veriləndə qeydə alınır; sayt əməliyyat sistemində faylın həqiqətən saxlanmasını təsdiqləyə bilməz. Tarixçədən təkrar yükləmə yeni export qeydi yaratmır. Print/PDF pəncərəsinin açılması export sayılmır.
- Analizi **Reopen**, hesabatı **Download again** ilə yenidən açmaq olar; yeni API sorğusu lazım deyil. Server hesabatı 30 dəqiqədən sonra silinsə də, brauzerdəki saxlanmış xülasə və nəticələrdən hesabat yüklənə bilər.
- Lokal tarixçə faylın məzmununu və IMAP giriş kodunu saxlamır, amma nəticədəki URL-lər, fayl adları, e-poçt header məlumatları və hesabat məzmunu saxlanır. Ortaq cihazda tarixçəni söndürün və ya iş bitəndə silin. “Save analyses…” seçimi yeni qeydləri dayandırır; mövcudları “Clear history” silir.
- Model **rules-v2.0**: 0–30 **Low risk**, 31–69 **Suspicious**, 70–100 **Dangerous**. “Low risk” təhlükəsizlik zəmanəti deyil. 30 və 70-in üst-üstə düşməsi bu sərhədlərlə aradan qaldırılıb.
- VirusTotal siqnalı əvvəlki kimi sabit 30/55/80 pilləsi deyil: faydalı mühərrik sayları və aşkarlama nisbəti ilə tam ədəd hesablanır. 18, 19 və 20 kimi nəticələr mümkündür; təsadüfi və ya AI tərəfindən uydurulmuş rəqəm deyil. Mühərriklər statistik baxımdan müstəqil hesab edilmir; bu, yenə kalibrasiya edilməmiş heuristic modeldir.
- Formul: malicious varsa `round(min(90,12+75*m/(m+8)+5*m/total))`; yalnız suspicious varsa `round(min(45,10+40*s/(s+8)+5*s/total))`. `total` yalnız malicious/suspicious/undetected/harmless cəmidir; timeout və error daxil deyil. AbuseIPDB ən çox 20 kontekst xalı verə bilər (`round(score*0.2)`, yalnız score ≥ 50). Digər mənbələrin təsdiq səviyyələri və lokal qayda çəkiləri saxlanır.

## 1. Lokal quraşdırma — Windows CMD

Python **3.11 və ya 3.12** istifadə edin.

```bat
cd layihenin-qovlugu
py -m venv .venv
.venv\Scripts\activate
python -m pip install -r requirements.txt
copy .env.example .env
```

`.env` daxilində öz açarlarınızı yazın. Sonra:

```bat
python -m uvicorn main:app --host 127.0.0.1 --port 8000
```

Brauzerdə **http://127.0.0.1:8000** açın. `index.html` faylını iki dəfə klikləməklə canlı backend işləməyəcək.

Linux/macOS: `python3 -m venv .venv`, `source .venv/bin/activate`, sonra eyni `pip` və `uvicorn` komandaları.

## 2. Render — mövcud saytı yeniləmək

1. Bütün layihə fayllarını GitHub-a yerləşdirin; `.env` göndərməyin.
2. Build Command: `pip install -r requirements.txt`
3. Start Command: `python -m uvicorn main:app --host 0.0.0.0 --port $PORT --workers 1`
4. Environment bölməsində aşağıdakı dəyişənləri daxil edin.
5. **Manual Deploy → Deploy latest commit**. Deploy tamamlananda brauzerdə Ctrl+F5 edin.

| Dəyişən | Təyinat |
|---|---|
| `VT_API_KEY` | URL və hash üçün mövcud VirusTotal hesabatları |
| `PHISHTANK_APP_KEY` | PhishTank açarı, istəyə bağlı; açarsız daha sərt limit var |
| `PHISHTANK_ENABLED` | `true` / `false`; standart `true` |
| `PHISHTANK_USER_AGENT` | Tətbiqi tanıdan ad; `.env.example` standart verir |
| `URLHAUS_AUTH_KEY` | URLhaus Auth-Key, tələb olunur |
| `ABUSEIPDB_API_KEY` | IP üzrə sui-istifadə qeydləri |
| `PULSEDIVE_API_KEY` | Domen konteksti |
| `IMAP_SERVER` | Məsələn `imap.gmail.com` |
| `IMAP_USER`, `IMAP_PASS` | Serverdə yoxlanılacaq hesab; tələb olunarsa app password |
| `IMAP_SCAN_TOKEN` | Poçt qutusu üçün uzun təsadüfi giriş kodu; UI-də IMAP tabına yazılır |
| `OPENROUTER_API_KEY` | İstəyə bağlı AI xülasəsi |
| `AI_MODEL` | Standart `openrouter/free`; hesabınıza uyğun model ilə dəyişə bilərsiniz |
| `AI_FALLBACK_MODEL` | İstəyə bağlı ehtiyat model |

Heç bir real açar paketdə yoxdur. IMAP girişi token olmadan açılmır. Sayt işləsə də, təyin edilməmiş açarın xidməti nəticə cədvəlində “Not configured” görünəcək — saxta nəticə verilməyəcək.

## 3. Təqdimatdan əvvəl əl ilə yoxlayın

1. Adi URL → beş mənbənin adı, real statusları, bal və tövsiyə.
2. Öz Word faylınız → format, SHA-256, lokal yoxlamalar; varsa çıxarılan link üçün ayrıca panel.
3. VirusTotal-da olmayan fayl → “No record”; dəstəklənməyən formatda məzmun yoxlaması varmış kimi göstərilmir.
4. 50 MiB-dan böyük, 200 MiB-dan kiçik fayl → upload və hash; 200 MiB-dan böyük fayl UI-də rədd edilməlidir.
5. “I entered a password” → hesab təhlükəsizliyi addımları.
6. TXT və JSON hesabatını yükləyin, mənbələrin nəticələrini müqayisə edin.
7. IMAP tokeni ilə unread məktub → sender yalnız məktub panelində; link və əlavə nəticələri öz kontekstində.
8. AI açarı varsa ingiliscə xülasə yaradın. Açarı olmadan standart hesabatı yoxlayın.

## 4. Testlər

```bash
pip install -r requirements-dev.txt
python -m pytest -q
```

Testlər real API açarı və şəxsi mailbox istifadə etmir. Provider HTTP cavabları və mail məzmunu test fixture-ları ilə əvəzlənir. 51 MiB ölçülü fayl real multipart endpoint-ə yüklənərək hash və nəticə axını da yoxlanılıb. Hazırlanarkən brauzer + backend axını da həmin nəzarətli cavablarla yoxlanılıb: URL, fayl, child link, IMAP, riskə görə tövsiyələr, AI xülasəsi, hesabat yükləmə və mobil görünüş.

**Sizin real API açarlarınızla, real poçt qutunuzla və Render hesabınızda canlı yoxlama aparılmayıb.** Xarici xidmətlərin kvota, hesab, ödəniş və erişim şərtləri nəticəyə təsir edə bilər.

## Məhdudiyyətlər və düzgün təqdimat

- Bu, phishing ilkin araşdırma alətidir; antivirus və ya sandbox deyil. Yüklənən fayllar işə salınmır, URL səhifələri açılmır. “No record”, “undetected” və aşağı bal təhlükəsizlik zəmanəti deyil.
- SPF/DKIM/DMARC müstəqil yoxlanılmır. Hücumçunun yazdığı `Authentication-Results: ... pass` sətrinə inanılmır. From və Reply-To fərqi təkbaşına spoofing sübutu deyil.
- PDF yalnız ilk 8 MiB xam marker skanıdır; sıxılmış və obfuskasiya olunmuş məzmun gözdən qaça bilər. Legacy `.doc/.xls`, şifrəli arxivlər və ZIP64 üçün tam məzmun parseri yoxdur.
- Office: maksimum 5,000 ZIP qeydi, 4 MiB central directory, 150 əlaqəli XML komponenti, hər XML 2 MiB, toplam 8 MiB. Entity expansion bloklanır. CRC / malformed XML xətası “passed” sayılmır.
- VirusTotal mövcud hesabatları sorğulayır, yeni skan submit/poll etmir. Prosesdə 4 sorğu/dəqiqə, 500/gün qoruması; 256 qeydlik TTL keş. Bir neçə tətbiq eyni açarı istifadə edirsə provider kvotası yenə əsasdır. Restart sayğacı sıfırlayır; birdən çox worker işlətməyin.
- Başqa mənbədə kvota / HTTP 429 / PhishTank 509 olsa, digər nəticələr saxlanılır. Mənbə sayını aşkarlama dəqiqliyi və ya müstəqil təsdiq sayı kimi təqdim etməyin.
- Raw fayl diskdə müvəqqəti spool edilir, emaldan sonra bağlanır. Eyni anda maksimum 2 fayl yüklənməsi qəbul edilir; server məşğuldursa yenidən cəhd mesajı qaytarılır. Hesabatlar (fayl bytes deyil) yaddaşda 30 dəqiqə, maksimum 64 qeyd saxlanır. Restartda silinir; təqdimatda hesabatı yükləyin.
- API açarları HTML/JS-də deyil. HTTPS istifadə edin. Məxfi tokenli URL-lər daxil etməyin: reputation provayderlərinə URL göndərilir. AI yalnız istifadəçi ayrıca düymə basanda işləyir.
- Risk çəkiləri izah edilən prototip qaydalarıdır, kalibrasiya edilmiş ehtimal, CVSS və ya aşkarlama keyfiyyəti benchmark-ı deyil.
- VirusTotal Public API və digər provider şərtləri akademik/demo istifadə ilə istehsalat biznes istifadəsini fərqləndirə bilər. Öz hesabınızın şərtlərinə əməl edin.

Rəsmi sənədlər:
- https://docs.virustotal.com/reference/files
- https://docs.virustotal.com/reference/url-object
- https://docs.virustotal.com/reference/public-vs-premium-api
- https://phishtank.org/api_info.php
- https://urlhaus.abuse.ch/api/
- https://docs.abuseipdb.com/
- https://docs.pulsedive.com/api/indicator/get-by-value
