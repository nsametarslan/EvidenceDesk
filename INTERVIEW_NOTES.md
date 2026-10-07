# Interview notes · Türkçe çalışma rehberi

Bu rehber mimariyi kod üzerinden açıklamak ve demoda incelemek içindir. Cevapları kendi gözlemlerinle tamamla; gerçekten yaptığın katkıyı ve anlayıp değiştirebildiğin bölümleri anlat.

## Projeyi iki cümlede anlat

“EvidenceDesk, dışarı aktarılmış kimlik doğrulama olaylarını yerelde incelemek için bir çalışma alanı. Açık kurallarla şüpheli örüntüleri seçiyor, ilgili olayları ve kaynak parmak izlerini gösteriyor; inceleme notunu JSON raporuyla birlikte saklıyor.”

## Veri nasıl ilerliyor?

1. Tarayıcı dosyayı `/api/import` adresine gönderir. Oturuma bağlı CSRF değeri kontrol edilir.
2. `parse_upload`, dosyanın tamamını okur; biçim, alanlar, zaman dilimi ve IP adresini doğrular. Tek yanlış olay varsa hiçbir satır kaydedilmez.
3. `normalize`, zamanı UTC'ye ve IP'yi standart yazıma çevirir. Standart olayın SHA-256 değeri aynı kaydın tekrar eklenmesini engeller.
4. `import_events`, SQLite transaction içinde olayları ve dosyayla ilişkilerini kaydeder. Dosyanın kendi hash'i olay hash'inden ayrıdır.
5. `detect`, olayları zaman sırasına koyar. `deque`, pencere dışına çıkan olayları baştan çıkarabilen bir kuyruktur. Aynı kullanıcı/IP/host için 5 başarısızlık 10 dakikaya sığıyorsa aday üretir.
6. Arayüz adayı, zaman çizelgesini ve masum açıklamayı gösterir. Notu kaydetmek ve eskalasyon kararı insanın işidir.
7. Kaydedilen incelemenin snapshot'ı tutulur: sonradan gelen eski olaylar grubu değiştirirse ilk not ve kanıt kaybolmaz.

## Teknoloji kararları

Python: doğrulama ve zaman penceresi mantığı okunabilir; bildiğin temele yakın. Flask: az sayıda açık HTTP uç noktası için yeterli. SQLite: ayrı servis kurmadan SQL, transaction ve kalıcı notlar. Düz JavaScript: küçük arayüzde bağımlılık ve derleme yükünü azaltıyor. Waitress: Flask debug sunucusunu kullanmadan Windows ve Linux'ta yerel servis sunuyor. Tek worker thread, küçük yerel kullanım için seçildi; yüksek trafik iddiası yok.

## Muhtemel sorular ve dürüst cevaplar

**Bu bir SIEM mi?** Hayır. Canlı veri toplama, entegrasyon ve kurumsal ölçek yok. Dışarı aktarılmış sınırlı bir veri setinde bağlam ve dokümantasyon çalışması.

**Neden timezone zorunlu?** Aynı saat yazımı farklı bölgelerde farklı zamanı ifade edebilir. Zaman penceresine yanlış anlam vermemek için kaynağın açık zaman dilimini istiyoruz.

**Bir hash delilin gerçek olduğunu kanıtlar mı?** Hayır. Aynı içeriği tanımaya ve içerik değişimini karşılaştırmaya yarar. Kimin ürettiğini ve değişmeden toplandığını doğrulamaz.

**SQL injection nasıl engellendi?** Kullanıcı değerleri SQL cümlesine birleştirilmiyor; `?` parametreleri üzerinden veriliyor. Bu kararı `storage.py` içinde gösterebilirsin.

**Yerel uygulamada neden CSRF var?** Kullanıcının ziyaret ettiği başka bir web sayfası yerel servise değişiklik isteği göndermeye çalışabilir. Oturuma bağlı token, origin ve host kontrolü bu yolu sınırlar. Yerel kötü amaçlı süreçlere karşı tam izolasyon sağlamaz.

**XSS nasıl önleniyor?** Arayüzde kayıtlar `textContent` ile metin olarak ekleniyor. Kayıttaki HTML çalıştırılmıyor; ayrıca CSP var. JSON çıktısı dosya eki olarak indiriliyor.

**Bir başarıdan önce 5 hata varsa saldırı mı?** Kesin değil. Kullanıcı parolasını düzeltiyor olabilir. Kullanıcı teyidi, beklenen erişim ve diğer güvenlik sinyalleri olmadan bu bir inceleme adayıdır.

**Tekrar yüklenen dosya ne olur?** Aynı dosya hash'i varsa ekleme yok. Farklı dosyada aynı standart olay varsa olay bir kez tutulur; iki kaynak dosyayla bağlantısı korunur.

**Neyi henüz yapmıyor?** Native Windows/Linux/cloud parser yok; eşikler sabit; veri şifreleme, çok kullanıcı ve üretim testi yok. Eş zamanlı olayların nedensel sırası hash sırasından çıkarılamaz.

**Senin katkın ne?** Gerçekte yaptığın katkıyı anlat: problemi tanımlamak, belirli fonksiyonları incelemek veya değiştirmek, demo davranışını kontrol etmek ya da testlerin koruduğu sınırı açıklamak. Katkı örneklerini gerçekten yaptığın çalışmadan seç; bağımsız yazarlık veya deneyim iddiası ekleme.

## Gerçekten anlamak için 20 dakikalık çalışma

Demoyu yükle, 6 olaylı adayı aç. Son başarıyı örnek dosyada kaldırıp ayrı bir yerel veri dizinine yükle: hangi bulgu kayboldu? Bir zamanı timezone olmadan yaz: neden dosya reddediliyor? Aynı dosyayı iki kez yükle: sayaç değişiyor mu? `rules.py` içindeki 10 dakikayı değiştirip sınır testini çalıştır: testin neyi koruduğunu kendi cümlenle anlat. Değişikliklerini public yapmadan önce testleri ve secret kontrolünü tekrar çalıştır.
