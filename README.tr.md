**[English README](README.md)**

# KageTamga

> Ağa değil, tamgaya güven.

Parmak izi güveni, imzalı eş tanıştırmaları ve Curve25519 + ML-KEM-768 E2EE kullanan, yalnızca tarayıcıda çalışan P2P mesajlaşma uygulaması.

## Adın kökeni

**KageTamga**, özellikle oluşturulmuş Japonca–Türkçe bir addır. *Kage* (影) Japoncada “gölge”; *tamga* ise tarihî Türk kültüründe kimlik ve köken bildiren işaret, damga veya mühürdür. Birlikte, bağımsız olarak doğrulanabilen özel bir işareti ve uygulamanın tam parmak izine dayalı güven modelini anlatır.

> **Güvenlik durumu:** Bu, bağımsız olarak denetlenmemiş bir MVP'dir; profesyonel olarak denetlenmiş bir mesajlaşma uygulamasının alternatifi değildir. Saf JavaScript FIPS 203 ML-KEM-768 katmanı, uygulamaya özgü deneysel bir ek savunmadır. Hassas kullanım öncesinde [SECURITY.md](SECURITY.md) ve [tehdit modelini](docs/THREAT-MODEL.md) okuyun.

## İçindekiler

- [Hızlı başlangıç](#hızlı-başlangıç)
- [Genel bakış](#genel-bakış)
- [Güven ve eş tanıştırma](#güven-ve-eş-tanıştırma)
- [Mesaj koruması](#mesaj-koruması)
- [Depolama, yedek ve gizlilik](#depolama-yedek-ve-gizlilik)
- [Bütünlük modeli](#bütünlük-modeli)
- [Belgeler](#belgeler)
- [Geliştirme](#geliştirme)
- [Lisans](#lisans)

## Hızlı başlangıç

### 1. Demoyu açın ve doğrulayın

**Demo URL'si için yer tutucu:** [https://example.invalid/kagetamga](https://example.invalid/kagetamga) <!-- Herkese açık KageTamga demo URL'siyle değiştirin. -->

Deponun ana kaynak sayfasını ayrıca güvendiğiniz bir yoldan açın ve uygulamanın gösterdiği iki tam özetten birini aşağıdaki statik derleme kartıyla karşılaştırın. Tarayıcı konsolu komutu, denetleyen bütünlük Service Worker'ına sabitlenmiş önbelleği yeniden özetletir; SHA-256 değerini hem küçük harfli onaltılık hem de dolgusuz Base64URL olarak yazdırır.

[![Current KageTamga SHA-256 build digest in hexadecimal and Base64URL](docs/build-digest.svg)](https://github.com/SeriousPassenger/KageTamga)

<!-- kagetamga-integrity-console:start -->
#### Dağıtılan derlemeyi tarayıcıda doğrulayın

KageTamga zorunlu ön denetimleri geçtikten sonra dağıtılan uygulamanın geliştirici konsolunu açın ve bu komutun tamamını yapıştırın:

```js
await (async () => {
  const registration = await navigator.serviceWorker.ready;
  const worker = navigator.serviceWorker.controller;
  const expectedScope = new URL(".", location.href).href;
  const expectedWorkerUrl = new URL("integrity-worker.js", expectedScope).href;
  if (registration.scope !== expectedScope || !worker || worker.scriptURL !== expectedWorkerUrl) {
    throw new Error("The expected KageTamga integrity worker does not control this page.");
  }
  if (registration.waiting) {
    throw new Error("A waiting integrity-worker update must be resolved before comparison.");
  }

  const channel = new MessageChannel();
  const result = await new Promise((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error("Integrity verification timed out.")), 10000);
    channel.port1.onmessage = ({ data }) => {
      clearTimeout(timeout);
      if (data?.ok && typeof data.buildDigest === "string") resolve(data.buildDigest);
      else reject(new Error(data?.error || "Integrity verification failed."));
    };
    worker.postMessage({ type: "VERIFY_PINNED_SHELL" }, [channel.port2]);
  });

  if (!/^[A-Za-z0-9_-]{43}$/.test(result)) {
    throw new Error("The worker returned a non-canonical SHA-256 digest.");
  }
  const padded = result.replaceAll("-", "+").replaceAll("_", "/").padEnd(44, "=");
  const binary = atob(padded);
  const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
  const canonical = btoa(String.fromCharCode(...bytes))
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/, "");
  if (bytes.length !== 32 || canonical !== result) {
    throw new Error("The worker returned a non-canonical SHA-256 digest.");
  }

  const output = Object.freeze({
    algorithm: "SHA-256",
    base64Url: result,
    hex: Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join(""),
  });
  console.log("KageTamga build digest (SHA-256, Base64URL unpadded):", output.base64Url);
  console.log("KageTamga build digest (SHA-256, lowercase hex):", output.hex);
  return output;
})()
```

Komut, geçerli uygulama yolunun tam `integrity-worker.js` denetleyicisini zorunlu kılar; Service Worker'dan sabitlenmiş manifesti ve önbelleği yeniden doğrulamasını ister; dönen 32 baytlık SHA-256 değerini denetler ve hem küçük harfli onaltılık hem de dolgusuz Base64URL gösterimlerini yazdırıp döndürür. Tam değerlerden birini, deponun ana kaynak sayfasını ayrı bir yoldan açarak yukarıdaki statik özet kartıyla karşılaştırın.

> Bu, yerel sabitlenmiş uygulama kabuğu tutarlılık denetimidir; bağımsız ve güven gerektirmeyen bir kanıt değildir. İlk teslim, sonraki Service Worker güncellemeleri, GitHub, derleme ortamı, tarayıcı ve uç cihaz güven sınırı olmaya devam eder.
<!-- kagetamga-integrity-console:end -->

### 2. Kendi statik derlemenizi yayımlayın

Gereksinimler: Node.js 22 veya üzeri, npm, HTTPS sunan bir statik barındırma hizmeti; uygulama arka ucu gerekmez.

```bash
git clone https://github.com/SeriousPassenger/KageTamga.git
cd KageTamga
npm ci
npm run build
```

`dist/` içeriğini kök dizinde veya bir statik site alt yolunda yayımlayın. Üretilen dosyaları daha sonra değiştirmeyin, küçültmeyin, içerik eklemeyin veya dönüştürmeyin. Birlikte gelen `_headers` dosyası, bu biçimi destekleyen hizmetlerde tercih edilen güvenlik politikasını uygular. Sabitlenmiş tarayıcı Service Worker'ı da ilk kullanımda tek korumalı yeniden yüklemeden sonra doğrulanmış uygulamayı zorunlu CSP ve çapraz köken izolasyon başlıklarıyla sunar. Ayrıntılar [dağıtım kılavuzunda](docs/DEPLOYMENT.md).

### 3. Yerelde çalıştırın

```bash
git clone https://github.com/SeriousPassenger/KageTamga.git
cd KageTamga
npm ci
npm run dev
```

Gösterilen localhost adresini iki ayrı tarayıcı profilinde açın. Her tarayıcı bir kimlik oluşturur veya içe aktarır, aynı oda bağlantısını açar ve ilk şifreli offer/answer kodlarını elle değiştirir. `npm run dev`, dağıtımda kullanılan aynı bütünlük-sabitlenmiş statik paketi derler ve önizler.

## Genel bakış

KageTamga arka uçsuz, küçük gruplara yönelik bir mesajlaşma uygulamasıdır. Sohbet şifreli metni WebRTC veri kanallarından doğrudan tarayıcılar arasında gider. İlk iki katılımcı, oda anahtarıyla şifrelenmiş WebRTC offer/answer kodlarını zaten kullandıkları herhangi bir kanaldan değiştirir. Güvenilen eşler bağlandıktan sonra, yeni katılımcının bağımsız imzasını ve her aktarıcının ikinci imzasını içeren tanıştırmaları mevcut P2P örgüsü üzerinden, yalnızca o yeni parmak izine önceden bağımsız güvenen tarayıcılara iletebilir.

Uygulama sinyalleşme sunucusu, hesap, merkezî konuşma kaydı, çevrimdışı posta kutusu, çalışma zamanı CDN'i, analiz SDK'sı veya zorunlu aktarım hizmeti yoktur. Ağ yolu keşfi için yapılandırılabilir herkese açık STUN uç noktaları varsayılandır. Kullanıcı bunları değiştirebilir, TURN bilgisi ekleyebilir veya yalnızca LAN adayları için listeyi boş bırakabilir. STUN ve TURN oda üyesi bulmaz ve offer/answer sinyalleşmesinin yerini tutmaz.

Başlıca özellikler:

- Yaklaşık 2–8 eş için tam örgülü WebRTC mesajlaşması.
- Sertifika içindeki bütün alt anahtarlar dahil yalnızca Ed25519 imzalama ve X25519 şifrelemeye izin veren OpenPGP v4 kimlikleri.
- Her imzalı oda kimliğine bağlanan zorunlu FIPS 203 ML-KEM-768 anahtar çifti.
- Tam 40 onaltılık parmak izi, QR gösterimi, kopyalama ve bağımsız karşılaştırma yönlendirmesi.
- Oda oluşturmadan önce yönetilebilen, kimlik sahibi tarafından imzalanmış, köken kapsamlı kalıcı güven listesi.
- İngilizce, Almanca, Japonca, Türkçe, İspanyolca, Fransızca, Basitleştirilmiş ve Geleneksel Çince.
- Uygulama, oda ve tek mesaj düzeyinde isteğe bağlı ve hassas alanları gizlenmiş geliştirici JSON'u.

## Güven ve eş tanıştırma

Güven yerel, yönlü ve geçişsizdir. Geçerli imza yalnızca anahtara sahip olunduğunu kanıtlar; anahtarı kullanan kişinin kim olduğunu kanıtlamaz.

1. Kullanıcı oda oluşturmadan veya odaya katılmadan önce kalıcı güvenilen parmak izi listesini görür. Tam açık anahtarı alıp 40 haneli parmak izini bağımsız kanaldan karşılaştırarak kişi ekleyebilir.
2. İlk bağlantı elle değiştirilen şifreli offer ve answer kullanır. Tam SDP ve imzalı kimlik bildirimi, kaynak eşin anahtarıyla imzalanır.
3. Bir eş, yalnızca tam parmak izi alıcının kalıcı ve yerel sahip imzalı güven listesinde bulunuyorsa aktarıcı olabilir.
4. Tanıştırılan kaynak parmak izi de her alıcı/ara tarayıcının kendi kalıcı güven listesinde önceden bulunmalıdır. Aktarıcının güveni devredilmez.
5. Aktarılan tanıştırma; yeni eşin imzalı kimliğini veya hedefe imzalı SDP'sini ve doğrudan aktarıcının oda, hedef, atlama sayısı, tek kullanımlık değer ve zamana bağlı yeni imzasını içerir. Her sonraki atlama kendi dış imzasını üretir.
6. İmzasız, geçersiz, eski, yinelenmiş veya kalıcı olarak güvenilmeyen kurulum bağlantı işlemi öncesinde düşürülür. Sohbette reddedilen doğrudan aktarıcı veya tanıştırılan kaynak parmak izini gösteren kırmızı hata oluşur. Güvenilmeyen sonraki atlama ya da kaynak için iletim istenen eş de yerel hatayı kaydeder ve iletmez.

Bir alıcının önceden güvenmediği katılımcı, bağımsız doğrulama için o alıcıya elle bağlanmalı veya ayrı yoldan elde edilen açık anahtarla kalıcı listeye eklenmelidir. Geçerli imzalar anahtar sahipliğini kanıtlar; güven oluşturmaz.

Aynı geçerli parmak izini sunan birden fazla aktarım oturumu tek kimlik olarak görünür. En yeni etkin imzalı bildirim güncel adı belirler; çevrimiçi oturum çevrimdışı kopyadan üstündür. Adları aynı olsa bile farklı parmak izleri birleşmez. Çevrimdışı ve yok sayılan kimlikler ayrı açılır listede daraltılır.

## Mesaj koruması

Her mesaj sürümlü `OpenPGP-Curve25519+ML-KEM-768/AES-256-GCM-v1` zarfını kullanır:

1. OpenPGP.js düz metni Ed25519 ile imzalar; gönderene ve yerel olarak güvenilen X25519 alıcılarına şifreler.
2. Tarayıcı her mesaj için yeni rastgele AES-256-GCM içerik anahtarı üretir ve imzalı OpenPGP şifreli metnini bununla şifreler.
3. Seçilen her alıcı için ML-KEM-768 kapsülleme ve HKDF-SHA-512, içerik anahtarını sarmalayan alıcıya özel AES anahtarı türetir.
4. İmzalı teslim manifestosu tam dış zarfı, mesajı, göndereni, odayı, zamanı ve sıralanmış alıcı parmak izlerini bağlar.

İçerik anahtarı açık gönderilmez ve paylaşılan oda mesaj anahtarı yoktur. Katılma, ayrılma, yok sayma veya güven değişikliği daha sonraki mesajların seçilen alıcılarını değiştirir; küresel AES anahtarı döndürmez. Bu Signal Double Ratchet değildir; uygulama düzeyinde ileri gizlilik veya ele geçirme sonrası güvenlik iddiası yoktur.

Yerel olarak güvenilmeyen bir göndericinin geçerli imzalı mesajı, yalnızca gönderici kullanıcıyı alıcı seçtiyse çözülebilir ve parmak izi doğrulanana kadar kırmızı gösterilir. Gönderici kullanıcının anahtarına güvenmediyse içerik anahtarı o kullanıcı için sarılmaz; yalnızca şifreli zarf ve teslim manifestosu görünür.

## Depolama, yedek ve gizlilik

- Özel anahtarlar, imzalı güven kayıtları ve şifreli mesaj kayıtları kullanıcı silene kadar köken kapsamlı IndexedDB'de kalır.
- Sohbet düz metni yalnızca açık sayfa durumundadır. Diğer katılımcılar kendi kopyalarını saklayabilir; yerel silme başka cihazı silemez.
- Rastgele 256 bit oda yeteneği URL'de `#room=` sonrasında kalır; normal HTTP isteğine eklenmez. Tam bağlantıyı alan herkes bağlantı kurmayı deneyebilir; bağlantı kimlik kanıtı değildir.
- `adınız.kagetamga.json`, kimlik açıldıktan sonra her an indirilebilir. Şifreli yük; eksiksiz OpenPGP kimliği, parola korumalı ML-KEM sırrı, iptal sertifikası ve kimlik sahibi tarafından imzalı kalıcı güven listesini içerir. Kimlik/güven yükü, açılmış ML-KEM sırrından türetilen anahtarla AES-256-GCM kullanılarak şifrelenir; ML-KEM sırrı geri yüklemede parola korumalı kalır.
- ICE uç noktaları ve TURN bilgileri yalnızca sekme belleğindedir ve yedeklenmez.
- Doğrudan WebRTC eşleri genellikle birbirlerinin ağ adresini öğrenir. STUN işletmecisi adres/zaman üst verisini; TURN işletmecisi ayrıca zaten şifreli paket trafiğini görebilir.

## Bütünlük modeli

Üretim JavaScript'i, CSS'i, kriptografi kütüphaneleri ve lisansları çalışma zamanı CDN'i olmadan yerel olarak paketlenir. Derleme her HTML/JavaScript/CSS dosyasını özetler, kabuk özetini `integrity-worker.js` içine damgalar, damgalanmış Service Worker'ı da özetler ve kanonik haritayı `integrity-manifest.json` olarak yayımlar. Service Worker yalnızca tüm özetler eşleşirse derlemeye özel önbelleği kurar ve uygulama yolu içindeki sabitlenmemiş bütün istekleri reddeder.

Bu ilk kullanımda güven modelidir; bağımsız kanıt değildir. Kötü niyetli ilk yanıt veya Service Worker güncellemesi, ele geçirilmiş kaynak/derleme hesabı, zararlı eklenti, tarayıcı açığı, kötü amaçlı yazılım veya kilidi açık uç cihaz sırları yakalayabilir. Tam derleme özetini ayrı yoldan açılan depo görünümüyle karşılaştırın ve [tehdit modelini](docs/THREAT-MODEL.md) okuyun.

## Belgeler

| Belge | Kapsam |
| --- | --- |
| [Kullanıcı kılavuzu](docs/USER-GUIDE.md) | Kimlik, oda öncesi güven, elle bağlantı, eş durumları, yedek, silme ve geliştirici modu |
| [Mimari](docs/ARCHITECTURE.md) | Statik teslim, tarayıcı örgüsü, çift imzalı tanıştırma, mesaj şifreleme, depolama ve veri görünürlüğü |
| [Tehdit modeli](docs/THREAT-MODEL.md) | Güven sınırları, saldırgan yetenekleri, güvenceler, kapsam dışı durumlar ve kısıtlar |
| [Dağıtım kılavuzu](docs/DEPLOYMENT.md) | Genel statik barındırma, güvenlik başlıkları, bütünlük doğrulaması ve sürüm denetimleri |
| [Güvenlik politikası](SECURITY.md) | Özel güvenlik açığı bildirimi ve yüksek öncelikli inceleme alanları |
| [Katkı kılavuzu](CONTRIBUTING.md) | Testler ile gizlilik, kriptografi, protokol ve ön yüz değişmezleri |
| [Üçüncü taraf bildirimleri](THIRD_PARTY_NOTICES.md) | Paketleme, atıf ve eksiksiz üretim lisansı oluşturma |

Teknik belgeler şu anda İngilizcedir; uygulama arayüzünün Türkçe çevirisi kaynak kodunda tamdır.

## Geliştirme

```bash
npm ci
npm run typecheck
npm test
npm run build
npm run check
```

`npm run check`; katı TypeScript'i, tüm testleri, üretim derlemesini, üretim lisanslarını, integrity-worker damgasını, manifesti, güvenlik derleme doğrulamasını ve statik özet kartını üretir. CI ayrıca bağımlılıkları denetler, README konsol komutuyla özet kartını doğrular ve `integrity-manifest.json` dosyasını derleme özetinin küçük harfli onaltılık adıyla yükler.

Kriptografi, imzalı alanlar, kalıcı güven, eş tanıştırma, tarayıcı depolaması, bütünlük kontrolleri, çeviriler, ICE davranışı veya güvenlik başlıklarını değiştirmeden önce [CONTRIBUTING.md](CONTRIBUTING.md) dosyasını okuyun.

## Lisans

[MIT](LICENSE) © 2026 SeriousPassenger <seriouspassenger@proton.me>
