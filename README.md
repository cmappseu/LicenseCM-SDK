# LicenseCM SDK'lar

LicenseCM lisans yönetim sistemi için çoklu platform SDK desteği.

## Desteklenen Diller

| Dil | Klasör | Durum |
|-----|--------|-------|
| Node.js | `/nodejs` | ✅ Hazır |
| Python | `/python` | ✅ Hazır |
| C# (.NET) | `/csharp` | ✅ Hazır |
| Go | `/go` | ✅ Hazır |
| Java | `/java` | ✅ Hazır |
| PHP | `/php` | ✅ Hazır |
| Rust | `/rust` | ✅ Hazır |
| Ruby | `/ruby` | ✅ Hazır |
| Lua | `/lua` | ✅ Hazır |
| C++ | `/cpp` | ✅ Hazır |
| Kotlin | `/kotlin` | ✅ Hazır |
| Swift | `/swift` | ✅ Hazır |
| Delphi/Pascal | `/delphi` | ✅ Hazır |

## Özellikler

Tüm SDK'lar aşağıdaki özellikleri destekler:

- 🔐 **AES-256-GCM Şifreleme** - İstek/yanıt şifreleme
- 🔑 **HMAC-SHA256 İmzalama** - Request signing
- 🖥️ **HWID Üretimi** - Donanım tabanlı benzersiz ID
- 💓 **Otomatik Heartbeat** - Canlılık kontrolü
- 🛡️ **VM/Sandbox Algılama** - Sanal makine tespiti
- 🐛 **Debug Algılama** - Hata ayıklama tespiti
- 📊 **Oturum Yönetimi** - Token rotasyonu

## Hızlı Başlangıç

### Node.js

```javascript
const LicenseCM = require('./licensecm');

const client = new LicenseCM({
  baseUrl: 'https://license.cmapps.eu',
  productId: 'your-product-id',
  secretKey: 'your-secret-key',
  useEncryption: true
});

await client.initialize();
const result = await client.activate('XXXX-XXXX-XXXX-XXXX');
```

### Python

```python
from licensecm import LicenseCM

client = LicenseCM(
    base_url='https://license.cmapps.eu',
    product_id='your-product-id',
    secret_key='your-secret-key',
    use_encryption=True
)

client.initialize()
result = client.activate('XXXX-XXXX-XXXX-XXXX')
```

### C#

```csharp
using LicenseCM;

var client = new LicenseCMClient(
    "https://license.cmapps.eu",
    "your-product-id",
    "your-secret-key",
    useEncryption: true
);

await client.InitializeAsync();
var result = await client.ActivateAsync("XXXX-XXXX-XXXX-XXXX");
```

### Go

```go
import "github.com/licensecm/sdk-go"

client := licensecm.NewClient(
    "https://license.cmapps.eu",
    "your-product-id",
    "your-secret-key",
)
client.UseEncryption = true

client.Initialize()
result, err := client.Activate("XXXX-XXXX-XXXX-XXXX", "")
```

### Java

```java
import com.licensecm.LicenseCM;

LicenseCM client = new LicenseCM(
    "https://license.cmapps.eu",
    "your-product-id",
    "your-secret-key"
);
client.setUseEncryption(true);

client.initialize();
JSONObject result = client.activate("XXXX-XXXX-XXXX-XXXX", null);
```

### PHP

```php
use LicenseCM\LicenseCMClient;

$client = new LicenseCMClient(
    'https://license.cmapps.eu',
    'your-product-id',
    'your-secret-key'
);
$client->setUseEncryption(true);

$client->initialize();
$result = $client->activate('XXXX-XXXX-XXXX-XXXX');
```

### Rust

```rust
use licensecm::LicenseCMClient;

let mut client = LicenseCMClient::new(
    "https://license.cmapps.eu",
    "your-product-id",
    "your-secret-key",
);
client.set_use_encryption(true);

client.initialize().await?;
let result = client.activate("XXXX-XXXX-XXXX-XXXX", None).await?;
```

### Ruby

```ruby
require 'licensecm'

client = LicenseCM::Client.new(
  base_url: 'https://license.cmapps.eu',
  product_id: 'your-product-id',
  secret_key: 'your-secret-key'
)
client.use_encryption = true

client.initialize_client
result = client.activate('XXXX-XXXX-XXXX-XXXX')
```

### Kotlin

```kotlin
import com.licensecm.LicenseCMClient

val client = LicenseCMClient(
    "https://license.cmapps.eu",
    "your-product-id",
    "your-secret-key"
).apply {
    useEncryption = true
}

client.initialize()
val result = client.activate("XXXX-XXXX-XXXX-XXXX")
```

### Swift

```swift
import LicenseCM

let client = LicenseCMClient(
    baseUrl: "https://license.cmapps.eu",
    productId: "your-product-id",
    secretKey: "your-secret-key"
)
client.useEncryption = true

client.initialize { _ in
    client.activate(licenseKey: "XXXX-XXXX-XXXX-XXXX") { result in
        // Handle result
    }
}
```

### Delphi

```pascal
uses LicenseCM;

var
  Client: TLicenseCMClient;
begin
  Client := TLicenseCMClient.Create(nil);
  Client.BaseUrl := 'https://license.cmapps.eu';
  Client.ProductId := 'your-product-id';
  Client.SecretKey := 'your-secret-key';
  Client.UseEncryption := True;

  Client.Initialize;
  Client.Activate('XXXX-XXXX-XXXX-XXXX');
end;
```

## API Endpoints

SDK'lar aşağıdaki API endpoint'lerini kullanır:

| Endpoint | Açıklama |
|----------|----------|
| `POST /api/client/validate` | Lisans doğrulama |
| `POST /api/client/activate` | Lisans aktivasyonu |
| `POST /api/client/deactivate` | Lisans deaktivasyonu |
| `POST /api/client/heartbeat` | Canlılık kontrolü |
| `GET /api/client/public-key` | Public key alma |

## Güvenlik

### HWID Üretimi

Tüm SDK'lar aşağıdaki bileşenlerden HWID oluşturur:
- Platform/OS bilgisi
- CPU mimarisi
- Hostname
- MAC adresi
- Disk seri numarası (Windows)
- CPU sayısı

### VM/Sandbox Algılama

SDK'lar şüpheli ortamları tespit eder:
- VMware, VirtualBox, QEMU MAC prefix'leri
- Şüpheli hostname'ler
- Düşük CPU/RAM
- Timing anomalileri

## Lisans

MIT License
