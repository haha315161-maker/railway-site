# Railway Deployment

## 1. Railway değişkenleri
Railway projesinde **Variables** bölümüne şunları ekleyin:

- `NODE_ENV=production`
- `SESSION_SECRET` = uzun ve rastgele bir değer
- `ADMIN_EMAIL` = admin olacak hesabın e-posta adresi
- `EMAIL_USER` = Gmail adresi
- `EMAIL_PASS` = Gmail App Password

`.env` dosyası deploy paketine dahil edilmez.

## 2. Deploy
Proje kökünde `package.json` bulunduğu için Railway `npm install`/`npm ci` ve `npm start` akışını kullanabilir. `railway.toml` başlangıç komutunu ve `/api/health` sağlık kontrolünü tanımlar.

## 3. SQLite kalıcılığı (önerilir)
Railway'de bir **Volume** oluşturup `/data` yoluna bağlayın ve şu değişkeni ekleyin:

`DATABASE_PATH=/data/database.db`

Volume olmadan SQLite dosyası servis yeniden oluşturulduğunda/deploy edildiğinde kalıcı olmayabilir.

## 4. Admin
`ADMIN_EMAIL` ile aynı e-posta adresine sahip normal kullanıcı admin olarak kabul edilir. İlk deploy sonrasında bu e-posta ile kayıt olun/giriş yapın ve `/admin.html` adresine gidin.

## 5. Not
`node_modules` ve `.git` deploy paketinden çıkarıldı; Railway bağımlılıkları `package-lock.json` üzerinden kendisi kurmalıdır.
