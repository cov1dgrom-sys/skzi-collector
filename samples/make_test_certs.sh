#!/usr/bin/env bash
# Генерация тестовых открытых частей сертификатов для проверки модуля сбора данных о СКЗИ.
# Требуется OpenSSL 3.4+ (есть в Git for Windows). Запуск: bash samples/make_test_certs.sh
# Сертификаты RSA (ГОСТ требует движка gost), но с российскими реквизитами (ИНН, СНИЛС, ОГРН)
# и расширением встроенной лицензии КриптоПро CSP (OID 1.2.643.2.2.49.2).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUT="$SCRIPT_DIR/certs"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$OUT/Отдел кадров" "$OUT/archive/2024"

# Имена INN, SNILS, OGRN встроены в OpenSSL 3.x; ИНН ЮЛ — числовой OID 1.2.643.100.4
# (префикс «0.» обязателен: OpenSSL отрезает в имени поля DN всё до первой точки)
cat > "$WORK/openssl.cnf" <<'EOF'
[ req ]
distinguished_name = dn_empty
string_mask = utf8only
utf8 = yes
prompt = no
[ dn_empty ]
CN = placeholder

[ dn_ca ]
C = RU
ST = 66 Свердловская область
L = Екатеринбург
O = Тестовый удостоверяющий центр Red Flag
0.1.2.643.100.4 = 6600000001
OGRN = 1026600000001
CN = Тестовый УЦ Red Flag

[ dn_ivanov ]
C = RU
ST = 66 Свердловская область
L = Екатеринбург
O = ООО "Ромашка"
title = Генеральный директор
SN = Иванов
GN = Иван Иванович
CN = Иванов Иван Иванович
SNILS = 12345678901
INN = 667012345678
emailAddress = ivanov@romashka.test

[ dn_petrova ]
C = RU
L = Екатеринбург
SN = Петрова
GN = Анна Сергеевна
CN = Петрова Анна Сергеевна
SNILS = 98765432109
INN = 667098765432

[ dn_romashka ]
C = RU
L = Екатеринбург
O = ООО "Ромашка"
CN = ООО "Ромашка"
0.1.2.643.100.4 = 6670000123
OGRN = 1166600000123

[ dn_sidorov ]
C = RU
SN = Сидоров
GN = Пётр Олегович
CN = Сидоров Пётр Олегович
SNILS = 11122233344

[ dn_expired ]
C = RU
SN = Кузнецова
GN = Мария Павловна
CN = Кузнецова Мария Павловна
INN = 667011112222

[ ext_ca ]
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash

[ ext_user ]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment
extendedKeyUsage = clientAuth, emailProtection
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid

[ ext_user_license50 ]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment
extendedKeyUsage = clientAuth, emailProtection
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
1.2.643.2.2.49.2 = ASN1:SEQUENCE:license50
[ license50 ]
product = UTF8:КриптоПро CSP
serial = PRINTABLESTRING:50500-TEST0-00000-00000-00001

[ ext_user_license40 ]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
1.2.643.2.2.49.2 = ASN1:SEQUENCE:license40
[ license40 ]
product = UTF8:КриптоПро CSP
serial = PRINTABLESTRING:40400-TEST0-00000-00000-00002

[ ext_user_license_unknown ]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, nonRepudiation
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
1.2.643.2.2.49.2 = ASN1:UTF8:Ограниченная лицензия
EOF

export OPENSSL_CONF="$WORK/openssl.cnf"
CNF="$WORK/openssl.cnf"

# Создаёт копию конфигурации, где DN запроса берётся из секции $1, и печатает путь к ней
config_for_dn() {
	sed "s/^distinguished_name = dn_empty/distinguished_name = $1/" "$CNF" > "$WORK/cfg_$1.cnf"
	echo "$WORK/cfg_$1.cnf"
}

# Делает сертификат пользователя: $1 — имя, $2 — секция DN, $3 — секция расширений, $4.. — доп. параметры x509
make_user_cert() {
	local name="$1" dn="$2" ext="$3"
	shift 3
	openssl req -new -newkey rsa:2048 -nodes -keyout "$WORK/$name.key" -out "$WORK/$name.csr" -config "$(config_for_dn "$dn")" -utf8
	openssl x509 -req -in "$WORK/$name.csr" -CA "$WORK/ca.pem" -CAkey "$WORK/ca.key" -set_serial "0x$(openssl rand -hex 16)" \
		-extfile "$CNF" -extensions "$ext" -out "$WORK/$name.pem" "$@"
}

# Корневой сертификат тестового УЦ
openssl req -x509 -new -newkey rsa:2048 -nodes -keyout "$WORK/ca.key" -out "$WORK/ca.pem" -days 3650 \
	-config "$(config_for_dn dn_ca)" -extensions ext_ca -utf8 -set_serial 0x01A2B3C4D5E6F708
openssl x509 -in "$WORK/ca.pem" -outform DER -out "$OUT/root_ca_redflag.cer"

make_user_cert ivanov dn_ivanov ext_user_license50 -days 365
make_user_cert petrova dn_petrova ext_user -days 730
make_user_cert romashka dn_romashka ext_user_license40 -days 450
make_user_cert sidorov dn_sidorov ext_user_license_unknown -days 365
make_user_cert expired dn_expired ext_user -not_before 20230101000000Z -not_after 20240101000000Z

# 1) DER
openssl x509 -in "$WORK/ivanov.pem" -outform DER -out "$OUT/ivanov_ii.cer"
# 2) PEM в подпапке с кириллицей и пробелом
cp "$WORK/petrova.pem" "$OUT/Отдел кадров/petrova_as.crt"
# 3) PEM-цепочка (сертификат организации + корневой)
cat "$WORK/romashka.pem" "$WORK/ca.pem" > "$OUT/romashka_chain.pem"
# 4) Base64 без заголовков PEM
openssl x509 -in "$WORK/sidorov.pem" -outform DER | openssl base64 > "$OUT/sidorov_po_base64.cer"
# 5) PKCS#7 с двумя сертификатами (дубли — проверка устранения повторов)
openssl crl2pkcs7 -nocrl -certfile "$WORK/ivanov.pem" -certfile "$WORK/petrova.pem" -outform DER -out "$OUT/bundle.p7b"
# 6) Истёкший сертификат во вложенной папке
openssl x509 -in "$WORK/expired.pem" -outform DER -out "$OUT/archive/2024/kuznetsova_mp.cer"
# 7) Повреждённый файл и посторонний файл
printf 'это не сертификат\n' > "$OUT/broken.cer"
printf 'просто текст\n' > "$OUT/readme.txt"

# 8) PKCS#12 с паролем (отдельная папка, чтобы не менять состав samples/certs)
P12_DIR="$OUT/../pkcs12"
mkdir -p "$P12_DIR"
printf '[req]
distinguished_name=dn
prompt=no
utf8=yes
string_mask=utf8only
[dn]
C=RU
O=Команда Red Flag
CN=Тестов Тест Тестович
' > "$WORK/p12.cnf"
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$WORK/p12.key" -out "$WORK/p12.pem" -days 3650 -config "$WORK/p12.cnf" -utf8 -set_serial 0x7E57001
openssl pkcs12 -export -in "$WORK/p12.pem" -inkey "$WORK/p12.key" -name "testov_tt" -passout pass:RedFlag-2026 	-certpbe PBE-SHA1-3DES -keypbe PBE-SHA1-3DES -macalg sha1 -out "$P12_DIR/testov_tt.p12"

echo "Готово: $OUT"
ls -R "$OUT"
