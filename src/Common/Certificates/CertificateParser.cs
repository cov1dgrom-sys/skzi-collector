using System;
using System.Collections.Generic;
using System.Globalization;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;

namespace Skzi.Common.Certificates
{
	/// <summary>
	/// Сведения о встроенной в сертификат лицензии КриптоПро CSP.
	/// </summary>
	public sealed class EmbeddedLicenseInfo
	{
		public bool IsPresent { get; set; }
		public string Version { get; set; }
		public string Details { get; set; }
	}

	/// <summary>
	/// Парсинг X.509-сертификатов: серийный номер, владелец, УЦ, реквизиты (ИНН, СНИЛС, ОГРН),
	/// алгоритмы (включая ГОСТ) и встроенная лицензия КриптоПро CSP.
	/// </summary>
	public static class CertificateParser
	{
		/// <summary>OID расширения «Ограниченная лицензия КРИПТО-ПРО» (встроенная лицензия CSP).</summary>
		public const string CryptoProEmbeddedLicenseOid = "1.2.643.2.2.49.2";

		/// <summary>Ветка OID КриптоПро, относящаяся к лицензированию.</summary>
		public const string CryptoProLicenseOidArc = "1.2.643.2.2.49.";

		/// <summary>Текст для случая, когда лицензия есть, но версию определить не удалось.</summary>
		public const string UnknownLicenseVersion = "не определена";

		private static readonly Dictionary<string, string> AttributeShortNames = new Dictionary<string, string>
		{
			{ "2.5.4.3", "CN" },
			{ "2.5.4.4", "SN" },
			{ "2.5.4.42", "G" },
			{ "2.5.4.43", "I" },
			{ "2.5.4.5", "SERIALNUMBER" },
			{ "2.5.4.6", "C" },
			{ "2.5.4.7", "L" },
			{ "2.5.4.8", "S" },
			{ "2.5.4.9", "STREET" },
			{ "2.5.4.10", "O" },
			{ "2.5.4.11", "OU" },
			{ "2.5.4.12", "T" },
			{ "1.2.840.113549.1.9.1", "E" },
			{ "0.9.2342.19200300.100.1.25", "DC" },
			{ "0.9.2342.19200300.100.1.1", "UID" },
			{ "1.2.643.3.131.1.1", "ИНН" },
			{ "1.2.643.100.4", "ИНН ЮЛ" },
			{ "1.2.643.100.1", "ОГРН" },
			{ "1.2.643.100.5", "ОГРНИП" },
			{ "1.2.643.100.3", "СНИЛС" }
		};

		private static readonly Dictionary<string, string> AlgorithmNames = new Dictionary<string, string>
		{
			{ "1.2.643.7.1.1.3.2", "ГОСТ Р 34.11-2012/34.10-2012 (256 бит)" },
			{ "1.2.643.7.1.1.3.3", "ГОСТ Р 34.11-2012/34.10-2012 (512 бит)" },
			{ "1.2.643.2.2.3", "ГОСТ Р 34.11-94/34.10-2001" },
			{ "1.2.643.2.2.4", "ГОСТ Р 34.11-94/34.10-94" },
			{ "1.2.643.7.1.1.1.1", "ГОСТ Р 34.10-2012 (256 бит)" },
			{ "1.2.643.7.1.1.1.2", "ГОСТ Р 34.10-2012 (512 бит)" },
			{ "1.2.643.2.2.19", "ГОСТ Р 34.10-2001" },
			{ "1.2.643.2.2.20", "ГОСТ Р 34.10-94" },
			{ "1.2.840.113549.1.1.1", "RSA" },
			{ "1.2.840.113549.1.1.5", "sha1RSA" },
			{ "1.2.840.113549.1.1.11", "sha256RSA" },
			{ "1.2.840.113549.1.1.12", "sha384RSA" },
			{ "1.2.840.113549.1.1.13", "sha512RSA" },
			{ "1.2.840.10045.2.1", "ECC" },
			{ "1.2.840.10045.4.3.2", "sha256ECDSA" },
			{ "1.2.840.10045.4.3.3", "sha384ECDSA" }
		};

		// Серийный номер (ключ) КриптоПро CSP: 5 групп по 5 символов, первые 4 цифры кодируют версию: 5050… → 5.0, 4040… → 4.0.
		private static readonly Regex LicenseKeyRegex = new Regex(
			@"(?<![0-9A-Z])(?<major>\d)(?<minor>\d)\k<major>\k<minor>[0-9A-Z]-[0-9A-Z]{5}-[0-9A-Z]{5}-[0-9A-Z]{5}-[0-9A-Z]{5}(?![0-9A-Z])",
			RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

		// Явное указание версии рядом с ключевым словом: «CSP 5.0», «версия 4.0», «version 5.0».
		private static readonly Regex ExplicitVersionRegex = new Regex(
			@"(?:CSP|ЦСП|верси[яи]|version|ver\.?)\s*[:№]?\s*(?<version>\d\.\d{1,2})",
			RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

		// Любая версия вида X.Y — используется только если в тексте явно упоминается КриптоПро.
		private static readonly Regex LooseVersionRegex = new Regex(
			@"(?<![\d.])(?<version>[2-9]\.\d)(?![\d])",
			RegexOptions.CultureInvariant);

		private static readonly Regex CryptoProMentionRegex = new Regex(
			@"crypto-?pro|криптопро|крипто-про",
			RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

		/// <summary>
		/// Разбирает сертификат и возвращает запись со всеми извлечёнными полями.
		/// </summary>
		public static CertificateRecord Parse(X509Certificate2 certificate)
		{
			if (certificate == null)
			{
				throw new ArgumentNullException("certificate");
			}

			CertificateRecord record = new CertificateRecord();
			record.SerialNumber = NormalizeSerialNumber(certificate.SerialNumber);
			record.Thumbprint = (certificate.Thumbprint ?? string.Empty).ToUpperInvariant();
			record.ValidFrom = certificate.NotBefore;
			record.ValidTo = certificate.NotAfter;

			List<KeyValuePair<string, string>> subjectAttributes = DecodeDistinguishedNameSafe(certificate.SubjectName.RawData);
			List<KeyValuePair<string, string>> issuerAttributes = DecodeDistinguishedNameSafe(certificate.IssuerName.RawData);

			record.SubjectDn = subjectAttributes.Count > 0 ? FormatDistinguishedName(subjectAttributes) : certificate.Subject;
			record.IssuerDn = issuerAttributes.Count > 0 ? FormatDistinguishedName(issuerAttributes) : certificate.Issuer;

			record.OwnerName = BuildOwnerName(subjectAttributes, certificate);
			record.OwnerOrganization = FindAttribute(subjectAttributes, "2.5.4.10");
			record.OwnerTitle = FindAttribute(subjectAttributes, "2.5.4.12");
			record.OwnerEmail = FindAttribute(subjectAttributes, "1.2.840.113549.1.9.1");
			record.OwnerSnils = FindAttribute(subjectAttributes, "1.2.643.100.3");
			record.OwnerInn = FirstNotEmpty(FindAttribute(subjectAttributes, "1.2.643.3.131.1.1"), FindAttribute(subjectAttributes, "1.2.643.100.4"));
			record.OwnerOgrn = FirstNotEmpty(FindAttribute(subjectAttributes, "1.2.643.100.1"), FindAttribute(subjectAttributes, "1.2.643.100.5"));

			// Удостоверяющий центр — полное имя издателя (записывается полностью), например
			// «CN=Иванов Иван Иванович, OU=Dev, O=MyCompany, L=Moscow, C=RU».
			record.CertificationAuthority = FirstNotEmpty(
				record.IssuerDn,
				certificate.GetNameInfo(X509NameType.SimpleName, true),
				certificate.Issuer);

			record.SignatureAlgorithm = GetAlgorithmDisplayName(
				certificate.SignatureAlgorithm == null ? null : certificate.SignatureAlgorithm.Value,
				certificate.SignatureAlgorithm == null ? null : certificate.SignatureAlgorithm.FriendlyName);
			record.PublicKeyAlgorithm = GetAlgorithmDisplayName(SafeGetKeyAlgorithm(certificate), null);

			EmbeddedLicenseInfo license = DetectEmbeddedLicense(certificate);
			record.HasEmbeddedCryptoProLicense = license.IsPresent;
			record.CryptoProLicenseVersion = license.IsPresent ? license.Version : null;
			record.CryptoProLicenseDetails = license.Details;

			record.HasPrivateKey = SafeHasPrivateKey(certificate);
			return record;
		}

		/// <summary>
		/// Приводит серийный номер к единому виду: HEX в верхнем регистре без пробелов и разделителей.
		/// </summary>
		public static string NormalizeSerialNumber(string serialNumber)
		{
			if (string.IsNullOrEmpty(serialNumber))
			{
				return string.Empty;
			}
			StringBuilder builder = new StringBuilder(serialNumber.Length);
			foreach (char symbol in serialNumber)
			{
				if (Uri.IsHexDigit(symbol))
				{
					builder.Append(char.ToUpperInvariant(symbol));
				}
			}
			return builder.ToString();
		}

		/// <summary>
		/// Ищет в сертификате расширение встроенной лицензии КриптоПро и пытается определить её версию.
		/// </summary>
		public static EmbeddedLicenseInfo DetectEmbeddedLicense(X509Certificate2 certificate)
		{
			EmbeddedLicenseInfo info = new EmbeddedLicenseInfo();
			foreach (X509Extension extension in certificate.Extensions)
			{
				string oid = extension.Oid == null ? null : extension.Oid.Value;
				if (oid == null)
				{
					continue;
				}
				bool isLicenseExtension = oid == CryptoProEmbeddedLicenseOid || oid.StartsWith(CryptoProLicenseOidArc, StringComparison.Ordinal);
				if (!isLicenseExtension)
				{
					continue;
				}

				info.IsPresent = true;
				List<string> texts = ExtractTexts(extension.RawData);
				string version = ExtractCryptoProVersion(texts);
				if (version != null)
				{
					info.Version = version;
				}
				info.Details = BuildLicenseDetails(oid, texts);
			}

			if (info.IsPresent && info.Version == null)
			{
				info.Version = UnknownLicenseVersion;
			}
			return info;
		}

		/// <summary>
		/// Определяет версию КриптоПро CSP по набору строк: сначала по серийному ключу (5050… → 5.0),
		/// затем по явному упоминанию версии, затем по любому «X.Y» рядом с упоминанием КриптоПро.
		/// Возвращает null, если версия не найдена.
		/// </summary>
		public static string ExtractCryptoProVersion(IEnumerable<string> texts)
		{
			if (texts == null)
			{
				return null;
			}
			string joinedText = string.Join(" ", texts);
			if (joinedText.Length == 0)
			{
				return null;
			}

			Match keyMatch = LicenseKeyRegex.Match(joinedText);
			if (keyMatch.Success)
			{
				return keyMatch.Groups["major"].Value + "." + keyMatch.Groups["minor"].Value;
			}

			Match explicitMatch = ExplicitVersionRegex.Match(joinedText);
			if (explicitMatch.Success)
			{
				return explicitMatch.Groups["version"].Value;
			}

			if (CryptoProMentionRegex.IsMatch(joinedText))
			{
				Match looseMatch = LooseVersionRegex.Match(joinedText);
				if (looseMatch.Success)
				{
					return looseMatch.Groups["version"].Value;
				}
			}
			return null;
		}

		/// <summary>
		/// Маскирует серийные ключи КриптоПро в тексте, оставляя первую и последнюю группы.
		/// </summary>
		public static string MaskLicenseKeys(string text)
		{
			if (string.IsNullOrEmpty(text))
			{
				return text;
			}
			return LicenseKeyRegex.Replace(text, delegate (Match match)
			{
				string[] groups = match.Value.Split('-');
				return groups[0] + "-*****-*****-*****-" + groups[groups.Length - 1];
			});
		}

		/// <summary>
		/// Извлекает все текстовые строки из DER-значения расширения; при ошибке разбора берёт печатные фрагменты.
		/// </summary>
		private static List<string> ExtractTexts(byte[] rawData)
		{
			List<string> texts = new List<string>();
			if (rawData == null || rawData.Length == 0)
			{
				return texts;
			}
			Asn1Node root = Asn1Node.TryParseExact(rawData);
			if (root != null)
			{
				root.CollectStrings(texts, 0);
			}
			if (texts.Count == 0)
			{
				texts.AddRange(ExtractPrintableRuns(rawData, 4));
			}
			return texts;
		}

		/// <summary>
		/// Выделяет из бинарных данных последовательности печатных ASCII-символов заданной минимальной длины.
		/// </summary>
		private static List<string> ExtractPrintableRuns(byte[] data, int minimumLength)
		{
			List<string> runs = new List<string>();
			StringBuilder current = new StringBuilder();
			foreach (byte currentByte in data)
			{
				if (currentByte >= 0x20 && currentByte < 0x7F)
				{
					current.Append((char)currentByte);
				}
				else
				{
					if (current.Length >= minimumLength)
					{
						runs.Add(current.ToString());
					}
					current.Length = 0;
				}
			}
			if (current.Length >= minimumLength)
			{
				runs.Add(current.ToString());
			}
			return runs;
		}

		/// <summary>
		/// Формирует текст с подробностями лицензии для журнала/БД (ключи маскируются).
		/// </summary>
		private static string BuildLicenseDetails(string oid, List<string> texts)
		{
			StringBuilder builder = new StringBuilder();
			builder.Append("OID ").Append(oid);
			if (texts.Count > 0)
			{
				builder.Append(": ").Append(MaskLicenseKeys(string.Join(" | ", texts)));
			}
			string details = builder.ToString();
			return details.Length > 1000 ? details.Substring(0, 1000) : details;
		}

		/// <summary>
		/// Декодирует DN из DER (последовательность пар OID → значение) без выбрасывания исключений.
		/// </summary>
		private static List<KeyValuePair<string, string>> DecodeDistinguishedNameSafe(byte[] rawName)
		{
			try
			{
				return DecodeDistinguishedName(rawName);
			}
			catch (FormatException)
			{
				return new List<KeyValuePair<string, string>>();
			}
		}

		/// <summary>
		/// Декодирует DN из DER: Name ::= SEQUENCE OF SET OF SEQUENCE { OID, значение }.
		/// Порядок сохраняется как в сертификате (от общего к частному).
		/// </summary>
		public static List<KeyValuePair<string, string>> DecodeDistinguishedName(byte[] rawName)
		{
			List<KeyValuePair<string, string>> attributes = new List<KeyValuePair<string, string>>();
			if (rawName == null || rawName.Length == 0)
			{
				return attributes;
			}
			Asn1Node nameNode = Asn1Node.Parse(rawName);
			foreach (Asn1Node relativeName in nameNode.Children)
			{
				foreach (Asn1Node attribute in relativeName.Children)
				{
					if (attribute.Children.Count < 2)
					{
						continue;
					}
					string oid = attribute.Children[0].ReadObjectIdentifier();
					string value = attribute.Children[1].ReadString();
					if (oid != null && value != null)
					{
						attributes.Add(new KeyValuePair<string, string>(oid, value.Trim()));
					}
				}
			}
			return attributes;
		}

		/// <summary>
		/// Формирует читаемую строку DN в привычном порядке (CN первым) с русскими названиями реквизитов.
		/// </summary>
		public static string FormatDistinguishedName(List<KeyValuePair<string, string>> attributes)
		{
			List<string> parts = new List<string>();
			for (int index = attributes.Count - 1; index >= 0; index--)
			{
				string shortName;
				if (!AttributeShortNames.TryGetValue(attributes[index].Key, out shortName))
				{
					shortName = "OID." + attributes[index].Key;
				}
				string value = attributes[index].Value;
				if (value.IndexOfAny(new[] { ',', '+', '=', '"' }) >= 0)
				{
					value = "\"" + value.Replace("\"", "\"\"") + "\"";
				}
				parts.Add(shortName + "=" + value);
			}
			return string.Join(", ", parts);
		}

		/// <summary>
		/// Возвращает русское/понятное название алгоритма по OID (для ГОСТ), иначе дружественное имя или сам OID.
		/// </summary>
		public static string GetAlgorithmDisplayName(string oid, string friendlyName)
		{
			string knownName;
			if (oid != null && AlgorithmNames.TryGetValue(oid, out knownName))
			{
				return knownName;
			}
			if (!string.IsNullOrWhiteSpace(friendlyName) && friendlyName != oid)
			{
				return friendlyName;
			}
			return oid;
		}

		/// <summary>
		/// Составляет имя владельца: «Фамилия Имя Отчество» из SN и G, иначе CN, иначе простое имя сертификата.
		/// </summary>
		private static string BuildOwnerName(List<KeyValuePair<string, string>> subjectAttributes, X509Certificate2 certificate)
		{
			string surname = FindAttribute(subjectAttributes, "2.5.4.4");
			string givenName = FindAttribute(subjectAttributes, "2.5.4.42");
			if (!string.IsNullOrWhiteSpace(surname) && !string.IsNullOrWhiteSpace(givenName))
			{
				return surname + " " + givenName;
			}
			return FirstNotEmpty(
				FindAttribute(subjectAttributes, "2.5.4.3"),
				surname,
				FindAttribute(subjectAttributes, "2.5.4.10"),
				certificate.GetNameInfo(X509NameType.SimpleName, false),
				certificate.Subject);
		}

		/// <summary>
		/// Ищет первое значение атрибута DN по OID.
		/// </summary>
		private static string FindAttribute(List<KeyValuePair<string, string>> attributes, string oid)
		{
			foreach (KeyValuePair<string, string> attribute in attributes)
			{
				if (attribute.Key == oid && !string.IsNullOrWhiteSpace(attribute.Value))
				{
					return attribute.Value;
				}
			}
			return null;
		}

		/// <summary>
		/// Возвращает первое непустое значение из списка.
		/// </summary>
		private static string FirstNotEmpty(params string[] values)
		{
			foreach (string value in values)
			{
				if (!string.IsNullOrWhiteSpace(value))
				{
					return value.Trim();
				}
			}
			return null;
		}

		/// <summary>
		/// Безопасно получает OID алгоритма открытого ключа (без обращения к криптопровайдеру).
		/// </summary>
		private static string SafeGetKeyAlgorithm(X509Certificate2 certificate)
		{
			try
			{
				return certificate.GetKeyAlgorithm();
			}
			catch (Exception)
			{
				return null;
			}
		}

		/// <summary>
		/// Безопасно проверяет наличие привязки к закрытому ключу.
		/// </summary>
		private static bool SafeHasPrivateKey(X509Certificate2 certificate)
		{
			try
			{
				return certificate.HasPrivateKey;
			}
			catch (Exception)
			{
				return false;
			}
		}

		/// <summary>
		/// Форматирует дату для журналов и отчётов.
		/// </summary>
		public static string FormatDate(DateTime value)
		{
			return value.ToString("dd.MM.yyyy HH:mm", CultureInfo.InvariantCulture);
		}
	}
}
