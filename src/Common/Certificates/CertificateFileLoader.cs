using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;

namespace Skzi.Common.Certificates
{
	/// <summary>
	/// Файл PKCS#12 (.p12/.pfx) защищён паролем, и ни один из заданных оператором паролей не подошёл.
	/// </summary>
	public sealed class PasswordProtectedFileException : CryptographicException
	{
		/// <summary>
		/// Создаёт исключение с текстом для журнала и предупреждений.
		/// </summary>
		public PasswordProtectedFileException(string message)
			: base(message)
		{
		}
	}

	/// <summary>
	/// Загрузка открытых частей сертификатов из файлов: DER (.cer/.crt/.der), PEM/Base64 (в т.ч. несколько
	/// сертификатов в одном файле), PKCS#7 (.p7b/.p7c), PKCS#12 (.p12/.pfx — с паролем, заданным оператором)
	/// и сериализованные сертификаты из реестра Windows.
	/// </summary>
	public static class CertificateFileLoader
	{
		// Идентификатор свойства «закодированный сертификат» в сериализованном элементе хранилища (CERT_CERT_PROP_ID).
		private const int SerializedCertificatePropertyId = 32;

		// Идентификатор свойства «сведения о ключевом контейнере» (CERT_KEY_PROV_INFO_PROP_ID).
		private const int KeyProviderInfoPropertyId = 2;

		private static readonly Regex PemBlockRegex = new Regex(
			@"-----BEGIN (?<label>[A-Z0-9 #]+)-----(?<body>[A-Za-z0-9+/=\s]+?)-----END \k<label>-----",
			RegexOptions.CultureInvariant | RegexOptions.Singleline);

		/// <summary>
		/// Читает файл и возвращает все найденные в нём сертификаты. Бросает исключение, если файл не содержит сертификатов.
		/// </summary>
		public static List<X509Certificate2> LoadFromFile(string filePath)
		{
			return LoadFromFile(filePath, null);
		}

		/// <summary>
		/// Читает файл и возвращает все найденные в нём сертификаты; для PKCS#12 пробует указанные пароли.
		/// </summary>
		public static List<X509Certificate2> LoadFromFile(string filePath, IList<string> pkcs12Passwords)
		{
			byte[] content = File.ReadAllBytes(filePath);
			return LoadFromBytes(content, pkcs12Passwords);
		}

		/// <summary>
		/// Определяет формат данных (PEM, Base64, DER, PKCS#7) и загружает из них сертификаты.
		/// </summary>
		public static List<X509Certificate2> LoadFromBytes(byte[] content)
		{
			return LoadFromBytes(content, null);
		}

		/// <summary>
		/// Определяет формат данных (PEM, Base64, DER, PKCS#7, PKCS#12) и загружает из них сертификаты.
		/// </summary>
		public static List<X509Certificate2> LoadFromBytes(byte[] content, IList<string> pkcs12Passwords)
		{
			if (content == null || content.Length == 0)
			{
				throw new CryptographicException("Файл пуст");
			}

			if (IsPkcs12(content))
			{
				return LoadPkcs12(content, pkcs12Passwords);
			}

			List<X509Certificate2> certificates = new List<X509Certificate2>();
			string text = TryDecodeAsText(content);

			if (text != null && text.Contains("-----BEGIN"))
			{
				foreach (Match block in PemBlockRegex.Matches(text))
				{
					string label = block.Groups["label"].Value;
					if (label.IndexOf("CERTIFICATE", StringComparison.OrdinalIgnoreCase) < 0 && label.IndexOf("PKCS7", StringComparison.OrdinalIgnoreCase) < 0)
					{
						continue;
					}
					byte[] der = Convert.FromBase64String(RemoveWhitespace(block.Groups["body"].Value));
					certificates.AddRange(ImportBinary(der));
				}
				if (certificates.Count == 0)
				{
					throw new CryptographicException("PEM-файл не содержит блоков CERTIFICATE/PKCS7");
				}
				return certificates;
			}

			if (text != null && LooksLikeBase64(text))
			{
				byte[] der = Convert.FromBase64String(RemoveWhitespace(text));
				return ImportBinary(der);
			}

			return ImportBinary(content);
		}

		/// <summary>
		/// Загружает сертификат из сериализованного элемента хранилища Windows (значение Blob в реестре).
		/// Дополнительно сообщает, есть ли у сертификата привязка к закрытому ключу.
		/// </summary>
		public static X509Certificate2 LoadFromSerializedStoreElement(byte[] blob, out bool hasPrivateKeyLink)
		{
			hasPrivateKeyLink = false;
			byte[] encodedCertificate = null;
			int offset = 0;
			while (offset + 12 <= blob.Length)
			{
				int propertyId = BitConverter.ToInt32(blob, offset);
				int length = BitConverter.ToInt32(blob, offset + 8);
				offset = offset + 12;
				if (length < 0 || length > blob.Length - offset)
				{
					break;
				}
				if (propertyId == KeyProviderInfoPropertyId)
				{
					hasPrivateKeyLink = true;
				}
				if (propertyId == SerializedCertificatePropertyId)
				{
					encodedCertificate = new byte[length];
					Buffer.BlockCopy(blob, offset, encodedCertificate, 0, length);
				}
				offset = offset + length;
			}

			if (encodedCertificate == null)
			{
				// Формат не распознан — пробуем отдать данные штатному загрузчику Windows.
				return new X509Certificate2(blob);
			}
			return new X509Certificate2(encodedCertificate);
		}

		/// <summary>
		/// Проверяет, являются ли данные контейнером PKCS#12 (.p12/.pfx).
		/// </summary>
		public static bool IsPkcs12(byte[] content)
		{
			if (content == null || content.Length < 4 || content[0] != 0x30)
			{
				return false;
			}
			try
			{
				return X509Certificate2.GetCertContentType(content) == X509ContentType.Pkcs12;
			}
			catch (CryptographicException)
			{
				return false;
			}
		}

		/// <summary>
		/// Открывает PKCS#12 штатными средствами Windows: сначала без пароля, затем с паролями, заданными оператором.
		/// Если ни один пароль не подошёл, бросает PasswordProtectedFileException — файл учитывается как непрочитанный.
		/// </summary>
		private static List<X509Certificate2> LoadPkcs12(byte[] content, IList<string> passwords)
		{
			List<string> candidates = new List<string>();
			candidates.Add(null);
			candidates.Add(string.Empty);
			if (passwords != null)
			{
				candidates.AddRange(passwords);
			}

			foreach (string password in candidates)
			{
				X509Certificate2Collection collection = new X509Certificate2Collection();
				try
				{
					collection.Import(content, password, X509KeyStorageFlags.DefaultKeySet);
				}
				catch (CryptographicException)
				{
					continue;
				}
				List<X509Certificate2> certificates = new List<X509Certificate2>();
				foreach (X509Certificate2 certificate in collection)
				{
					certificates.Add(certificate);
				}
				if (certificates.Count == 0)
				{
					throw new CryptographicException("Контейнер PKCS#12 не содержит сертификатов");
				}
				return certificates;
			}

			string hint = passwords == null || passwords.Count == 0
				? "пароли не заданы"
				: "ни один из заданных паролей (" + passwords.Count + ") не подошёл";
			throw new PasswordProtectedFileException("Файл PKCS#12 защищён паролем, " + hint
				+ ". Укажите пароль в панели: «Настройки» → «Пароли для .p12/.pfx» (используется при сканировании «Этот ПК» и без агента)");
		}

		/// <summary>
		/// Загружает сертификаты из бинарных данных (DER-сертификат или контейнер PKCS#7).
		/// </summary>
		private static List<X509Certificate2> ImportBinary(byte[] data)
		{
			List<X509Certificate2> certificates = new List<X509Certificate2>();
			X509Certificate2Collection collection = new X509Certificate2Collection();
			collection.Import(data);
			foreach (X509Certificate2 certificate in collection)
			{
				certificates.Add(certificate);
			}
			if (certificates.Count == 0)
			{
				throw new CryptographicException("Данные не содержат сертификатов");
			}
			return certificates;
		}

		/// <summary>
		/// Пытается интерпретировать байты как ASCII/UTF-8 текст. Возвращает null для бинарных данных.
		/// </summary>
		private static string TryDecodeAsText(byte[] content)
		{
			int sampleLength = Math.Min(content.Length, 4096);
			for (int index = 0; index < sampleLength; index++)
			{
				byte currentByte = content[index];
				bool isAllowedControl = currentByte == 9 || currentByte == 10 || currentByte == 13;
				if (currentByte < 0x20 && !isAllowedControl)
				{
					return null;
				}
			}
			string text = Encoding.UTF8.GetString(content);
			return text.TrimStart('﻿');
		}

		/// <summary>
		/// Проверяет, состоит ли текст только из символов Base64 (сертификат в Base64 без заголовков PEM).
		/// </summary>
		private static bool LooksLikeBase64(string text)
		{
			string compact = RemoveWhitespace(text);
			if (compact.Length < 64 || compact.Length % 4 != 0)
			{
				return false;
			}
			foreach (char symbol in compact)
			{
				bool isBase64Char = (symbol >= 'A' && symbol <= 'Z') || (symbol >= 'a' && symbol <= 'z') || (symbol >= '0' && symbol <= '9') || symbol == '+' || symbol == '/' || symbol == '=';
				if (!isBase64Char)
				{
					return false;
				}
			}
			return true;
		}

		/// <summary>
		/// Удаляет из строки все пробельные символы.
		/// </summary>
		private static string RemoveWhitespace(string text)
		{
			StringBuilder builder = new StringBuilder(text.Length);
			foreach (char symbol in text)
			{
				if (!char.IsWhiteSpace(symbol))
				{
					builder.Append(symbol);
				}
			}
			return builder.ToString();
		}
	}
}
