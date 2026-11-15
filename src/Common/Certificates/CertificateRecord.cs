using System;
using System.Collections.Generic;
using System.Xml.Serialization;

namespace Skzi.Common.Certificates
{
	/// <summary>
	/// Результат парсинга одного сертификата: всё, что сохраняется в БД и показывается в панели управления.
	/// Класс сериализуется в XML при передаче от агента к панели.
	/// </summary>
	public class CertificateRecord
	{
		/// <summary>Серийный номер сертификата (HEX, верхний регистр, без пробелов).</summary>
		public string SerialNumber { get; set; }

		/// <summary>Отпечаток SHA-1 (HEX).</summary>
		public string Thumbprint { get; set; }

		/// <summary>Имя владельца (ФИО из SN+G, иначе CN).</summary>
		public string OwnerName { get; set; }

		/// <summary>ИНН владельца (ФЛ или ЮЛ).</summary>
		public string OwnerInn { get; set; }

		/// <summary>СНИЛС владельца.</summary>
		public string OwnerSnils { get; set; }

		/// <summary>ОГРН / ОГРНИП владельца.</summary>
		public string OwnerOgrn { get; set; }

		/// <summary>Организация владельца (поле O).</summary>
		public string OwnerOrganization { get; set; }

		/// <summary>Должность владельца (поле T).</summary>
		public string OwnerTitle { get; set; }

		/// <summary>Адрес электронной почты владельца.</summary>
		public string OwnerEmail { get; set; }

		/// <summary>Полное имя субъекта (DN).</summary>
		public string SubjectDn { get; set; }

		/// <summary>Удостоверяющий центр (CN издателя, иначе O).</summary>
		public string CertificationAuthority { get; set; }

		/// <summary>Полное имя издателя (DN).</summary>
		public string IssuerDn { get; set; }

		/// <summary>Начало срока действия (локальное время).</summary>
		public DateTime ValidFrom { get; set; }

		/// <summary>Окончание срока действия (локальное время).</summary>
		public DateTime ValidTo { get; set; }

		/// <summary>Алгоритм подписи сертификата (с русскими названиями для ГОСТ).</summary>
		public string SignatureAlgorithm { get; set; }

		/// <summary>Алгоритм открытого ключа.</summary>
		public string PublicKeyAlgorithm { get; set; }

		/// <summary>Признак встроенной в сертификат лицензии КриптоПро CSP (расширение 1.2.643.2.2.49.2).</summary>
		public bool HasEmbeddedCryptoProLicense { get; set; }

		/// <summary>Версия КриптоПро CSP, на которую выдана встроенная лицензия (если лицензия есть).</summary>
		public string CryptoProLicenseVersion { get; set; }

		/// <summary>Дополнительные сведения о встроенной лицензии (строки из расширения, ключ замаскирован).</summary>
		public string CryptoProLicenseDetails { get; set; }

		/// <summary>Есть ли у сертификата привязка к закрытому ключу (для сертификатов из хранилища).</summary>
		public bool HasPrivateKey { get; set; }

		/// <summary>Где найден сертификат: файлы и хранилища.</summary>
		[XmlArrayItem("Source")]
		public List<string> Sources { get; set; }

		/// <summary>
		/// Создаёт пустую запись сертификата.
		/// </summary>
		public CertificateRecord()
		{
			Sources = new List<string>();
		}

		/// <summary>
		/// Признак истёкшего срока действия на текущий момент.
		/// </summary>
		[XmlIgnore]
		public bool IsExpired
		{
			get { return ValidTo < DateTime.Now; }
		}

		/// <summary>
		/// Источники через «; » — для показа в таблице и записи в БД.
		/// </summary>
		[XmlIgnore]
		public string SourcesText
		{
			get { return Sources == null ? string.Empty : string.Join("; ", Sources); }
		}

		/// <summary>
		/// Добавляет источник, если такого ещё нет (без учёта регистра).
		/// </summary>
		public void AddSource(string source)
		{
			if (string.IsNullOrWhiteSpace(source))
			{
				return;
			}
			foreach (string existing in Sources)
			{
				if (string.Equals(existing, source, StringComparison.OrdinalIgnoreCase))
				{
					return;
				}
			}
			Sources.Add(source);
		}
	}
}
