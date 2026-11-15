using System;
using System.Collections.Generic;
using System.Xml.Serialization;
using Skzi.Common.Certificates;
using Skzi.Common.Configuration;

namespace Skzi.Common.Scanning
{
	/// <summary>
	/// Сведения о КриптоПро CSP, установленном на сканируемом ПК.
	/// </summary>
	public class CryptoProInfo
	{
		/// <summary>Установлен ли КриптоПро CSP.</summary>
		public bool IsInstalled { get; set; }

		/// <summary>Название продукта (как в «Программы и компоненты»).</summary>
		public string ProductName { get; set; }

		/// <summary>Полная версия (например, 5.0.12000).</summary>
		public string Version { get; set; }

		/// <summary>Серийный номер лицензии (замаскирован).</summary>
		public string LicenseSerialMasked { get; set; }

		/// <summary>Версия CSP, на которую выдана установленная лицензия (по серийному номеру).</summary>
		public string LicenseVersion { get; set; }

		/// <summary>Доп. сведения о лицензии (вывод cpconfig, ключ замаскирован), если удалось получить.</summary>
		public string LicenseDetails { get; set; }

		/// <summary>Срок действия лицензии: «бессрочная», «до 31.12.2026» и т.п.; null — не удалось определить.</summary>
		public string LicenseValidity { get; set; }

		/// <summary>Дата установки КриптоПро CSP (ДД.ММ.ГГГГ), если есть в реестре.</summary>
		public string InstallDate { get; set; }

		/// <summary>Откуда получены сведения (реестр, файл провайдера и т.п.).</summary>
		public string DetectionSource { get; set; }

		/// <summary>Другие установленные продукты КриптоПро (ЭЦП Browser plug-in, TSP/OCSP Client и т.д.).</summary>
		[XmlArrayItem("Product")]
		public List<string> OtherProducts { get; set; }

		/// <summary>
		/// Создаёт пустые сведения о КриптоПро.
		/// </summary>
		public CryptoProInfo()
		{
			OtherProducts = new List<string>();
		}

		/// <summary>
		/// Краткое описание для таблиц: «КриптоПро CSP 5.0.12000» или «не установлен».
		/// </summary>
		[XmlIgnore]
		public string DisplayText
		{
			get
			{
				if (!IsInstalled)
				{
					return "не установлен";
				}
				string name = string.IsNullOrWhiteSpace(ProductName) ? "КриптоПро CSP" : ProductName;
				if (!string.IsNullOrWhiteSpace(Version) && name.IndexOf(Version, StringComparison.OrdinalIgnoreCase) < 0)
				{
					name = name + " " + Version;
				}
				return name;
			}
		}
	}

	/// <summary>
	/// Результат сканирования одного ПК: КриптоПро, найденные сертификаты, статистика и предупреждения.
	/// Сериализуется в XML при передаче от агента к панели.
	/// </summary>
	[XmlRoot("ScanResult")]
	public class ScanResult
	{
		/// <summary>Имя сканируемого ПК.</summary>
		public string ComputerName { get; set; }

		/// <summary>Способ сканирования: Agent, Agentless, Local.</summary>
		public string ScanMode { get; set; }

		/// <summary>Учётная запись, под которой выполнялось сканирование.</summary>
		public string ScannedAs { get; set; }

		/// <summary>Версия ОС сканируемого ПК.</summary>
		public string OperatingSystem { get; set; }

		/// <summary>Версия программы, выполнившей сканирование.</summary>
		public string ScannerVersion { get; set; }

		/// <summary>Время начала сканирования.</summary>
		public DateTime StartedAt { get; set; }

		/// <summary>Время окончания сканирования.</summary>
		public DateTime FinishedAt { get; set; }

		/// <summary>Сведения о КриптоПро CSP.</summary>
		public CryptoProInfo CryptoPro { get; set; }

		/// <summary>Найденные сертификаты (без дублей по отпечатку).</summary>
		[XmlArrayItem("Certificate")]
		public List<CertificateRecord> Certificates { get; set; }

		/// <summary>Предупреждения (нет доступа к папке, повреждённый файл и т.п.).</summary>
		[XmlArrayItem("Warning")]
		public List<string> Warnings { get; set; }

		/// <summary>Сколько директорий просмотрено.</summary>
		public int DirectoriesScanned { get; set; }

		/// <summary>Сколько файлов-кандидатов обработано.</summary>
		public int FilesScanned { get; set; }

		/// <summary>Сколько файлов не удалось разобрать как сертификат.</summary>
		public int FilesFailed { get; set; }

		/// <summary>Сколько сертификатов найдено в хранилищах Windows.</summary>
		public int StoreCertificatesFound { get; set; }

		/// <summary>Сколько сертификатов найдено в ключевых контейнерах КриптоПро.</summary>
		public int ContainerCertificatesFound { get; set; }

		/// <summary>
		/// Директории, которые были фактически просмотрены (маски раскрыты, пути в виде «C:\...» на сканируемом ПК).
		/// Нужны, чтобы отметить в БД сертификаты, пропавшие из просмотренных папок.
		/// </summary>
		[XmlArrayItem("Directory")]
		public List<ScanDirectoryEntry> ScannedDirectories { get; set; }

		/// <summary>Расширения файлов, которые искались при сканировании (через «;»).</summary>
		public string ScannedFileExtensions { get; set; }

		/// <summary>Были ли просмотрены хранилища сертификатов Windows.</summary>
		public bool CertificateStoresScanned { get; set; }

		/// <summary>Были ли просмотрены ключевые контейнеры КриптоПро.</summary>
		public bool CryptoProContainersScanned { get; set; }

		/// <summary>
		/// Создаёт пустой результат сканирования.
		/// </summary>
		public ScanResult()
		{
			CryptoPro = new CryptoProInfo();
			Certificates = new List<CertificateRecord>();
			Warnings = new List<string>();
			ScannedDirectories = new List<ScanDirectoryEntry>();
		}

		/// <summary>
		/// Длительность сканирования.
		/// </summary>
		[XmlIgnore]
		public TimeSpan Duration
		{
			get { return FinishedAt - StartedAt; }
		}
	}
}
