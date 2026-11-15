using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Xml;
using System.Xml.Serialization;
using Skzi.Common.Logging;

namespace Skzi.Common.Configuration
{
	/// <summary>
	/// Параметры одного сканирования: директории, расширения файлов, хранилища, ограничения.
	/// </summary>
	public sealed class ScanOptions
	{
		public const string DefaultExtensions = ".cer;.crt;.der;.pem;.cert;.p7b;.p7c;.p12;.pfx";

		/// <summary>Директории для поиска файлов сертификатов.</summary>
		public List<ScanDirectoryEntry> Directories { get; set; }

		/// <summary>Допустимые расширения файлов (в нижнем регистре, с точкой).</summary>
		public HashSet<string> FileExtensions { get; set; }

		/// <summary>Сканировать личные хранилища сертификатов Windows.</summary>
		public bool ScanCertificateStores { get; set; }

		/// <summary>Максимальный размер файла сертификата в байтах.</summary>
		public long MaxFileSizeBytes { get; set; }

		/// <summary>Искать сертификаты в ключевых контейнерах КриптоПро CSP.</summary>
		public bool ScanCryptoProContainers { get; set; }

		/// <summary>Пароли для открытия файлов PKCS#12 (.p12/.pfx), заданные оператором. Не сохраняются и не передаются по сети.</summary>
		public List<string> Pkcs12Passwords { get; set; }

		/// <summary>
		/// Создаёт параметры сканирования со значениями по умолчанию.
		/// </summary>
		public ScanOptions()
		{
			Directories = new List<ScanDirectoryEntry>();
			FileExtensions = ParseExtensions(DefaultExtensions);
			ScanCertificateStores = true;
			MaxFileSizeBytes = 2048 * 1024;
			ScanCryptoProContainers = true;
			Pkcs12Passwords = new List<string>();
		}

		/// <summary>
		/// Расширения файлов одной строкой через «;» (для журнала и результата сканирования).
		/// </summary>
		public string FileExtensionsText
		{
			get
			{
				List<string> sorted = new List<string>(FileExtensions);
				sorted.Sort(StringComparer.OrdinalIgnoreCase);
				return string.Join(";", sorted);
			}
		}

		/// <summary>
		/// Разбирает строку расширений вида «.cer;.crt;pem» в набор «.cer», «.crt», «.pem».
		/// </summary>
		public static HashSet<string> ParseExtensions(string extensionsText)
		{
			HashSet<string> extensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
			if (string.IsNullOrWhiteSpace(extensionsText))
			{
				extensionsText = DefaultExtensions;
			}
			foreach (string rawExtension in extensionsText.Split(new[] { ';', ',', ' ', '|' }, StringSplitOptions.RemoveEmptyEntries))
			{
				string extension = rawExtension.Trim().TrimStart('*');
				if (extension.Length == 0)
				{
					continue;
				}
				if (!extension.StartsWith(".", StringComparison.Ordinal))
				{
					extension = "." + extension;
				}
				extensions.Add(extension.ToLowerInvariant());
			}
			return extensions;
		}

		/// <summary>
		/// Формирует параметры сканирования из конфигурации агента.
		/// </summary>
		public static ScanOptions FromAgentConfig(AgentConfig config)
		{
			ScanOptions options = new ScanOptions();
			options.Directories.AddRange(config.ScanDirectories);
			options.FileExtensions = ParseExtensions(config.CertificateFileExtensions);
			options.ScanCertificateStores = config.ScanCertificateStores;
			options.MaxFileSizeBytes = Math.Max(1, config.MaxCertificateFileSizeKb) * 1024L;
			options.ScanCryptoProContainers = config.ScanCryptoProContainers;
			return options;
		}

		/// <summary>
		/// Формирует параметры сканирования из конфигурации панели управления (вместе с паролями PKCS#12 оператора).
		/// </summary>
		public static ScanOptions FromPanelConfig(PanelConfig config)
		{
			ScanOptions options = new ScanOptions();
			options.Directories.AddRange(config.ScanDirectories);
			options.FileExtensions = ParseExtensions(config.CertificateFileExtensions);
			options.ScanCertificateStores = config.ScanCertificateStores;
			options.MaxFileSizeBytes = Math.Max(1, config.MaxCertificateFileSizeKb) * 1024L;
			options.ScanCryptoProContainers = config.ScanCryptoProContainers;
			options.Pkcs12Passwords.AddRange(config.GetPfxPasswords());
			return options;
		}

		/// <summary>
		/// Добавляет директории, исключая дубликаты путей.
		/// </summary>
		public void AddDirectories(IEnumerable<ScanDirectoryEntry> additionalDirectories)
		{
			if (additionalDirectories == null)
			{
				return;
			}
			foreach (ScanDirectoryEntry candidate in additionalDirectories)
			{
				if (candidate == null || string.IsNullOrWhiteSpace(candidate.Path))
				{
					continue;
				}
				bool alreadyPresent = false;
				foreach (ScanDirectoryEntry existing in Directories)
				{
					if (string.Equals(existing.Path.TrimEnd('\\'), candidate.Path.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase))
					{
						existing.Recursive = existing.Recursive || candidate.Recursive;
						alreadyPresent = true;
						break;
					}
				}
				if (!alreadyPresent)
				{
					Directories.Add(new ScanDirectoryEntry(candidate.Path.Trim(), candidate.Recursive));
				}
			}
		}
	}

	/// <summary>
	/// Чтение и запись конфигурационных XML-файлов.
	/// </summary>
	public static class ConfigFile
	{
		/// <summary>
		/// Возвращает полный путь к файлу конфигурации рядом с исполняемым файлом.
		/// </summary>
		public static string GetDefaultPath(string fileName)
		{
			return Path.Combine(AppDomain.CurrentDomain.BaseDirectory, fileName);
		}

		/// <summary>
		/// Читает конфигурацию из XML-файла. Если файла нет — создаёт его из значений по умолчанию.
		/// Ошибки разбора записываются в журнал и пробрасываются вызывающему коду.
		/// </summary>
		public static T LoadOrCreate<T>(string filePath, Func<T> createDefault) where T : class
		{
			if (!File.Exists(filePath))
			{
				T defaultConfig = createDefault();
				Logger.Warning("Файл конфигурации не найден, создан файл со значениями по умолчанию: " + filePath);
				try
				{
					Save(filePath, defaultConfig);
				}
				catch (Exception saveException)
				{
					Logger.Error("Не удалось сохранить конфигурацию по умолчанию: " + filePath, saveException);
				}
				return defaultConfig;
			}

			try
			{
				T config = Load<T>(filePath);
				Logger.Info("Прочитан файл конфигурации: " + filePath);
				return config;
			}
			catch (Exception loadException)
			{
				Logger.Error("Ошибка чтения файла конфигурации " + filePath, loadException);
				throw;
			}
		}

		/// <summary>
		/// Читает XML-файл конфигурации с безопасными настройками парсера (DTD запрещены).
		/// </summary>
		public static T Load<T>(string filePath) where T : class
		{
			XmlReaderSettings readerSettings = new XmlReaderSettings();
			readerSettings.DtdProcessing = DtdProcessing.Prohibit;
			readerSettings.XmlResolver = null;
			readerSettings.IgnoreComments = true;
			using (XmlReader reader = XmlReader.Create(filePath, readerSettings))
			{
				XmlSerializer serializer = new XmlSerializer(typeof(T));
				T config = serializer.Deserialize(reader) as T;
				if (config == null)
				{
					throw new InvalidDataException("Файл конфигурации пуст или имеет неверный корневой элемент: " + filePath);
				}
				return config;
			}
		}

		/// <summary>
		/// Сохраняет конфигурацию в XML-файл (UTF-8, с отступами). Запись атомарная — через временный файл.
		/// </summary>
		public static void Save<T>(string filePath, T config) where T : class
		{
			string directory = Path.GetDirectoryName(Path.GetFullPath(filePath));
			if (!string.IsNullOrEmpty(directory))
			{
				Directory.CreateDirectory(directory);
			}
			string temporaryPath = filePath + ".tmp";
			XmlWriterSettings writerSettings = new XmlWriterSettings();
			writerSettings.Indent = true;
			writerSettings.IndentChars = "\t";
			writerSettings.Encoding = new UTF8Encoding(false);
			using (XmlWriter writer = XmlWriter.Create(temporaryPath, writerSettings))
			{
				XmlSerializer serializer = new XmlSerializer(typeof(T));
				XmlSerializerNamespaces namespaces = new XmlSerializerNamespaces();
				namespaces.Add(string.Empty, string.Empty);
				serializer.Serialize(writer, config, namespaces);
			}
			if (File.Exists(filePath))
			{
				File.Replace(temporaryPath, filePath, null);
			}
			else
			{
				File.Move(temporaryPath, filePath);
			}
		}
	}
}
