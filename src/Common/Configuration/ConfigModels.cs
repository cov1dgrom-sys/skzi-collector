using System;
using System.Collections.Generic;
using System.Data.SqlClient;
using System.Security.Cryptography;
using System.Text;
using System.Xml.Serialization;

namespace Skzi.Common.Configuration
{
	/// <summary>
	/// Директория для сканирования. Поддерживаются переменные окружения (%USERPROFILE%)
	/// и маски в сегментах пути (C:\Users\*\Desktop).
	/// </summary>
	public class ScanDirectoryEntry
	{
		/// <summary>Сканировать ли вложенные папки.</summary>
		[XmlAttribute("Recursive")]
		public bool Recursive { get; set; }

		/// <summary>Путь к директории.</summary>
		[XmlText]
		public string Path { get; set; }

		/// <summary>
		/// Создаёт запись директории (по умолчанию — с подпапками).
		/// </summary>
		public ScanDirectoryEntry()
		{
			Recursive = true;
		}

		/// <summary>
		/// Создаёт запись директории с путём и признаком обхода подпапок.
		/// </summary>
		public ScanDirectoryEntry(string path, bool recursive)
		{
			Path = path;
			Recursive = recursive;
		}

		/// <summary>
		/// Текстовое представление для показа в интерфейсе.
		/// </summary>
		public override string ToString()
		{
			return Recursive ? Path : Path + " (без подпапок)";
		}
	}

	/// <summary>
	/// Конфигурация агента (agent.config.xml) — устанавливается на каждый сканируемый ПК.
	/// </summary>
	[XmlRoot("AgentConfig")]
	public class AgentConfig
	{
		/// <summary>TCP-порт, на котором агент принимает запросы панели.</summary>
		public int ListenPort { get; set; }

		/// <summary>Общий секретный ключ для аутентификации панели (HMAC-SHA256).</summary>
		public string SharedKey { get; set; }

		/// <summary>Разрешённые адреса панели управления (пусто — любые, при условии верного ключа).</summary>
		[XmlArrayItem("Client")]
		public List<string> AllowedClients { get; set; }

		/// <summary>Директории для сканирования файлов сертификатов.</summary>
		[XmlArrayItem("Directory")]
		public List<ScanDirectoryEntry> ScanDirectories { get; set; }

		/// <summary>Расширения файлов сертификатов через «;».</summary>
		public string CertificateFileExtensions { get; set; }

		/// <summary>Сканировать ли личные хранилища сертификатов Windows.</summary>
		public bool ScanCertificateStores { get; set; }

		/// <summary>Максимальный размер файла сертификата, КБ (большие файлы пропускаются).</summary>
		public int MaxCertificateFileSizeKb { get; set; }

		/// <summary>Принимать ли дополнительные директории, присланные панелью.</summary>
		public bool AcceptDirectoriesFromPanel { get; set; }

		/// <summary>Искать сертификаты в ключевых контейнерах КриптоПро CSP (реестр, съёмные носители, токены).</summary>
		public bool ScanCryptoProContainers { get; set; }

		/// <summary>Папка журналов (относительно exe или абсолютный путь).</summary>
		public string LogDirectory { get; set; }

		/// <summary>Сколько суток хранить файлы журнала (0 — не удалять).</summary>
		public int LogRetentionDays { get; set; }

		/// <summary>Максимальный размер одного файла журнала, МБ (при превышении начинается следующая часть).</summary>
		public int LogMaxFileSizeMb { get; set; }

		/// <summary>Строка подключения к MSSQL для автономного режима «--scan --db» (необязательно).</summary>
		public string DatabaseConnectionString { get; set; }

		/// <summary>Имя таблицы для автономного режима.</summary>
		public string DatabaseTableName { get; set; }

		/// <summary>
		/// Создаёт конфигурацию агента со значениями по умолчанию (без директорий).
		/// </summary>
		public AgentConfig()
		{
			ListenPort = 50555;
			SharedKey = string.Empty;
			AllowedClients = new List<string>();
			ScanDirectories = new List<ScanDirectoryEntry>();
			CertificateFileExtensions = ScanOptions.DefaultExtensions;
			ScanCertificateStores = true;
			MaxCertificateFileSizeKb = 2048;
			AcceptDirectoriesFromPanel = true;
			ScanCryptoProContainers = true;
			LogDirectory = "logs";
			LogRetentionDays = Logging.Logger.DefaultRetentionDays;
			LogMaxFileSizeMb = Logging.Logger.DefaultMaxFileSizeMb;
			DatabaseTableName = DatabaseSettings.DefaultTableName;
		}

		/// <summary>
		/// Создаёт конфигурацию агента с типовыми директориями (используется, если файла конфигурации нет).
		/// </summary>
		public static AgentConfig CreateDefault()
		{
			AgentConfig config = new AgentConfig();
			config.SharedKey = "RedFlag-SKZI-ChangeMe";
			config.ScanDirectories.Add(new ScanDirectoryEntry(@"C:\Certs", true));
			config.ScanDirectories.Add(new ScanDirectoryEntry(@"C:\Users\*\Desktop", true));
			config.ScanDirectories.Add(new ScanDirectoryEntry(@"C:\Users\*\Documents", true));
			config.ScanDirectories.Add(new ScanDirectoryEntry(@"C:\Users\*\Downloads", true));
			return config;
		}
	}

	/// <summary>
	/// Параметры подключения к Microsoft SQL Server.
	/// </summary>
	public class DatabaseSettings
	{
		public const string DefaultTableName = "dbo.SkziCertificates";
		private static readonly byte[] PasswordEntropy = Encoding.UTF8.GetBytes("RedFlag.Skzi.Panel");

		/// <summary>Сервер MSSQL (например, localhost\SQLEXPRESS или (localdb)\MSSQLLocalDB).</summary>
		public string Server { get; set; }

		/// <summary>Имя базы данных.</summary>
		public string DatabaseName { get; set; }

		/// <summary>Использовать проверку подлинности Windows.</summary>
		public bool UseWindowsAuthentication { get; set; }

		/// <summary>Логин SQL Server (если не Windows-аутентификация).</summary>
		public string UserName { get; set; }

		/// <summary>Пароль, зашифрованный DPAPI для текущего пользователя Windows (Base64).</summary>
		public string ProtectedPassword { get; set; }

		/// <summary>Имя таблицы (схема.таблица).</summary>
		public string TableName { get; set; }

		/// <summary>Создавать базу данных, если её нет.</summary>
		public bool CreateDatabaseIfMissing { get; set; }

		/// <summary>Таймаут подключения, секунд.</summary>
		public int ConnectTimeoutSeconds { get; set; }

		/// <summary>
		/// Создаёт параметры подключения со значениями по умолчанию.
		/// </summary>
		public DatabaseSettings()
		{
			Server = @"localhost\SQLEXPRESS";
			DatabaseName = "SkziInventory";
			UseWindowsAuthentication = true;
			UserName = string.Empty;
			ProtectedPassword = string.Empty;
			TableName = DefaultTableName;
			CreateDatabaseIfMissing = true;
			ConnectTimeoutSeconds = 15;
		}

		/// <summary>
		/// Сохраняет пароль в зашифрованном виде (DPAPI, область текущего пользователя).
		/// </summary>
		public void SetPassword(string plainPassword)
		{
			if (string.IsNullOrEmpty(plainPassword))
			{
				ProtectedPassword = string.Empty;
				return;
			}
			byte[] protectedBytes = ProtectedData.Protect(Encoding.UTF8.GetBytes(plainPassword), PasswordEntropy, DataProtectionScope.CurrentUser);
			ProtectedPassword = Convert.ToBase64String(protectedBytes);
		}

		/// <summary>
		/// Расшифровывает сохранённый пароль. Возвращает пустую строку, если пароль не задан или не расшифровывается.
		/// </summary>
		public string GetPassword()
		{
			if (string.IsNullOrEmpty(ProtectedPassword))
			{
				return string.Empty;
			}
			try
			{
				byte[] plainBytes = ProtectedData.Unprotect(Convert.FromBase64String(ProtectedPassword), PasswordEntropy, DataProtectionScope.CurrentUser);
				return Encoding.UTF8.GetString(plainBytes);
			}
			catch (Exception)
			{
				return string.Empty;
			}
		}

		/// <summary>
		/// Собирает строку подключения ADO.NET из параметров.
		/// </summary>
		public string BuildConnectionString()
		{
			SqlConnectionStringBuilder builder = new SqlConnectionStringBuilder();
			builder.DataSource = Server;
			builder.InitialCatalog = DatabaseName;
			builder.IntegratedSecurity = UseWindowsAuthentication;
			if (!UseWindowsAuthentication)
			{
				builder.UserID = UserName ?? string.Empty;
				builder.Password = GetPassword();
			}
			builder.ConnectTimeout = ConnectTimeoutSeconds > 0 ? ConnectTimeoutSeconds : 15;
			builder.ApplicationName = "SKZI Control Panel";
			return builder.ConnectionString;
		}
	}

	/// <summary>
	/// Конфигурация панели управления (panel.config.xml).
	/// </summary>
	[XmlRoot("PanelConfig")]
	public class PanelConfig
	{
		private static readonly byte[] PfxPasswordEntropy = Encoding.UTF8.GetBytes("RedFlag.Skzi.Pkcs12");

		/// <summary>Подключение к MSSQL.</summary>
		public DatabaseSettings Database { get; set; }

		/// <summary>Порт агентов.</summary>
		public int AgentPort { get; set; }

		/// <summary>Общий секретный ключ (должен совпадать с ключом в конфигурации агентов).</summary>
		public string SharedKey { get; set; }

		/// <summary>Таймаут ожидания ответа агента, секунд.</summary>
		public int AgentTimeoutSeconds { get; set; }

		/// <summary>Максимальное число одновременно сканируемых ПК.</summary>
		public int MaxParallelScans { get; set; }

		/// <summary>Передавать ли агентам директории из настроек панели.</summary>
		public bool SendDirectoriesToAgents { get; set; }

		/// <summary>
		/// Агенты ищут файлы только в директориях, указанных в панели (директории из agent.config.xml не используются).
		/// Так папки для поиска задаёт тот, кто собирает сертификаты.
		/// </summary>
		public bool AgentsUseOnlyPanelDirectories { get; set; }

		/// <summary>Сразу записывать результаты сканирования в БД.</summary>
		public bool SaveToDatabaseAfterScan { get; set; }

		/// <summary>Режим сканирования по умолчанию: Agent или Agentless.</summary>
		public string DefaultScanMode { get; set; }

		/// <summary>Директории для сканирования (для локального и безагентного режимов, а также для отправки агентам).</summary>
		[XmlArrayItem("Directory")]
		public List<ScanDirectoryEntry> ScanDirectories { get; set; }

		/// <summary>Расширения файлов сертификатов через «;».</summary>
		public string CertificateFileExtensions { get; set; }

		/// <summary>Сканировать ли хранилища сертификатов Windows.</summary>
		public bool ScanCertificateStores { get; set; }

		/// <summary>Максимальный размер файла сертификата, КБ.</summary>
		public int MaxCertificateFileSizeKb { get; set; }

		/// <summary>Искать сертификаты в ключевых контейнерах КриптоПро CSP (реестр, съёмные носители, токены).</summary>
		public bool ScanCryptoProContainers { get; set; }

		/// <summary>
		/// Пароли для файлов PKCS#12 (.p12/.pfx), зашифрованные DPAPI текущего пользователя (Base64).
		/// Используются только при сканировании с этого ПК («Этот ПК» и безагентный режим); агентам не передаются.
		/// </summary>
		public string ProtectedPfxPasswords { get; set; }

		/// <summary>Список ПК для сканирования (имена или IP-адреса).</summary>
		[XmlArrayItem("Host")]
		public List<string> Hosts { get; set; }

		/// <summary>Папка установки агента на удалённых ПК при развёртывании из панели.</summary>
		public string AgentInstallPath { get; set; }

		/// <summary>Папка журналов панели.</summary>
		public string LogDirectory { get; set; }

		/// <summary>Сколько суток хранить файлы журнала (0 — не удалять).</summary>
		public int LogRetentionDays { get; set; }

		/// <summary>Максимальный размер одного файла журнала, МБ (при превышении начинается следующая часть).</summary>
		public int LogMaxFileSizeMb { get; set; }

		/// <summary>
		/// Создаёт конфигурацию панели со значениями по умолчанию (без директорий и ПК).
		/// </summary>
		public PanelConfig()
		{
			Database = new DatabaseSettings();
			AgentPort = 50555;
			SharedKey = string.Empty;
			AgentTimeoutSeconds = 180;
			MaxParallelScans = 8;
			SendDirectoriesToAgents = true;
			AgentsUseOnlyPanelDirectories = true;
			SaveToDatabaseAfterScan = true;
			DefaultScanMode = "Agent";
			ScanDirectories = new List<ScanDirectoryEntry>();
			CertificateFileExtensions = ScanOptions.DefaultExtensions;
			ScanCertificateStores = true;
			MaxCertificateFileSizeKb = 2048;
			ScanCryptoProContainers = true;
			ProtectedPfxPasswords = string.Empty;
			Hosts = new List<string>();
			AgentInstallPath = @"C:\Program Files\SkziAgent";
			LogDirectory = "logs";
			LogRetentionDays = Logging.Logger.DefaultRetentionDays;
			LogMaxFileSizeMb = Logging.Logger.DefaultMaxFileSizeMb;
		}

		/// <summary>
		/// Сохраняет пароли PKCS#12 в зашифрованном виде (DPAPI, область текущего пользователя).
		/// </summary>
		public void SetPfxPasswords(IEnumerable<string> passwords)
		{
			List<string> cleaned = new List<string>();
			if (passwords != null)
			{
				foreach (string password in passwords)
				{
					if (!string.IsNullOrEmpty(password) && !cleaned.Contains(password))
					{
						cleaned.Add(password);
					}
				}
			}
			if (cleaned.Count == 0)
			{
				ProtectedPfxPasswords = string.Empty;
				return;
			}
			byte[] plainBytes = Encoding.UTF8.GetBytes(string.Join("\n", cleaned));
			byte[] protectedBytes = ProtectedData.Protect(plainBytes, PfxPasswordEntropy, DataProtectionScope.CurrentUser);
			ProtectedPfxPasswords = Convert.ToBase64String(protectedBytes);
		}

		/// <summary>
		/// Расшифровывает сохранённые пароли PKCS#12. Возвращает пустой список, если паролей нет или они не расшифровываются.
		/// </summary>
		public List<string> GetPfxPasswords()
		{
			List<string> passwords = new List<string>();
			if (string.IsNullOrEmpty(ProtectedPfxPasswords))
			{
				return passwords;
			}
			try
			{
				byte[] plainBytes = ProtectedData.Unprotect(Convert.FromBase64String(ProtectedPfxPasswords), PfxPasswordEntropy, DataProtectionScope.CurrentUser);
				foreach (string password in Encoding.UTF8.GetString(plainBytes).Split('\n'))
				{
					if (password.Length > 0)
					{
						passwords.Add(password);
					}
				}
			}
			catch (Exception)
			{
				// Конфигурация перенесена с другого ПК или пользователя — пароли нужно ввести заново.
			}
			return passwords;
		}

		/// <summary>
		/// Создаёт конфигурацию панели со значениями по умолчанию.
		/// </summary>
		public static PanelConfig CreateDefault()
		{
			PanelConfig config = new PanelConfig();
			config.Database.Server = Skzi.Common.Database.SqlServerLocator.SuggestDefaultServer();
			config.SharedKey = "RedFlag-SKZI-ChangeMe";
			config.ScanDirectories.Add(new ScanDirectoryEntry(@"C:\Certs", true));
			config.ScanDirectories.Add(new ScanDirectoryEntry(@"C:\Users\*\Desktop", true));
			config.ScanDirectories.Add(new ScanDirectoryEntry(@"C:\Users\*\Documents", true));
			config.ScanDirectories.Add(new ScanDirectoryEntry(@"C:\Users\*\Downloads", true));
			config.Hosts.Add("localhost");
			return config;
		}
	}
}
