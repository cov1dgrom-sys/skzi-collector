using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.ServiceProcess;
using System.Text;
using System.Threading;
using Skzi.Common.Certificates;
using Skzi.Common.Configuration;
using Skzi.Common.Database;
using Skzi.Common.Logging;
using Skzi.Common.Network;
using Skzi.Common.Scanning;

namespace Skzi.Agent
{
	/// <summary>
	/// Точка входа агента. Агент работает в фоне и не показывает окон. Режимы:
	///   (без параметров)  — двойной щелчок: установить службу Windows (с запросом прав администратора)
	///                       и работать в фоне; окно консоли прячется, результат — в окне сообщения;
	///   --service         — запуск службой Windows;
	///   --install         — установить как службу Windows (нужны права администратора);
	///   --uninstall       — удалить службу;
	///   --background      — запустить агент в фоне без окна и без службы (до выхода из системы);
	///   --stop            — остановить агент, запущенный через --background;
	///   --status          — показать, работает ли агент;
	///   --console         — агент в окне консоли до Ctrl+C (для отладки);
	///   --scan [--dir папка]... [--out файл.xml] [--db] — разовое сканирование этого ПК
	///                       (--dir задаёт папки для поиска вместо папок из конфигурации, можно несколько раз);
	///   --config путь     — использовать другой файл конфигурации.
	/// </summary>
	public static class Program
	{
		public const string ConfigFileName = "agent.config.xml";

		/// <summary>
		/// Разбирает параметры командной строки и запускает нужный режим.
		/// </summary>
		public static int Main(string[] args)
		{
			Logger.Initialize("SkziAgent", "logs", Environment.UserInteractive);
			Logger.RegisterGlobalExceptionHandlers();
			TrySetConsoleEncoding();

			List<string> arguments = new List<string>(args);
			string configPath = GetOptionValue(arguments, "--config") ?? ConfigFile.GetDefaultPath(ConfigFileName);

			try
			{
				switch (BackgroundAgent.ResolveCommand(arguments))
				{
					case AgentCommand.Service:
						ServiceBase.Run(new AgentWindowsService(configPath));
						return 0;
					case AgentCommand.BackgroundWorker:
						return BackgroundAgent.RunWorker(configPath);
					case AgentCommand.Help:
						PrintHelp();
						return 0;
					case AgentCommand.Install:
						return InstallService(configPath);
					case AgentCommand.Uninstall:
						return UninstallService();
					case AgentCommand.Scan:
						return RunSingleScan(configPath, GetOptionValues(arguments, "--dir"), GetOptionValue(arguments, "--out"), HasFlag(arguments, "--db"));
					case AgentCommand.Console:
						return RunConsoleAgent(configPath);
					case AgentCommand.Background:
						return BackgroundAgent.RunBackgroundCommand(configPath);
					case AgentCommand.Stop:
						return BackgroundAgent.RunStopCommand();
					case AgentCommand.Status:
						return BackgroundAgent.RunStatusCommand(configPath);
					default:
						return BackgroundAgent.RunDefault(configPath, HasFlag(arguments, BackgroundAgent.NoWindowFlag));
				}
			}
			catch (Exception exception)
			{
				Logger.Error("Критическая ошибка агента", exception);
				return 1;
			}
		}

		/// <summary>
		/// Читает конфигурацию агента и перенастраивает журнал на папку из конфигурации.
		/// </summary>
		public static AgentConfig LoadConfig(string configPath)
		{
			AgentConfig config = ConfigFile.LoadOrCreate<AgentConfig>(configPath, AgentConfig.CreateDefault);
			Logger.Initialize("SkziAgent", config.LogDirectory, Environment.UserInteractive);
			Logger.ConfigureRotation(config.LogRetentionDays, config.LogMaxFileSizeMb);
			List<string> directoryNames = new List<string>();
			foreach (ScanDirectoryEntry entry in config.ScanDirectories)
			{
				directoryNames.Add(entry.ToString());
			}
			Logger.Info("Директории для сканирования из конфигурации: " + (directoryNames.Count == 0 ? "(не заданы)" : string.Join("; ", directoryNames)));
			return config;
		}

		/// <summary>
		/// Агент в консольном режиме: слушает порт до нажатия Ctrl+C.
		/// </summary>
		private static int RunConsoleAgent(string configPath)
		{
			Logger.Info("Агент запущен в консоли. Пользователь: " + CertificateCollector.GetCurrentAccountName() + ", версия: " + CertificateCollector.GetScannerVersion());
			AgentConfig config = LoadConfig(configPath);
			AgentServer server = new AgentServer(config);
			server.Start();

			ManualResetEvent stopEvent = new ManualResetEvent(false);
			Console.CancelKeyPress += delegate (object sender, ConsoleCancelEventArgs eventArgs)
			{
				eventArgs.Cancel = true;
				stopEvent.Set();
			};
			Console.WriteLine("Агент работает. Для остановки нажмите Ctrl+C. Справка: SkziAgent.exe --help");
			stopEvent.WaitOne();
			server.Stop();
			Logger.Info("Выход из агента");
			return 0;
		}

		/// <summary>
		/// Разовое сканирование этого ПК: вывод в консоль, сохранение XML и (по флагу --db) запись в MSSQL.
		/// Папки, указанные через --dir, заменяют папки из конфигурации.
		/// </summary>
		private static int RunSingleScan(string configPath, List<string> requestedDirectories, string outputPath, bool writeToDatabase)
		{
			Logger.Info("Разовое сканирование ПК. Пользователь: " + CertificateCollector.GetCurrentAccountName());
			AgentConfig config = LoadConfig(configPath);
			ScanOptions options = ScanOptions.FromAgentConfig(config);
			if (requestedDirectories.Count > 0)
			{
				options.Directories.Clear();
				foreach (string directory in requestedDirectories)
				{
					options.Directories.Add(new ScanDirectoryEntry(directory, true));
				}
				Logger.Info("Папки для поиска указаны в командной строке: " + string.Join("; ", requestedDirectories));
			}
			ScanResult result = CertificateCollector.Scan(new LocalScanTarget(), options, CertificateCollector.ModeLocal, CancellationToken.None);
			PrintScanResult(result);

			if (!string.IsNullOrWhiteSpace(outputPath))
			{
				File.WriteAllText(outputPath, XmlMessageSerializer.Serialize(result), new UTF8Encoding(false));
				Logger.Info("Результат сканирования сохранён в " + Path.GetFullPath(outputPath));
			}

			if (writeToDatabase)
			{
				if (string.IsNullOrWhiteSpace(config.DatabaseConnectionString))
				{
					Logger.Error("Для --db укажите DatabaseConnectionString в " + configPath);
					return 3;
				}
				CertificateRepository repository = new CertificateRepository(config.DatabaseConnectionString, config.DatabaseTableName);
				repository.EnsureDatabaseExists();
				repository.EnsureTableExists();
				SaveStatistics statistics = repository.SaveScanResult(result);
				Console.WriteLine("Запись в БД: " + statistics);
			}
			return 0;
		}

		/// <summary>
		/// Регистрирует агент как службу Windows. Агент, запущенный в фоне без службы, перед этим
		/// останавливается, чтобы освободить порт.
		/// </summary>
		public static int InstallService(string configPath)
		{
			if (!ServiceSetup.IsAdministrator())
			{
				Logger.Error("Для установки службы запустите командную строку от имени администратора");
				return 5;
			}
			if (BackgroundAgent.StopBackgroundCopy())
			{
				Logger.Info("Агент, работавший в фоне без службы, остановлен: дальше работает служба");
			}
			AgentConfig config = LoadConfig(configPath);
			string executablePath = Assembly.GetExecutingAssembly().Location;
			int exitCode = ServiceSetup.Install(executablePath, config.ListenPort);
			Console.WriteLine(exitCode == 0 ? "Служба установлена и запущена." : "Установка завершилась с ошибкой, подробности в журнале: " + Logger.CurrentLogFilePath);
			return exitCode;
		}

		/// <summary>
		/// Удаляет службу агента.
		/// </summary>
		private static int UninstallService()
		{
			if (!ServiceSetup.IsAdministrator())
			{
				Logger.Error("Для удаления службы запустите командную строку от имени администратора");
				return 5;
			}
			return ServiceSetup.Uninstall(true);
		}

		/// <summary>
		/// Печатает результат сканирования в консоль в виде списка сертификатов.
		/// </summary>
		private static void PrintScanResult(ScanResult result)
		{
			Console.WriteLine();
			Console.WriteLine("ПК: " + result.ComputerName + " | КриптоПро: " + result.CryptoPro.DisplayText
				+ (string.IsNullOrEmpty(result.CryptoPro.LicenseSerialMasked) ? string.Empty : " | лицензия " + result.CryptoPro.LicenseSerialMasked)
				+ (string.IsNullOrEmpty(result.CryptoPro.LicenseValidity) ? string.Empty : " | срок: " + result.CryptoPro.LicenseValidity));
			Console.WriteLine("Сертификатов: " + result.Certificates.Count + " | файлов: " + result.FilesScanned + " (ошибок " + result.FilesFailed + ")"
				+ " | директорий: " + result.DirectoriesScanned + " | время: " + (int)result.Duration.TotalMilliseconds + " мс");
			Console.WriteLine(new string('-', 100));
			foreach (CertificateRecord record in result.Certificates)
			{
				Console.WriteLine(record.SerialNumber + " | " + record.OwnerName + " | УЦ: " + record.CertificationAuthority
					+ " | до " + CertificateParser.FormatDate(record.ValidTo) + (record.IsExpired ? " (ИСТЁК)" : string.Empty)
					+ " | лицензия КриптоПро: " + (record.HasEmbeddedCryptoProLicense ? "да, версия " + record.CryptoProLicenseVersion : "нет"));
			}
			if (result.Warnings.Count > 0)
			{
				Console.WriteLine(new string('-', 100));
				Console.WriteLine("Предупреждения (" + result.Warnings.Count + "):");
				int shown = 0;
				foreach (string warning in result.Warnings)
				{
					Console.WriteLine("  " + warning);
					shown = shown + 1;
					if (shown >= 20)
					{
						Console.WriteLine("  ... полный список — в журнале и XML-результате");
						break;
					}
				}
			}
			Console.WriteLine();
		}

		/// <summary>
		/// Выводит справку по параметрам командной строки.
		/// </summary>
		private static void PrintHelp()
		{
			Console.WriteLine("SkziAgent — агент сбора данных о СКЗИ (команда Red Flag)");
			Console.WriteLine();
			Console.WriteLine("Агент работает в фоне и не показывает окон: служба Windows ждёт запросов панели управления.");
			Console.WriteLine();
			Console.WriteLine("  SkziAgent.exe                      (двойной щелчок) установить службу и работать в фоне; права администратора");
			Console.WriteLine("                                     запрашиваются через UAC, без них можно запустить в фоне без службы");
			Console.WriteLine("  SkziAgent.exe --install            установить как службу Windows и открыть порт в брандмауэре (администратор)");
			Console.WriteLine("  SkziAgent.exe --uninstall          удалить службу");
			Console.WriteLine("  SkziAgent.exe --background         запустить в фоне без окна и без службы (до выхода из системы)");
			Console.WriteLine("  SkziAgent.exe --stop               остановить агент, запущенный через --background");
			Console.WriteLine("  SkziAgent.exe --status             работает ли агент: служба, фоновый режим, ответ на порту");
			Console.WriteLine("  SkziAgent.exe --console            агент в окне консоли до Ctrl+C (для отладки)");
			Console.WriteLine("  SkziAgent.exe --scan               просканировать этот ПК и вывести результат");
			Console.WriteLine("  SkziAgent.exe --scan --dir D:\\Certs ... искать файлы только в указанных папках (можно несколько --dir)");
			Console.WriteLine("  SkziAgent.exe --scan --out r.xml   ... и сохранить результат в XML");
			Console.WriteLine("  SkziAgent.exe --scan --db          ... и записать в MSSQL (DatabaseConnectionString в конфигурации)");
			Console.WriteLine("  --config путь                      использовать другой файл конфигурации");
			Console.WriteLine();
			Console.WriteLine("Журналы: " + Logger.LogDirectory);
		}

		/// <summary>
		/// Проверяет наличие флага в аргументах (без учёта регистра).
		/// </summary>
		private static bool HasFlag(List<string> arguments, string flag)
		{
			foreach (string argument in arguments)
			{
				if (string.Equals(argument, flag, StringComparison.OrdinalIgnoreCase))
				{
					return true;
				}
			}
			return false;
		}

		/// <summary>
		/// Возвращает значение параметра вида «--имя значение» или null.
		/// </summary>
		private static string GetOptionValue(List<string> arguments, string option)
		{
			for (int index = 0; index < arguments.Count - 1; index++)
			{
				if (string.Equals(arguments[index], option, StringComparison.OrdinalIgnoreCase))
				{
					return arguments[index + 1];
				}
			}
			return null;
		}

		/// <summary>
		/// Возвращает все значения повторяющегося параметра вида «--имя значение».
		/// </summary>
		private static List<string> GetOptionValues(List<string> arguments, string option)
		{
			List<string> values = new List<string>();
			for (int index = 0; index < arguments.Count - 1; index++)
			{
				if (string.Equals(arguments[index], option, StringComparison.OrdinalIgnoreCase) && !string.IsNullOrWhiteSpace(arguments[index + 1]))
				{
					values.Add(arguments[index + 1].Trim());
				}
			}
			return values;
		}

		/// <summary>
		/// Включает UTF-8 в консоли, чтобы корректно выводилась кириллица.
		/// </summary>
		private static void TrySetConsoleEncoding()
		{
			try
			{
				if (Environment.UserInteractive)
				{
					Console.OutputEncoding = Encoding.UTF8;
				}
			}
			catch (Exception)
			{
				// Нет консоли — не важно.
			}
		}
	}
}
