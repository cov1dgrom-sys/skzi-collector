using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using Skzi.Common.Configuration;
using Skzi.Common.Database;
using Skzi.Common.Logging;
using Skzi.Common.Scanning;

namespace Skzi.ControlPanel
{
	/// <summary>
	/// Точка входа панели управления.
	/// </summary>
	public static class Program
	{
		public const string ConfigFileName = "panel.config.xml";

		// Код завершения «нет прав администратора» (как ERROR_ACCESS_DENIED в Windows).
		public const int AccessDeniedExitCode = 5;

		/// <summary>
		/// Проверяет, запущена ли панель с правами администратора (с повышенными правами при включённом UAC).
		/// </summary>
		public static bool IsRunningAsAdministrator()
		{
			using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
			{
				return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
			}
		}

		/// <summary>
		/// Перезапускает панель с запросом прав администратора (UAC) и теми же параметрами.
		/// Возвращает false, если пользователь отказался или повысить права нельзя.
		/// </summary>
		private static bool RestartAsAdministrator(string[] args)
		{
			StringBuilder arguments = new StringBuilder();
			foreach (string argument in args)
			{
				arguments.Append(arguments.Length > 0 ? " " : string.Empty).Append('"').Append(argument.Replace("\"", "\\\"")).Append('"');
			}
			ProcessStartInfo startInfo = new ProcessStartInfo(Application.ExecutablePath, arguments.ToString());
			startInfo.UseShellExecute = true;
			startInfo.Verb = "runas";
			startInfo.WorkingDirectory = AppDomain.CurrentDomain.BaseDirectory;
			try
			{
				Process.Start(startInfo);
				return true;
			}
			catch (Win32Exception exception)
			{
				Logger.Warning("Права администратора не получены: " + exception.Message);
				return false;
			}
		}

		/// <summary>
		/// Настраивает журнал и обработку исключений, читает конфигурацию и открывает главное окно.
		/// </summary>
		[STAThread]
		public static int Main(string[] args)
		{
			Logger.Initialize("SkziControlPanel", "logs", false);
			Logger.RegisterGlobalExceptionHandlers();
			Application.SetUnhandledExceptionMode(UnhandledExceptionMode.CatchException);
			Application.ThreadException += OnUiThreadException;
			Application.EnableVisualStyles();
			Application.SetCompatibleTextRenderingDefault(false);

			Logger.Info("Приложение запущено. User login: " + Environment.UserName + ", ПК: " + Environment.MachineName
				+ ", версия: " + CertificateCollector.GetScannerVersion());

			bool headlessScan = false;
			string configPath = ConfigFile.GetDefaultPath(ConfigFileName);
			foreach (string argument in args)
			{
				if (string.Equals(argument, "--scan-all", StringComparison.OrdinalIgnoreCase))
				{
					headlessScan = true;
				}
				else if (!argument.StartsWith("--", StringComparison.Ordinal))
				{
					configPath = argument;
				}
			}

			// Панель запускается только от имени администратора (на АРМ проверяющего): рядовой сотрудник
			// не может открыть её и сканировать сеть, даже если знает общий ключ.
			if (!IsRunningAsAdministrator())
			{
				if (headlessScan)
				{
					Logger.Error("Плановое сканирование не выполнено: панель управления запускается только от имени администратора"
						+ " (в задании Планировщика включите «Выполнять с наивысшими правами»)");
					Logger.Info("Выход из приложения (нет прав администратора)");
					return AccessDeniedExitCode;
				}
				if (RestartAsAdministrator(args))
				{
					Logger.Info("Перезапуск панели с правами администратора");
					return 0;
				}
				MessageBox.Show("Панель управления запускается только от имени администратора.\n\n"
					+ "Запустите её на АРМ проверяющего и подтвердите запрос прав администратора.",
					"Модуль сбора данных о СКЗИ", MessageBoxButtons.OK, MessageBoxIcon.Warning);
				Logger.Info("Выход из приложения (нет прав администратора)");
				return AccessDeniedExitCode;
			}

			PanelConfig config;
			try
			{
				config = ConfigFile.LoadOrCreate<PanelConfig>(configPath, PanelConfig.CreateDefault);
			}
			catch (Exception exception)
			{
				if (headlessScan)
				{
					Logger.Info("Выход из приложения (ошибка конфигурации)");
					return 1;
				}
				DialogResult answer = MessageBox.Show("Файл конфигурации повреждён:\n" + configPath + "\n\n" + exception.Message
					+ "\n\nЗапустить с настройками по умолчанию? (файл будет перезаписан при сохранении настроек)",
					"Ошибка конфигурации", MessageBoxButtons.YesNo, MessageBoxIcon.Error);
				if (answer != DialogResult.Yes)
				{
					Logger.Info("Выход из приложения (ошибка конфигурации)");
					return 1;
				}
				config = PanelConfig.CreateDefault();
			}
			Logger.Initialize("SkziControlPanel", config.LogDirectory, false);
			Logger.ConfigureRotation(config.LogRetentionDays, config.LogMaxFileSizeMb);
			if (string.IsNullOrWhiteSpace(config.Database.Server))
			{
				config.Database.Server = SqlServerLocator.SuggestDefaultServer();
				Logger.Info("Сервер MSSQL в конфигурации не указан — выбран найденный на этом ПК: " + config.Database.Server);
			}

			if (headlessScan)
			{
				int failedHosts = RunHeadlessScan(config);
				Logger.Info("Выход из приложения");
				return failedHosts;
			}

			Application.Run(new MainForm(configPath, config));
			Logger.Info("Выход из приложения");
			return 0;
		}

		/// <summary>
		/// Сканирование всех ПК из конфигурации без окна (для Планировщика заданий Windows):
		/// способ — DefaultScanMode, результаты пишутся в БД. Возвращает число ПК с ошибками.
		/// </summary>
		private static int RunHeadlessScan(PanelConfig config)
		{
			ScanMethod method = string.Equals(config.DefaultScanMode, "Agentless", StringComparison.OrdinalIgnoreCase) ? ScanMethod.Agentless : ScanMethod.Agent;
			Logger.Info("Плановое сканирование всех ПК (без окна): ПК " + config.Hosts.Count + ", способ " + method);
			ScanCoordinator coordinator = new ScanCoordinator(config);
			SemaphoreSlim limiter = new SemaphoreSlim(Math.Max(1, config.MaxParallelScans));
			int failedCount = 0;
			List<Task> tasks = new List<Task>();
			foreach (string host in config.Hosts)
			{
				string address = host;
				tasks.Add(Task.Run(async () =>
				{
					await limiter.WaitAsync().ConfigureAwait(false);
					try
					{
						HostScanOutcome outcome = await coordinator.ScanHostAsync(address, method, CancellationToken.None).ConfigureAwait(false);
						Logger.Info("ПК " + address + ": сертификатов " + outcome.Result.Certificates.Count
							+ (outcome.DatabaseStatistics != null ? ", БД: " + outcome.DatabaseStatistics : string.Empty)
							+ (outcome.DatabaseError != null ? ", ошибка БД: " + outcome.DatabaseError : string.Empty));
						if (outcome.DatabaseError != null)
						{
							Interlocked.Increment(ref failedCount);
						}
					}
					catch (Exception exception)
					{
						Interlocked.Increment(ref failedCount);
						Logger.Error("Ошибка сканирования ПК " + address + ": " + ScanCoordinator.DescribeError(exception, config.AgentPort), exception);
					}
					finally
					{
						limiter.Release();
					}
				}));
			}
			Task.WaitAll(tasks.ToArray());
			Logger.Info("Плановое сканирование завершено: ПК " + config.Hosts.Count + ", с ошибками " + failedCount);
			return failedCount;
		}

		/// <summary>
		/// Перехватывает необработанные исключения в потоке интерфейса: запись в журнал и сообщение пользователю.
		/// </summary>
		private static void OnUiThreadException(object sender, ThreadExceptionEventArgs eventArgs)
		{
			Logger.Error("Необработанное исключение в интерфейсе", eventArgs.Exception);
			MessageBox.Show("Произошла ошибка: " + eventArgs.Exception.Message + "\n\nПодробности записаны в журнал:\n" + Logger.CurrentLogFilePath,
				"Ошибка", MessageBoxButtons.OK, MessageBoxIcon.Error);
		}
	}
}
