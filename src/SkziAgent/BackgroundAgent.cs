using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.ServiceProcess;
using System.Text;
using System.Threading;
using Skzi.Common.Configuration;
using Skzi.Common.Logging;
using Skzi.Common.Network;

namespace Skzi.Agent
{
	/// <summary>
	/// Режим запуска агента, выбранный по параметрам командной строки.
	/// </summary>
	public enum AgentCommand
	{
		/// <summary>Без параметров (двойной щелчок): поставить службу и работать в фоне без окна.</summary>
		Default,
		/// <summary>--service: запуск диспетчером служб Windows.</summary>
		Service,
		/// <summary>--console: агент в окне консоли до Ctrl+C (для отладки).</summary>
		Console,
		/// <summary>--background: запустить скрытую копию агента без службы и сразу вернуться.</summary>
		Background,
		/// <summary>--background-worker: сама скрытая копия (запускается из --background).</summary>
		BackgroundWorker,
		/// <summary>--stop: остановить скрытую копию.</summary>
		Stop,
		/// <summary>--status: показать, работает ли агент.</summary>
		Status,
		/// <summary>--install: установить службу.</summary>
		Install,
		/// <summary>--uninstall: удалить службу.</summary>
		Uninstall,
		/// <summary>--scan: разовое сканирование этого ПК.</summary>
		Scan,
		/// <summary>--help: справка.</summary>
		Help
	}

	/// <summary>
	/// Работа агента в фоне без окна: выбор режима по командной строке, скрытая копия без службы,
	/// установка службы двойным щелчком (с запросом прав администратора), сообщения пользователю.
	/// </summary>
	public static class BackgroundAgent
	{
		public const string WorkerFlag = "--background-worker";
		public const string NoWindowFlag = "--no-window";
		public const int ElevationCancelledExitCode = 1223;
		private const string StopEventName = "Local\\SkziAgent.Background.Stop";
		private const string InstanceMutexName = "Local\\SkziAgent.Background.Instance";
		private const string MessageCaption = "Агент сбора данных о СКЗИ";
		private const int StartWaitMilliseconds = 10000;

		/// <summary>
		/// Определяет режим запуска по параметрам командной строки (без учёта регистра).
		/// Без параметров — режим по умолчанию: агент должен работать в фоне и не показываться.
		/// </summary>
		public static AgentCommand ResolveCommand(IList<string> arguments)
		{
			Dictionary<string, AgentCommand> flags = new Dictionary<string, AgentCommand>(StringComparer.OrdinalIgnoreCase);
			flags["--service"] = AgentCommand.Service;
			flags[WorkerFlag] = AgentCommand.BackgroundWorker;
			flags["--help"] = AgentCommand.Help;
			flags["-h"] = AgentCommand.Help;
			flags["/?"] = AgentCommand.Help;
			flags["--install"] = AgentCommand.Install;
			flags["--uninstall"] = AgentCommand.Uninstall;
			flags["--scan"] = AgentCommand.Scan;
			flags["--console"] = AgentCommand.Console;
			flags["--background"] = AgentCommand.Background;
			flags["--stop"] = AgentCommand.Stop;
			flags["--status"] = AgentCommand.Status;

			// Порядок важен: служебные режимы проверяются раньше пользовательских.
			AgentCommand[] priority = new AgentCommand[]
			{
				AgentCommand.Service, AgentCommand.BackgroundWorker, AgentCommand.Help, AgentCommand.Install, AgentCommand.Uninstall,
				AgentCommand.Scan, AgentCommand.Console, AgentCommand.Background, AgentCommand.Stop, AgentCommand.Status
			};
			HashSet<AgentCommand> requested = new HashSet<AgentCommand>();
			foreach (string argument in arguments)
			{
				AgentCommand command;
				if (argument != null && flags.TryGetValue(argument.Trim(), out command))
				{
					requested.Add(command);
				}
			}
			foreach (AgentCommand command in priority)
			{
				if (requested.Contains(command))
				{
					return command;
				}
			}
			return AgentCommand.Default;
		}

		/// <summary>
		/// Запуск двойным щелчком: окно консоли прячется, агент ставится службой Windows
		/// (запускается вместе с Windows, работает без окна). Нет прав администратора — запрашиваются через UAC;
		/// если отказать, можно запустить агент в фоне без службы до выхода из системы.
		/// </summary>
		public static int RunDefault(string configPath, bool alreadyWithoutWindow)
		{
			if (!alreadyWithoutWindow && HideOwnConsoleWindow())
			{
				// Окно консоли создано только для агента (двойной щелчок). В Windows 11 его показывает Терминал,
				// и спрятать его нельзя, поэтому агент перезапускается без окна, а эта копия сразу выходит — окно закрывается.
				NativeMethods.ProcessInformation hiddenCopy;
				if (TryStartHiddenProcess(NoWindowFlag + " --config \"" + configPath + "\"", out hiddenCopy))
				{
					CloseProcessHandles(hiddenCopy);
					return 0;
				}
			}
			AgentConfig config = Program.LoadConfig(configPath);

			ServiceControllerStatus? serviceStatus = GetServiceStatus();
			if (serviceStatus == ServiceControllerStatus.Running)
			{
				Logger.Info("Запуск без параметров: служба агента уже работает");
				ShowMessage("Агент уже работает в фоне как служба Windows «" + ServiceSetup.ServiceDisplayName + "».\n\n"
					+ "Окно ему не нужно: он ждёт запросов панели управления на порту " + config.ListenPort + ".", MessageIcon.Information);
				return 0;
			}
			if (IsBackgroundCopyRunning())
			{
				Logger.Info("Запуск без параметров: агент уже работает в фоне без службы");
				ShowMessage("Агент уже работает в фоне (без службы, до выхода из системы).\n\n"
					+ "Чтобы он запускался вместе с Windows, установите службу: SkziAgent.exe --install от имени администратора.", MessageIcon.Information);
				return 0;
			}

			Logger.Info("Запуск без параметров: установка агента службой Windows");
			int exitCode = ServiceSetup.IsAdministrator() ? Program.InstallService(configPath) : RunElevated("--install --config \"" + configPath + "\"");
			if (exitCode == 0)
			{
				ShowMessage("Агент установлен как служба Windows и работает в фоне.\n\n"
					+ "Он запускается вместе с Windows, окон не показывает и ждёт запросов панели управления на порту " + config.ListenPort + ".\n"
					+ "Удалить: SkziAgent.exe --uninstall от имени администратора.", MessageIcon.Information);
				return 0;
			}
			if (exitCode == ElevationCancelledExitCode)
			{
				Logger.Warning("Права администратора не предоставлены, служба не установлена");
				bool startWithoutService = AskYesNo("Без прав администратора службу не установить.\n\n"
					+ "Запустить агент в фоне без службы? Он будет работать без окна до выхода из системы "
					+ "и увидит только сертификаты текущего пользователя и указанные папки.");
				if (!startWithoutService)
				{
					return ElevationCancelledExitCode;
				}
				int startCode = StartBackgroundCopy(configPath, config.ListenPort);
				if (startCode == 0)
				{
					ShowMessage("Агент работает в фоне без окна (порт " + config.ListenPort + ").\n\nОстановить: SkziAgent.exe --stop", MessageIcon.Information);
				}
				else
				{
					ShowMessage("Агент не запустился. Подробности в журнале:\n" + Logger.CurrentLogFilePath, MessageIcon.Error);
				}
				return startCode;
			}
			ShowMessage("Не удалось установить службу агента (код " + exitCode + ").\n\nПодробности в журнале:\n" + Logger.CurrentLogFilePath, MessageIcon.Error);
			return exitCode;
		}

		/// <summary>
		/// --background из командной строки: запускает скрытую копию агента и печатает результат.
		/// </summary>
		public static int RunBackgroundCommand(string configPath)
		{
			AgentConfig config = Program.LoadConfig(configPath);
			if (GetServiceStatus() == ServiceControllerStatus.Running)
			{
				System.Console.WriteLine("Агент уже работает в фоне как служба Windows — вторая копия не нужна.");
				return 0;
			}
			if (IsBackgroundCopyRunning())
			{
				System.Console.WriteLine("Агент уже работает в фоне. Остановить: SkziAgent.exe --stop");
				return 0;
			}
			int exitCode = StartBackgroundCopy(configPath, config.ListenPort);
			System.Console.WriteLine(exitCode == 0
				? "Агент работает в фоне без окна (порт " + config.ListenPort + "). Остановить: SkziAgent.exe --stop"
				: "Агент не запустился, подробности в журнале: " + Logger.CurrentLogFilePath);
			return exitCode;
		}

		/// <summary>
		/// Запускает скрытую копию агента (без окна) и ждёт, пока она ответит на порту. Возвращает 0 при успехе.
		/// Копия запускается без наследования дескрипторов: иначе программа, которая читает вывод
		/// «SkziAgent.exe --background», ждала бы завершения фонового агента.
		/// </summary>
		public static int StartBackgroundCopy(string configPath, int port)
		{
			NativeMethods.ProcessInformation processInformation;
			if (!TryStartHiddenProcess(WorkerFlag + " --config \"" + configPath + "\"", out processInformation))
			{
				return 1;
			}
			try
			{
				Stopwatch stopwatch = Stopwatch.StartNew();
				while (stopwatch.ElapsedMilliseconds < StartWaitMilliseconds)
				{
					if (NativeMethods.WaitForSingleObject(processInformation.hProcess, 0) == NativeMethods.WaitObject0)
					{
						uint workerExitCode;
						NativeMethods.GetExitCodeProcess(processInformation.hProcess, out workerExitCode);
						Logger.Error("Фоновый агент завершился сразу после запуска (код " + workerExitCode + "), подробности выше в журнале");
						return workerExitCode == 0 ? 1 : (int)workerExitCode;
					}
					if (ProbeLocalAgent(port, 500) != null)
					{
						Logger.Info("Агент запущен в фоне без окна, PID " + processInformation.dwProcessId);
						return 0;
					}
					Thread.Sleep(200);
				}
				Logger.Error("Фоновый агент не ответил на порту " + port + " за " + StartWaitMilliseconds / 1000 + " с");
				return 1;
			}
			finally
			{
				CloseProcessHandles(processInformation);
			}
		}

		/// <summary>
		/// Запускает эту же программу с параметрами без окна и без наследования дескрипторов.
		/// Возвращает false (и пишет ошибку в журнал), если запустить не удалось.
		/// </summary>
		private static bool TryStartHiddenProcess(string arguments, out NativeMethods.ProcessInformation processInformation)
		{
			string executablePath = Assembly.GetExecutingAssembly().Location;
			StringBuilder commandLine = new StringBuilder("\"" + executablePath + "\" " + arguments);
			NativeMethods.StartupInfo startupInfo = new NativeMethods.StartupInfo();
			startupInfo.cb = Marshal.SizeOf(typeof(NativeMethods.StartupInfo));
			bool started = NativeMethods.CreateProcessW(null, commandLine, IntPtr.Zero, IntPtr.Zero, false,
				NativeMethods.CreateNoWindow | NativeMethods.CreateNewProcessGroup, IntPtr.Zero,
				Path.GetDirectoryName(executablePath), ref startupInfo, out processInformation);
			if (!started)
			{
				Logger.Error("Не удалось запустить агент без окна: " + arguments, new Win32Exception(Marshal.GetLastWin32Error()));
			}
			return started;
		}

		/// <summary>
		/// Закрывает дескрипторы процесса и потока, полученные при запуске.
		/// </summary>
		private static void CloseProcessHandles(NativeMethods.ProcessInformation processInformation)
		{
			NativeMethods.CloseHandle(processInformation.hThread);
			NativeMethods.CloseHandle(processInformation.hProcess);
		}

		/// <summary>
		/// Работа скрытой копии: TCP-сервер агента до команды --stop или выхода пользователя из системы.
		/// Вторая копия не запускается.
		/// </summary>
		public static int RunWorker(string configPath)
		{
			bool createdNew;
			using (Mutex instanceMutex = new Mutex(true, InstanceMutexName, out createdNew))
			{
				if (!createdNew)
				{
					Logger.Warning("Агент уже работает в фоне, вторая копия не запускается");
					return 0;
				}
				try
				{
					using (EventWaitHandle stopEvent = new EventWaitHandle(false, EventResetMode.ManualReset, StopEventName))
					{
						AgentConfig config = Program.LoadConfig(configPath);
						AgentServer server = new AgentServer(config);
						server.Start();
						Logger.Info("Агент работает в фоне без окна: порт " + config.ListenPort + ", PID " + Process.GetCurrentProcess().Id
							+ ", пользователь " + Skzi.Common.Scanning.CertificateCollector.GetCurrentAccountName());
						stopEvent.WaitOne();
						server.Stop();
						Logger.Info("Фоновый агент остановлен командой --stop");
					}
				}
				finally
				{
					instanceMutex.ReleaseMutex();
				}
			}
			return 0;
		}

		/// <summary>
		/// --stop: останавливает скрытую копию агента и ждёт её завершения. Службу не трогает.
		/// </summary>
		public static int RunStopCommand()
		{
			if (!StopBackgroundCopy())
			{
				string serviceHint = GetServiceStatus().HasValue ? " Служба агента управляется через «Службы» или SkziAgent.exe --uninstall." : string.Empty;
				System.Console.WriteLine("Агент в фоне без службы не запущен." + serviceHint);
				return 0;
			}
			System.Console.WriteLine("Фоновый агент остановлен.");
			return 0;
		}

		/// <summary>
		/// Подаёт скрытой копии сигнал остановки и ждёт её завершения (до 10 с). Возвращает false, если копии нет.
		/// </summary>
		public static bool StopBackgroundCopy()
		{
			EventWaitHandle stopEvent;
			if (!EventWaitHandle.TryOpenExisting(StopEventName, out stopEvent))
			{
				return false;
			}
			using (stopEvent)
			{
				stopEvent.Set();
			}
			Stopwatch stopwatch = Stopwatch.StartNew();
			while (IsBackgroundCopyRunning() && stopwatch.ElapsedMilliseconds < StartWaitMilliseconds)
			{
				Thread.Sleep(100);
			}
			Logger.Info("Фоновому агенту отправлена команда остановки");
			return true;
		}

		/// <summary>
		/// --status: печатает состояние службы, скрытой копии и ответ агента на порту.
		/// </summary>
		public static int RunStatusCommand(string configPath)
		{
			AgentConfig config = ConfigFile.LoadOrCreate<AgentConfig>(configPath, AgentConfig.CreateDefault);
			ServiceControllerStatus? serviceStatus = GetServiceStatus();
			System.Console.WriteLine("Служба «" + ServiceSetup.ServiceDisplayName + "»: "
				+ (serviceStatus.HasValue ? DescribeServiceStatus(serviceStatus.Value) : "не установлена"));
			System.Console.WriteLine("Агент в фоне без службы: " + (IsBackgroundCopyRunning() ? "работает" : "не запущен"));
			AgentHello hello = ProbeLocalAgent(config.ListenPort, 2000);
			System.Console.WriteLine("Порт " + config.ListenPort + ": " + (hello != null
				? "агент отвечает (ПК " + hello.ComputerName + ", версия " + hello.AgentVersion + ")"
				: "агент не отвечает"));
			return hello != null ? 0 : 4;
		}

		/// <summary>
		/// Проверяет, работает ли скрытая копия агента в этом сеансе Windows.
		/// </summary>
		public static bool IsBackgroundCopyRunning()
		{
			Mutex instanceMutex;
			if (!Mutex.TryOpenExisting(InstanceMutexName, out instanceMutex))
			{
				return false;
			}
			instanceMutex.Dispose();
			return true;
		}

		/// <summary>
		/// Возвращает состояние службы агента или null, если служба не установлена либо недоступна
		/// текущему пользователю (у службы ограничен доступ — её видят только администраторы и система).
		/// </summary>
		public static ServiceControllerStatus? GetServiceStatus()
		{
			try
			{
				using (ServiceController controller = new ServiceController(ServiceSetup.ServiceName))
				{
					return controller.Status;
				}
			}
			catch (Exception)
			{
				// InvalidOperationException — службы нет; Win32Exception «Отказано в доступе» — служба скрыта от этого пользователя.
				return null;
			}
		}

		/// <summary>
		/// Переводит состояние службы в текст для пользователя.
		/// </summary>
		private static string DescribeServiceStatus(ServiceControllerStatus status)
		{
			switch (status)
			{
				case ServiceControllerStatus.Running:
					return "работает";
				case ServiceControllerStatus.Stopped:
					return "остановлена";
				case ServiceControllerStatus.StartPending:
					return "запускается";
				case ServiceControllerStatus.StopPending:
					return "останавливается";
				default:
					return status.ToString();
			}
		}

		/// <summary>
		/// Спрашивает у агента на этом ПК приветствие; null — агент не отвечает.
		/// </summary>
		private static AgentHello ProbeLocalAgent(int port, int timeoutMilliseconds)
		{
			try
			{
				return AgentClient.ProbeAsync("127.0.0.1", port, timeoutMilliseconds, CancellationToken.None).Result;
			}
			catch (Exception)
			{
				return null;
			}
		}

		/// <summary>
		/// Запускает эту же программу с правами администратора (окно UAC) без окна консоли и ждёт её завершения.
		/// Возвращает код выхода или ElevationCancelledExitCode, если пользователь отказал.
		/// </summary>
		private static int RunElevated(string arguments)
		{
			ProcessStartInfo startInfo = new ProcessStartInfo(Assembly.GetExecutingAssembly().Location, arguments);
			startInfo.UseShellExecute = true;
			startInfo.Verb = "runas";
			startInfo.WindowStyle = ProcessWindowStyle.Hidden;
			try
			{
				using (Process process = Process.Start(startInfo))
				{
					process.WaitForExit();
					return process.ExitCode;
				}
			}
			catch (Win32Exception exception)
			{
				if (exception.NativeErrorCode == ElevationCancelledExitCode)
				{
					return ElevationCancelledExitCode;
				}
				Logger.Error("Не удалось запустить агент с правами администратора", exception);
				return 1;
			}
		}

		/// <summary>
		/// Прячет окно консоли, если оно создано только для этого процесса (запуск двойным щелчком).
		/// Если агент запущен из командной строки, её окно не трогается.
		/// </summary>
		public static bool HideOwnConsoleWindow()
		{
			try
			{
				uint[] processIds = new uint[4];
				uint attachedCount = NativeMethods.GetConsoleProcessList(processIds, (uint)processIds.Length);
				IntPtr consoleWindow = NativeMethods.GetConsoleWindow();
				if (attachedCount != 1 || consoleWindow == IntPtr.Zero)
				{
					return false;
				}
				NativeMethods.ShowWindow(consoleWindow, NativeMethods.SwHide);
				return true;
			}
			catch (Exception)
			{
				return false;
			}
		}

		/// <summary>
		/// Значок окна сообщения.
		/// </summary>
		private enum MessageIcon
		{
			Information,
			Error
		}

		/// <summary>
		/// Показывает окно сообщения поверх остальных окон.
		/// </summary>
		private static void ShowMessage(string text, MessageIcon icon)
		{
			uint iconFlag = icon == MessageIcon.Error ? NativeMethods.MbIconError : NativeMethods.MbIconInformation;
			NativeMethods.MessageBoxW(IntPtr.Zero, text, MessageCaption, NativeMethods.MbOk | iconFlag | NativeMethods.MbSetForeground | NativeMethods.MbTopMost);
		}

		/// <summary>
		/// Задаёт вопрос «Да/Нет» и возвращает true, если выбрано «Да».
		/// </summary>
		private static bool AskYesNo(string text)
		{
			int answer = NativeMethods.MessageBoxW(IntPtr.Zero, text, MessageCaption,
				NativeMethods.MbYesNo | NativeMethods.MbIconQuestion | NativeMethods.MbSetForeground | NativeMethods.MbTopMost);
			return answer == NativeMethods.IdYes;
		}

		/// <summary>
		/// Функции Windows для запуска процесса без окна, работы с окном консоли и окнами сообщений.
		/// </summary>
		private static class NativeMethods
		{
			public const uint CreateNoWindow = 0x08000000;
			public const uint CreateNewProcessGroup = 0x00000200;
			public const uint WaitObject0 = 0;
			public const int SwHide = 0;
			public const uint MbOk = 0x0;
			public const uint MbYesNo = 0x4;
			public const uint MbIconError = 0x10;
			public const uint MbIconQuestion = 0x20;
			public const uint MbIconInformation = 0x40;
			public const uint MbSetForeground = 0x10000;
			public const uint MbTopMost = 0x40000;
			public const int IdYes = 6;

			/// <summary>
			/// Параметры запуска процесса (STARTUPINFOW).
			/// </summary>
			[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
			public struct StartupInfo
			{
				public int cb;
				public string lpReserved;
				public string lpDesktop;
				public string lpTitle;
				public int dwX;
				public int dwY;
				public int dwXSize;
				public int dwYSize;
				public int dwXCountChars;
				public int dwYCountChars;
				public int dwFillAttribute;
				public int dwFlags;
				public short wShowWindow;
				public short cbReserved2;
				public IntPtr lpReserved2;
				public IntPtr hStdInput;
				public IntPtr hStdOutput;
				public IntPtr hStdError;
			}

			/// <summary>
			/// Сведения о запущенном процессе (PROCESS_INFORMATION).
			/// </summary>
			[StructLayout(LayoutKind.Sequential)]
			public struct ProcessInformation
			{
				public IntPtr hProcess;
				public IntPtr hThread;
				public int dwProcessId;
				public int dwThreadId;
			}

			[DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
			[return: MarshalAs(UnmanagedType.Bool)]
			public static extern bool CreateProcessW(string applicationName, StringBuilder commandLine, IntPtr processAttributes, IntPtr threadAttributes,
				[MarshalAs(UnmanagedType.Bool)] bool inheritHandles, uint creationFlags, IntPtr environment, string currentDirectory,
				ref StartupInfo startupInfo, out ProcessInformation processInformation);

			[DllImport("kernel32.dll", SetLastError = true)]
			public static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);

			[DllImport("kernel32.dll", SetLastError = true)]
			[return: MarshalAs(UnmanagedType.Bool)]
			public static extern bool GetExitCodeProcess(IntPtr process, out uint exitCode);

			[DllImport("kernel32.dll", SetLastError = true)]
			[return: MarshalAs(UnmanagedType.Bool)]
			public static extern bool CloseHandle(IntPtr handle);

			[DllImport("kernel32.dll", SetLastError = true)]
			public static extern uint GetConsoleProcessList([Out] uint[] processIds, uint processCount);

			[DllImport("kernel32.dll")]
			public static extern IntPtr GetConsoleWindow();

			[DllImport("user32.dll")]
			[return: MarshalAs(UnmanagedType.Bool)]
			public static extern bool ShowWindow(IntPtr window, int command);

			[DllImport("user32.dll", CharSet = CharSet.Unicode)]
			public static extern int MessageBoxW(IntPtr owner, string text, string caption, uint type);
		}
	}
}
