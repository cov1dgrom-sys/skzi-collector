using System;
using System.Globalization;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Skzi.Common.Logging
{
	/// <summary>
	/// Уровень важности записи журнала.
	/// </summary>
	public enum LogLevel
	{
		Info,
		Warning,
		Error
	}

	/// <summary>
	/// Аргументы события записи строки в журнал (используется панелью для показа журнала в окне).
	/// </summary>
	public sealed class LogLineEventArgs : EventArgs
	{
		public LogLevel Level { get; private set; }
		public string Line { get; private set; }

		/// <summary>
		/// Создаёт аргументы события с уровнем и текстом строки журнала.
		/// </summary>
		public LogLineEventArgs(LogLevel level, string line)
		{
			Level = level;
			Line = line;
		}
	}

	/// <summary>
	/// Потокобезопасный файловый журнал.
	/// Формат строки: «16.09.25 08:43:23.739 - [INFO] Текст сообщения» (дата и время с точностью до миллисекунд и уровень).
	/// Ротация: новый файл на каждые сутки (logs\ИмяПриложения_ГГГГ-ММ-ДД.log), при превышении размера — следующая часть
	/// (ИмяПриложения_ГГГГ-ММ-ДД_2.log); файлы старше заданного числа суток удаляются.
	/// </summary>
	public static class Logger
	{
		private const string TimestampFormat = "dd.MM.yy HH:mm:ss.fff";
		public const int DefaultRetentionDays = 30;
		public const int DefaultMaxFileSizeMb = 10;

		private static readonly object WriteLock = new object();
		private static string applicationName = "Skzi";
		private static string logDirectory = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "logs");
		private static bool writeToConsole;
		private static bool globalHandlersRegistered;
		private static int retentionDays = DefaultRetentionDays;
		private static long maxFileSizeBytes = DefaultMaxFileSizeMb * 1024L * 1024L;
		private static DateTime currentFileDate = DateTime.MinValue;
		private static int currentFilePart = 1;
		private static DateTime lastCleanupDate = DateTime.MinValue;

		/// <summary>
		/// Событие возникает после записи каждой строки в журнал.
		/// </summary>
		public static event EventHandler<LogLineEventArgs> LineWritten;

		/// <summary>
		/// Папка, в которую пишутся файлы журнала.
		/// </summary>
		public static string LogDirectory
		{
			get { return logDirectory; }
		}

		/// <summary>
		/// Полный путь к текущему файлу журнала (за текущие сутки, с учётом номера части при ротации по размеру).
		/// </summary>
		public static string CurrentLogFilePath
		{
			get
			{
				lock (WriteLock)
				{
					DateTime today = DateTime.Today;
					int part = currentFileDate == today ? currentFilePart : 1;
					return BuildLogFilePath(today, part);
				}
			}
		}

		/// <summary>
		/// Сколько суток хранятся файлы журнала (0 — не удалять).
		/// </summary>
		public static int RetentionDays
		{
			get { return retentionDays; }
		}

		/// <summary>
		/// Формирует путь к файлу журнала за указанные сутки: первая часть без номера, следующие — с «_2», «_3»…
		/// </summary>
		private static string BuildLogFilePath(DateTime date, int part)
		{
			string fileName = applicationName + "_" + date.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture)
				+ (part > 1 ? "_" + part.ToString(CultureInfo.InvariantCulture) : string.Empty) + ".log";
			return Path.Combine(logDirectory, fileName);
		}

		/// <summary>
		/// Настраивает журнал: имя приложения (префикс файла), папку журналов и дублирование в консоль.
		/// </summary>
		public static void Initialize(string appName, string directory, bool duplicateToConsole)
		{
			lock (WriteLock)
			{
				if (!string.IsNullOrWhiteSpace(appName))
				{
					applicationName = appName;
				}
				if (!string.IsNullOrWhiteSpace(directory))
				{
					logDirectory = Path.IsPathRooted(directory)
						? directory
						: Path.Combine(AppDomain.CurrentDomain.BaseDirectory, directory);
				}
				writeToConsole = duplicateToConsole;
				currentFileDate = DateTime.MinValue;
				lastCleanupDate = DateTime.MinValue;
			}
		}

		/// <summary>
		/// Настраивает ротацию: срок хранения файлов (сутки, 0 — хранить всё) и максимальный размер одного файла (МБ, 0 — без ограничения).
		/// </summary>
		public static void ConfigureRotation(int keepDays, int maxSizeMb)
		{
			lock (WriteLock)
			{
				retentionDays = Math.Max(0, keepDays);
				maxFileSizeBytes = Math.Max(0, maxSizeMb) * 1024L * 1024L;
				lastCleanupDate = DateTime.MinValue;
			}
		}

		/// <summary>
		/// Текстовая метка уровня для строки журнала.
		/// </summary>
		public static string GetLevelTag(LogLevel level)
		{
			switch (level)
			{
				case LogLevel.Warning:
					return "[WARN]";
				case LogLevel.Error:
					return "[ERROR]";
				default:
					return "[INFO]";
			}
		}

		/// <summary>
		/// Подписывается на все глобальные необработанные исключения, чтобы они гарантированно попадали в журнал.
		/// </summary>
		public static void RegisterGlobalExceptionHandlers()
		{
			if (globalHandlersRegistered)
			{
				return;
			}
			globalHandlersRegistered = true;

			AppDomain.CurrentDomain.UnhandledException += delegate (object sender, UnhandledExceptionEventArgs eventArgs)
			{
				Exception exception = eventArgs.ExceptionObject as Exception;
				Error("Необработанное исключение в домене приложения (завершение: " + eventArgs.IsTerminating + ")", exception);
			};

			TaskScheduler.UnobservedTaskException += delegate (object sender, UnobservedTaskExceptionEventArgs eventArgs)
			{
				Error("Необработанное исключение в фоновой задаче", eventArgs.Exception);
				eventArgs.SetObserved();
			};
		}

		/// <summary>
		/// Записывает информационное сообщение.
		/// </summary>
		public static void Info(string message)
		{
			Write(LogLevel.Info, message);
		}

		/// <summary>
		/// Записывает предупреждение (некорректная, но не критичная ситуация).
		/// </summary>
		public static void Warning(string message)
		{
			Write(LogLevel.Warning, message);
		}

		/// <summary>
		/// Записывает сообщение об ошибке без исключения.
		/// </summary>
		public static void Error(string message)
		{
			Write(LogLevel.Error, message);
		}

		/// <summary>
		/// Записывает сообщение об ошибке вместе с полной информацией об исключении (тип, текст, стек, вложенные исключения).
		/// </summary>
		public static void Error(string message, Exception exception)
		{
			if (exception == null)
			{
				Error(message);
				return;
			}
			Write(LogLevel.Error, message + Environment.NewLine + DescribeException(exception));
		}

		/// <summary>
		/// Формирует подробное текстовое описание исключения, включая цепочку InnerException.
		/// </summary>
		public static string DescribeException(Exception exception)
		{
			StringBuilder builder = new StringBuilder();
			int depth = 0;
			Exception current = exception;
			while (current != null && depth < 10)
			{
				string indent = new string(' ', 4 + depth * 2);
				builder.Append(indent).Append(depth == 0 ? "Исключение: " : "Вложенное исключение: ")
					.Append(current.GetType().FullName).Append(": ").Append(current.Message).AppendLine();
				if (!string.IsNullOrEmpty(current.StackTrace))
				{
					builder.Append(indent).AppendLine("Стек вызовов:");
					foreach (string stackLine in current.StackTrace.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
					{
						builder.Append(indent).Append("  ").AppendLine(stackLine.Trim());
					}
				}
				AggregateException aggregate = current as AggregateException;
				if (aggregate != null && aggregate.InnerExceptions.Count > 1)
				{
					for (int index = 1; index < aggregate.InnerExceptions.Count; index++)
					{
						builder.Append(indent).Append("Дополнительное исключение: ")
							.Append(aggregate.InnerExceptions[index].GetType().FullName).Append(": ")
							.Append(aggregate.InnerExceptions[index].Message).AppendLine();
					}
				}
				current = current.InnerException;
				depth = depth + 1;
			}
			return builder.ToString().TrimEnd();
		}

		/// <summary>
		/// Формирует строку журнала с отметкой времени и уровнем и дописывает её в файл. Ошибки записи журнала не пробрасываются.
		/// </summary>
		private static void Write(LogLevel level, string message)
		{
			DateTime now = DateTime.Now;
			string line = FormatLine(now, level, message);
			lock (WriteLock)
			{
				try
				{
					Directory.CreateDirectory(logDirectory);
					string filePath = SelectFileForWriting(now.Date);
					File.AppendAllText(filePath, line + Environment.NewLine, Encoding.UTF8);
					if (lastCleanupDate != now.Date)
					{
						lastCleanupDate = now.Date;
						DeleteExpiredFiles(now.Date);
					}
				}
				catch (Exception writeException)
				{
					// Журнал не должен ронять приложение — пишем проблему в отладочный вывод.
					System.Diagnostics.Debug.WriteLine("Не удалось записать журнал: " + writeException.Message);
				}

				if (writeToConsole)
				{
					WriteToConsole(level, line);
				}
			}

			EventHandler<LogLineEventArgs> handler = LineWritten;
			if (handler != null)
			{
				try
				{
					handler(null, new LogLineEventArgs(level, line));
				}
				catch (Exception)
				{
					// Ошибка подписчика не должна мешать записи журнала.
				}
			}
		}

		/// <summary>
		/// Формирует строку журнала: «16.09.25 08:43:23.739 - [INFO] текст».
		/// </summary>
		public static string FormatLine(DateTime timestamp, LogLevel level, string message)
		{
			return timestamp.ToString(TimestampFormat, CultureInfo.InvariantCulture) + " - " + GetLevelTag(level) + " " + (message ?? string.Empty);
		}

		/// <summary>
		/// Выбирает файл для записи: при смене суток начинает новый файл, при превышении размера — следующую часть.
		/// Вызывается под блокировкой WriteLock.
		/// </summary>
		private static string SelectFileForWriting(DateTime today)
		{
			if (currentFileDate != today)
			{
				currentFileDate = today;
				currentFilePart = 1;
				// После перезапуска продолжаем запись в последнюю существующую часть за сегодня.
				while (File.Exists(BuildLogFilePath(today, currentFilePart + 1)))
				{
					currentFilePart = currentFilePart + 1;
				}
			}
			string filePath = BuildLogFilePath(today, currentFilePart);
			if (maxFileSizeBytes > 0)
			{
				FileInfo fileInfo = new FileInfo(filePath);
				if (fileInfo.Exists && fileInfo.Length >= maxFileSizeBytes)
				{
					currentFilePart = currentFilePart + 1;
					filePath = BuildLogFilePath(today, currentFilePart);
				}
			}
			return filePath;
		}

		/// <summary>
		/// Удаляет файлы журнала этого приложения старше срока хранения. Вызывается под блокировкой WriteLock.
		/// </summary>
		private static void DeleteExpiredFiles(DateTime today)
		{
			if (retentionDays <= 0)
			{
				return;
			}
			DateTime oldestKeptDate = today.AddDays(-retentionDays);
			try
			{
				foreach (string filePath in Directory.GetFiles(logDirectory, applicationName + "_*.log"))
				{
					DateTime fileDate;
					if (TryGetLogFileDate(Path.GetFileNameWithoutExtension(filePath), out fileDate) && fileDate < oldestKeptDate)
					{
						File.Delete(filePath);
					}
				}
			}
			catch (Exception cleanupException)
			{
				System.Diagnostics.Debug.WriteLine("Не удалось удалить старые журналы: " + cleanupException.Message);
			}
		}

		/// <summary>
		/// Извлекает дату из имени файла журнала «Приложение_ГГГГ-ММ-ДД» или «Приложение_ГГГГ-ММ-ДД_N».
		/// </summary>
		public static bool TryGetLogFileDate(string fileNameWithoutExtension, out DateTime fileDate)
		{
			fileDate = DateTime.MinValue;
			string prefix = applicationName + "_";
			if (fileNameWithoutExtension == null || !fileNameWithoutExtension.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
			{
				return false;
			}
			string rest = fileNameWithoutExtension.Substring(prefix.Length);
			if (rest.Length < 10)
			{
				return false;
			}
			return DateTime.TryParseExact(rest.Substring(0, 10), "yyyy-MM-dd", CultureInfo.InvariantCulture, DateTimeStyles.None, out fileDate);
		}

		/// <summary>
		/// Выводит строку журнала в консоль, подсвечивая предупреждения и ошибки цветом.
		/// </summary>
		private static void WriteToConsole(LogLevel level, string line)
		{
			try
			{
				ConsoleColor previousColor = Console.ForegroundColor;
				if (level == LogLevel.Error)
				{
					Console.ForegroundColor = ConsoleColor.Red;
				}
				else if (level == LogLevel.Warning)
				{
					Console.ForegroundColor = ConsoleColor.Yellow;
				}
				Console.WriteLine(line);
				Console.ForegroundColor = previousColor;
			}
			catch (Exception)
			{
				// Консоль может отсутствовать (служба Windows) — это не ошибка.
			}
		}
	}
}
