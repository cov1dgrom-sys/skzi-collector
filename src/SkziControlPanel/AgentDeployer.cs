using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using Skzi.Common.Configuration;
using Skzi.Common.Logging;

namespace Skzi.ControlPanel
{
	/// <summary>
	/// Развёртывание и удаление агента на удалённых ПК из панели управления:
	/// копирование файлов через административный ресурс (\\ПК\C$) и регистрация службы через «sc \\ПК».
	/// Требуются права локального администратора на целевом ПК.
	/// </summary>
	public static class AgentDeployer
	{
		public const string ServiceName = "SkziAgent";
		public const string AgentExecutableName = "SkziAgent.exe";
		public const string AgentConfigName = "agent.config.xml";
		private const string ServiceDisplayName = "СКЗИ: агент сбора данных о сертификатах";
		private const string ServiceDescription = "Собирает сведения о личных сертификатах и КриптоПро CSP по запросу панели управления (команда Red Flag).";

		// Дескриптор безопасности службы — тот же, что при локальной установке (ServiceSetup.RestrictedServiceSecurity):
		// полный доступ у системы и администраторов, аудит обращений; обычный пользователь службу не видит и не останавливает.
		public const string ServiceSecurityDescriptor =
			"D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)";

		/// <summary>
		/// Копирует агент на ПК, создаёт конфигурацию из настроек панели, регистрирует и запускает службу.
		/// Возвращает описание результата; при ошибке бросает исключение.
		/// </summary>
		public static string Deploy(string host, PanelConfig config)
		{
			string sourceExecutable = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, AgentExecutableName);
			if (!File.Exists(sourceExecutable))
			{
				throw new FileNotFoundException("Рядом с панелью не найден файл агента " + AgentExecutableName, sourceExecutable);
			}

			string installPath = string.IsNullOrWhiteSpace(config.AgentInstallPath) ? @"C:\Program Files\SkziAgent" : config.AgentInstallPath.TrimEnd('\\');
			string accessibleInstallPath = ToAccessiblePath(host, installPath);
			string remoteExecutablePath = installPath + "\\" + AgentExecutableName;
			string serverArgument = ScanCoordinator.IsLocalHost(host) ? string.Empty : "\\\\" + host + " ";

			Logger.Info("Развёртывание агента на " + host + " в " + installPath);
			RunServiceControl(serverArgument + "stop " + ServiceName, false);
			WaitForServiceStopped(serverArgument);

			Directory.CreateDirectory(accessibleInstallPath);
			File.Copy(sourceExecutable, Path.Combine(accessibleInstallPath, AgentExecutableName), true);
			ConfigFile.Save(Path.Combine(accessibleInstallPath, AgentConfigName), BuildAgentConfig(config));
			Logger.Info("Файлы агента скопированы в " + accessibleInstallPath);

			string binaryPath = "\\\"" + remoteExecutablePath + "\\\" --service";
			string serviceParameters = " binPath= \"" + binaryPath + "\" start= auto DisplayName= \"" + ServiceDisplayName + "\"";
			string createOutput;
			int createCode = RunServiceControl(serverArgument + "create " + ServiceName + serviceParameters, out createOutput);
			if (createCode == 1073)
			{
				// Служба уже существует — обновляем её параметры.
				createCode = RunServiceControl(serverArgument + "config " + ServiceName + serviceParameters, out createOutput);
			}
			if (createCode != 0)
			{
				throw new InvalidOperationException("Не удалось зарегистрировать службу на " + host + " (код " + createCode + "): " + createOutput);
			}
			RunServiceControl(serverArgument + "failure " + ServiceName + " reset= 86400 actions= restart/60000/restart/60000/restart/300000", false);
			RunServiceControl(serverArgument + "description " + ServiceName + " \"" + ServiceDescription + "\"", false);
			// Как и при локальной установке, скрываем службу от обычных пользователей ПК (штатное разграничение доступа, не сокрытие процесса).
			RunServiceControl(serverArgument + "sdset " + ServiceName + " \"" + ServiceSecurityDescriptor + "\"", true);

			string startOutput;
			int startCode = RunServiceControl(serverArgument + "start " + ServiceName, out startOutput);
			if (startCode != 0 && startCode != 1056)
			{
				throw new InvalidOperationException("Служба зарегистрирована, но не запустилась на " + host + " (код " + startCode + "): " + startOutput);
			}
			string message = "Агент установлен и запущен на " + host + " (" + remoteExecutablePath + ")";
			Logger.Info(message);
			return message;
		}

		/// <summary>
		/// Останавливает и удаляет службу агента на ПК и удаляет его файлы (по возможности).
		/// </summary>
		public static string Remove(string host, PanelConfig config)
		{
			string installPath = string.IsNullOrWhiteSpace(config.AgentInstallPath) ? @"C:\Program Files\SkziAgent" : config.AgentInstallPath.TrimEnd('\\');
			string serverArgument = ScanCoordinator.IsLocalHost(host) ? string.Empty : "\\\\" + host + " ";
			Logger.Info("Удаление агента с " + host);

			RunServiceControl(serverArgument + "stop " + ServiceName, false);
			WaitForServiceStopped(serverArgument);
			string deleteOutput;
			int deleteCode = RunServiceControl(serverArgument + "delete " + ServiceName, out deleteOutput);
			if (deleteCode != 0 && deleteCode != 1060)
			{
				throw new InvalidOperationException("Не удалось удалить службу на " + host + " (код " + deleteCode + "): " + deleteOutput);
			}

			string accessibleInstallPath = ToAccessiblePath(host, installPath);
			try
			{
				File.Delete(Path.Combine(accessibleInstallPath, AgentExecutableName));
				File.Delete(Path.Combine(accessibleInstallPath, AgentConfigName));
			}
			catch (Exception exception)
			{
				Logger.Warning("Файлы агента на " + host + " не удалены (будут удалены после перезагрузки или вручную): " + exception.Message);
			}
			string message = "Агент удалён с " + host;
			Logger.Info(message);
			return message;
		}

		/// <summary>
		/// Формирует конфигурацию агента из настроек панели (порт, ключ, директории, расширения).
		/// </summary>
		public static AgentConfig BuildAgentConfig(PanelConfig config)
		{
			AgentConfig agentConfig = new AgentConfig();
			agentConfig.ListenPort = config.AgentPort;
			agentConfig.SharedKey = config.SharedKey;
			agentConfig.ScanDirectories.AddRange(config.ScanDirectories);
			agentConfig.CertificateFileExtensions = config.CertificateFileExtensions;
			agentConfig.ScanCertificateStores = config.ScanCertificateStores;
			agentConfig.MaxCertificateFileSizeKb = config.MaxCertificateFileSizeKb;
			agentConfig.ScanCryptoProContainers = config.ScanCryptoProContainers;
			agentConfig.AcceptDirectoriesFromPanel = true;
			agentConfig.LogRetentionDays = config.LogRetentionDays;
			agentConfig.LogMaxFileSizeMb = config.LogMaxFileSizeMb;
			return agentConfig;
		}

		/// <summary>
		/// Преобразует локальный путь целевого ПК в путь, доступный панели (\\ПК\C$\... или локальный).
		/// </summary>
		private static string ToAccessiblePath(string host, string localPath)
		{
			if (ScanCoordinator.IsLocalHost(host))
			{
				return localPath;
			}
			Match match = Regex.Match(localPath, @"^(?<drive>[A-Za-z]):\\(?<rest>.*)$");
			if (!match.Success)
			{
				throw new ArgumentException("Папка установки агента должна быть полным путём вида C:\\...: " + localPath);
			}
			return "\\\\" + host + "\\" + match.Groups["drive"].Value.ToUpperInvariant() + "$\\" + match.Groups["rest"].Value;
		}

		/// <summary>
		/// Ждёт остановки службы (до 20 секунд), чтобы можно было перезаписать exe.
		/// </summary>
		private static void WaitForServiceStopped(string serverArgument)
		{
			for (int attempt = 0; attempt < 20; attempt++)
			{
				string output;
				int code = RunServiceControl(serverArgument + "query " + ServiceName, out output);
				if (code != 0 || output.Contains("STOPPED") || output.Contains("1060"))
				{
					return;
				}
				Thread.Sleep(1000);
			}
		}

		/// <summary>
		/// Запускает sc.exe без анализа результата.
		/// </summary>
		private static void RunServiceControl(string arguments, bool logErrors)
		{
			string output;
			int code = RunServiceControl(arguments, out output);
			if (logErrors && code != 0)
			{
				Logger.Warning("sc " + arguments + " завершилась с кодом " + code + ": " + output);
			}
		}

		/// <summary>
		/// Запускает sc.exe и возвращает код завершения и вывод.
		/// </summary>
		private static int RunServiceControl(string arguments, out string output)
		{
			ProcessStartInfo startInfo = new ProcessStartInfo("sc.exe", arguments);
			startInfo.UseShellExecute = false;
			startInfo.CreateNoWindow = true;
			startInfo.RedirectStandardOutput = true;
			startInfo.RedirectStandardError = true;
			startInfo.StandardOutputEncoding = Encoding.GetEncoding(866);
			startInfo.StandardErrorEncoding = Encoding.GetEncoding(866);
			using (Process process = Process.Start(startInfo))
			{
				string standardOutput = process.StandardOutput.ReadToEnd();
				string standardError = process.StandardError.ReadToEnd();
				if (!process.WaitForExit(60000))
				{
					process.Kill();
					output = "таймаут sc.exe";
					return -1;
				}
				output = Regex.Replace((standardOutput + " " + standardError).Trim(), @"\s+", " ");
				return process.ExitCode;
			}
		}
	}
}
