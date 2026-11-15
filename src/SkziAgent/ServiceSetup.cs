using System;
using System.Diagnostics;
using System.Security.Principal;
using System.ServiceProcess;
using System.Text;
using Skzi.Common.Logging;

namespace Skzi.Agent
{
	/// <summary>
	/// Установка и удаление агента как службы Windows, настройка правила брандмауэра.
	/// </summary>
	public static class ServiceSetup
	{
		public const string ServiceName = "SkziAgent";
		public const string ServiceDisplayName = "СКЗИ: агент сбора данных о сертификатах";
		public const string ServiceDescription = "Собирает сведения о личных сертификатах и КриптоПро CSP по запросу панели управления (команда Red Flag).";
		public const string FirewallRuleName = "SKZI Agent";

		// Дескриптор безопасности службы: полный доступ только у системы (SY) и администраторов (BA);
		// запись аудита на все попытки доступа (SACL). ACE для обычных (интерактивных) пользователей нет,
		// поэтому служба не видна и не управляема из services.msc и sc под учётной записью без прав администратора.
		// Это штатный механизм Windows (разграничение доступа к службе), а не сокрытие процесса.
		// Та же строка используется при установке из панели по сети (AgentDeployer.ServiceSecurityDescriptor); совпадение проверяет автотест.
		public const string RestrictedServiceSecurity =
			"D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)";

		/// <summary>
		/// Проверяет, запущен ли процесс с правами администратора.
		/// </summary>
		public static bool IsAdministrator()
		{
			WindowsPrincipal principal = new WindowsPrincipal(WindowsIdentity.GetCurrent());
			return principal.IsInRole(WindowsBuiltInRole.Administrator);
		}

		/// <summary>
		/// Регистрирует службу (автозапуск, перезапуск при сбое), открывает порт в брандмауэре и запускает службу.
		/// Возвращает 0 при успехе.
		/// </summary>
		public static int Install(string executablePath, int port)
		{
			string output;
			Uninstall(false);

			string binaryPath = "\\\"" + executablePath + "\\\" --service";
			int exitCode = RunTool("sc.exe", "create " + ServiceName + " binPath= \"" + binaryPath + "\" start= auto DisplayName= \"" + ServiceDisplayName + "\"", out output);
			if (exitCode != 0)
			{
				Logger.Error("Не удалось зарегистрировать службу (код " + exitCode + "): " + output);
				return exitCode;
			}
			RunTool("sc.exe", "description " + ServiceName + " \"" + ServiceDescription + "\"", out output);
			RunTool("sc.exe", "failure " + ServiceName + " reset= 86400 actions= restart/60000/restart/60000/restart/300000", out output);
			Logger.Info("Служба " + ServiceName + " зарегистрирована: " + executablePath);

			HideServiceFromStandardUsers();
			EnsureFirewallRule(executablePath, port);

			try
			{
				using (ServiceController controller = new ServiceController(ServiceName))
				{
					controller.Start();
					controller.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(30));
				}
				Logger.Info("Служба " + ServiceName + " запущена");
			}
			catch (Exception exception)
			{
				Logger.Error("Служба зарегистрирована, но не запустилась", exception);
				return 2;
			}
			return 0;
		}

		/// <summary>
		/// Останавливает и удаляет службу, удаляет правило брандмауэра.
		/// </summary>
		public static int Uninstall(bool logIfMissing)
		{
			string output;
			try
			{
				using (ServiceController controller = new ServiceController(ServiceName))
				{
					if (controller.Status != ServiceControllerStatus.Stopped)
					{
						controller.Stop();
						controller.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(30));
					}
				}
			}
			catch (InvalidOperationException)
			{
				if (logIfMissing)
				{
					Logger.Info("Служба " + ServiceName + " не установлена");
				}
			}
			catch (System.ServiceProcess.TimeoutException exception)
			{
				Logger.Error("Служба не остановилась за 30 секунд", exception);
			}

			int exitCode = RunTool("sc.exe", "delete " + ServiceName, out output);
			if (exitCode == 0)
			{
				Logger.Info("Служба " + ServiceName + " удалена");
			}
			RunTool("netsh.exe", "advfirewall firewall delete rule name=\"" + FirewallRuleName + "\"", out output);
			return 0;
		}

		/// <summary>
		/// Ограничивает доступ к службе дескриптором безопасности: обычный пользователь её не видит и не может
		/// остановить, администратор и система сохраняют полный контроль. Все попытки доступа пишутся в аудит.
		/// Выполняется с наилучшими намерениями: при ошибке установка не прерывается.
		/// </summary>
		public static void HideServiceFromStandardUsers()
		{
			string output;
			int exitCode = RunTool("sc.exe", "sdset " + ServiceName + " \"" + RestrictedServiceSecurity + "\"", out output);
			if (exitCode == 0)
			{
				Logger.Info("Доступ к службе " + ServiceName + " ограничен: видна и управляема только администраторам и системе");
			}
			else
			{
				Logger.Warning("Не удалось ограничить доступ к службе (код " + exitCode + "): " + output);
			}
		}

		/// <summary>
		/// Создаёт (пересоздаёт) правило брандмауэра Windows, разрешающее входящие подключения к агенту.
		/// </summary>
		public static void EnsureFirewallRule(string executablePath, int port)
		{
			string output;
			RunTool("netsh.exe", "advfirewall firewall delete rule name=\"" + FirewallRuleName + "\"", out output);
			int exitCode = RunTool("netsh.exe", "advfirewall firewall add rule name=\"" + FirewallRuleName + "\" dir=in action=allow protocol=TCP localport=" + port
				+ " program=\"" + executablePath + "\" enable=yes profile=any", out output);
			if (exitCode == 0)
			{
				Logger.Info("Правило брандмауэра «" + FirewallRuleName + "» для порта " + port + " создано");
			}
			else
			{
				Logger.Warning("Не удалось создать правило брандмауэра (код " + exitCode + "): " + output);
			}
		}

		/// <summary>
		/// Запускает системную утилиту, ждёт завершения и возвращает код выхода и вывод.
		/// </summary>
		private static int RunTool(string fileName, string arguments, out string output)
		{
			ProcessStartInfo startInfo = new ProcessStartInfo(fileName, arguments);
			startInfo.UseShellExecute = false;
			startInfo.CreateNoWindow = true;
			startInfo.RedirectStandardOutput = true;
			startInfo.RedirectStandardError = true;
			startInfo.StandardOutputEncoding = Encoding.GetEncoding(866);
			startInfo.StandardErrorEncoding = Encoding.GetEncoding(866);
			try
			{
				using (Process process = Process.Start(startInfo))
				{
					string standardOutput = process.StandardOutput.ReadToEnd();
					string standardError = process.StandardError.ReadToEnd();
					process.WaitForExit(60000);
					output = (standardOutput + " " + standardError).Trim();
					return process.ExitCode;
				}
			}
			catch (Exception exception)
			{
				Logger.Error("Не удалось запустить " + fileName + " " + arguments, exception);
				output = exception.Message;
				return -1;
			}
		}
	}
}
