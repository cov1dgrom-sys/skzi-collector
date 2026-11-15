using System;
using System.Reflection;
using System.ServiceProcess;
using Skzi.Common.Configuration;
using Skzi.Common.Logging;

namespace Skzi.Agent
{
	/// <summary>
	/// Агент в режиме службы Windows (работает от имени LocalSystem и видит личные хранилища
	/// всех пользователей, вошедших в систему).
	/// </summary>
	public sealed class AgentWindowsService : ServiceBase
	{
		private readonly string configPath;
		private AgentServer server;

		/// <summary>
		/// Создаёт службу с путём к файлу конфигурации агента.
		/// </summary>
		public AgentWindowsService(string configPath)
		{
			this.configPath = configPath;
			ServiceName = ServiceSetup.ServiceName;
			CanStop = true;
			CanShutdown = true;
			AutoLog = true;
		}

		/// <summary>
		/// Запуск службы: чтение конфигурации, проверка правила брандмауэра, старт TCP-сервера.
		/// </summary>
		protected override void OnStart(string[] args)
		{
			try
			{
				AgentConfig config = Program.LoadConfig(configPath);
				ServiceSetup.EnsureFirewallRule(Assembly.GetExecutingAssembly().Location, config.ListenPort);
				server = new AgentServer(config);
				server.Start();
				Logger.Info("Служба агента запущена");
			}
			catch (Exception exception)
			{
				Logger.Error("Ошибка запуска службы агента", exception);
				throw;
			}
		}

		/// <summary>
		/// Остановка службы.
		/// </summary>
		protected override void OnStop()
		{
			StopServer();
		}

		/// <summary>
		/// Остановка при выключении компьютера.
		/// </summary>
		protected override void OnShutdown()
		{
			StopServer();
		}

		/// <summary>
		/// Останавливает TCP-сервер, если он запущен.
		/// </summary>
		private void StopServer()
		{
			try
			{
				if (server != null)
				{
					server.Stop();
					server = null;
				}
				Logger.Info("Служба агента остановлена");
			}
			catch (Exception exception)
			{
				Logger.Error("Ошибка остановки службы агента", exception);
			}
		}
	}
}
