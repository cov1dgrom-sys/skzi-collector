using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Skzi.Common.Configuration;
using Skzi.Common.Database;
using Skzi.Common.Logging;
using Skzi.Common.Network;
using Skzi.Common.Scanning;

namespace Skzi.ControlPanel
{
	/// <summary>
	/// Способ сканирования удалённого ПК.
	/// </summary>
	public enum ScanMethod
	{
		/// <summary>Через установленный на ПК агент (TCP).</summary>
		Agent,

		/// <summary>Без агента: административные ресурсы \\ПК\C$ и удалённый реестр.</summary>
		Agentless,

		/// <summary>Локальный ПК, на котором запущена панель.</summary>
		Local
	}

	/// <summary>
	/// Итог сканирования одного ПК: результат и сведения о записи в БД.
	/// </summary>
	public sealed class HostScanOutcome
	{
		public ScanResult Result { get; set; }
		public SaveStatistics DatabaseStatistics { get; set; }
		public string DatabaseError { get; set; }
	}

	/// <summary>
	/// Выполняет сканирование ПК выбранным способом и записывает результаты в MSSQL.
	/// </summary>
	public sealed class ScanCoordinator
	{
		private readonly PanelConfig config;
		private readonly object databaseInitializationLock = new object();
		private string initializedConnectionKey;

		/// <summary>
		/// Создаёт координатор с текущей конфигурацией панели.
		/// </summary>
		public ScanCoordinator(PanelConfig config)
		{
			this.config = config;
		}

		/// <summary>
		/// Сканирует ПК и (если включено в настройках) сохраняет результат в БД.
		/// Ошибки сканирования пробрасываются, ошибки записи в БД возвращаются в DatabaseError.
		/// </summary>
		public async Task<HostScanOutcome> ScanHostAsync(string host, ScanMethod method, CancellationToken cancellationToken)
		{
			HostScanOutcome outcome = new HostScanOutcome();
			if (method == ScanMethod.Agent)
			{
				outcome.Result = await ScanThroughAgentAsync(host, cancellationToken).ConfigureAwait(false);
			}
			else
			{
				IScanTarget target = method == ScanMethod.Local || IsLocalHost(host)
					? (IScanTarget)new LocalScanTarget()
					: new RemoteAdminShareTarget(host);
				ScanOptions options = ScanOptions.FromPanelConfig(config);
				string modeName = target.IsLocal ? CertificateCollector.ModeLocal : CertificateCollector.ModeAgentless;
				outcome.Result = await Task.Run(() => CertificateCollector.Scan(target, options, modeName, cancellationToken), cancellationToken).ConfigureAwait(false);
			}

			if (config.SaveToDatabaseAfterScan)
			{
				try
				{
					outcome.DatabaseStatistics = await Task.Run(() => SaveToDatabase(outcome.Result)).ConfigureAwait(false);
				}
				catch (Exception exception)
				{
					outcome.DatabaseError = exception.Message;
					Logger.Error("Не удалось записать результат сканирования " + host + " в БД", exception);
				}
			}
			return outcome;
		}

		/// <summary>
		/// Отправляет агенту подписанный запрос на сканирование и возвращает его результат.
		/// </summary>
		private async Task<ScanResult> ScanThroughAgentAsync(string host, CancellationToken cancellationToken)
		{
			AgentRequest request = new AgentRequest();
			request.Command = AgentRequest.CommandScan;
			request.RequestedBy = CertificateCollector.GetCurrentAccountName() + "@" + Environment.MachineName;
			if (config.SendDirectoriesToAgents)
			{
				request.ExtraDirectories.AddRange(config.ScanDirectories);
				request.UseOnlyRequestedDirectories = config.AgentsUseOnlyPanelDirectories;
			}
			request.ScanCryptoProContainers = config.ScanCryptoProContainers;
			Logger.Info("Запрос сканирования агенту " + host + ":" + config.AgentPort + " (" + request.RequestId + ")");
			AgentResponse response = await AgentClient.SendRequestAsync(host, config.AgentPort, config.SharedKey, request,
				Math.Max(10, config.AgentTimeoutSeconds) * 1000, cancellationToken).ConfigureAwait(false);
			if (!response.Success || response.Result == null)
			{
				throw new InvalidOperationException("Агент " + host + " сообщил об ошибке: " + (response.ErrorMessage ?? "нет результата"));
			}
			return response.Result;
		}

		/// <summary>
		/// Записывает результат в БД; при первом обращении создаёт БД и таблицу (если их нет).
		/// </summary>
		public SaveStatistics SaveToDatabase(ScanResult result)
		{
			CertificateRepository repository = CreateRepository();
			EnsureDatabaseReady(repository);
			return repository.SaveScanResult(result);
		}

		/// <summary>
		/// Создаёт репозиторий по текущим настройкам подключения.
		/// </summary>
		public CertificateRepository CreateRepository()
		{
			return new CertificateRepository(config.Database.BuildConnectionString(), config.Database.TableName);
		}

		/// <summary>
		/// Один раз (на набор параметров подключения) проверяет/создаёт БД и таблицу.
		/// </summary>
		public void EnsureDatabaseReady(CertificateRepository repository)
		{
			string connectionKey = config.Database.BuildConnectionString() + "|" + repository.QuotedTableName;
			lock (databaseInitializationLock)
			{
				if (connectionKey == initializedConnectionKey)
				{
					return;
				}
				if (config.Database.CreateDatabaseIfMissing)
				{
					repository.EnsureDatabaseExists();
				}
				repository.EnsureTableExists();
				initializedConnectionKey = connectionKey;
			}
		}

		/// <summary>
		/// Сбрасывает признак инициализации БД (после изменения настроек подключения).
		/// </summary>
		public void ResetDatabaseInitialization()
		{
			lock (databaseInitializationLock)
			{
				initializedConnectionKey = null;
			}
		}

		/// <summary>
		/// Определяет, указывает ли имя/адрес на этот же компьютер.
		/// </summary>
		public static bool IsLocalHost(string host)
		{
			if (string.IsNullOrWhiteSpace(host))
			{
				return false;
			}
			string trimmed = host.Trim();
			if (trimmed == "." || string.Equals(trimmed, "localhost", StringComparison.OrdinalIgnoreCase)
				|| string.Equals(trimmed, Environment.MachineName, StringComparison.OrdinalIgnoreCase))
			{
				return true;
			}
			IPAddress address;
			if (!IPAddress.TryParse(trimmed, out address))
			{
				return false;
			}
			if (IPAddress.IsLoopback(address))
			{
				return true;
			}
			try
			{
				foreach (NetworkInterface networkInterface in NetworkInterface.GetAllNetworkInterfaces())
				{
					foreach (UnicastIPAddressInformation unicast in networkInterface.GetIPProperties().UnicastAddresses)
					{
						if (unicast.Address.Equals(address))
						{
							return true;
						}
					}
				}
			}
			catch (NetworkInformationException)
			{
				// Не удалось получить адреса интерфейсов — считаем узел удалённым.
			}
			return false;
		}

		/// <summary>
		/// Преобразует исключение в понятное пользователю сообщение.
		/// </summary>
		public static string DescribeError(Exception exception, int agentPort)
		{
			Exception current = exception;
			AggregateException aggregate = exception as AggregateException;
			if (aggregate != null && aggregate.InnerExceptions.Count == 1)
			{
				current = aggregate.InnerExceptions[0];
			}
			SocketException socketException = current as SocketException ?? current.InnerException as SocketException;
			if (socketException != null)
			{
				switch (socketException.SocketErrorCode)
				{
					case SocketError.ConnectionRefused:
						return "Агент не отвечает на порту " + agentPort + " (не установлен, остановлен или порт закрыт брандмауэром)";
					case SocketError.HostNotFound:
					case SocketError.NoData:
						return "ПК не найден в сети (имя не разрешается)";
					case SocketError.TimedOut:
					case SocketError.HostUnreachable:
					case SocketError.NetworkUnreachable:
						return "ПК недоступен по сети";
				}
				return "Сетевая ошибка: " + socketException.Message;
			}
			if (current is TimeoutException)
			{
				return current.Message;
			}
			if (current is UnauthorizedAccessException)
			{
				return current.Message.Contains("ключ") || current.Message.Contains("Агент")
					? current.Message
					: "Нет доступа: " + current.Message;
			}
			if (current is OperationCanceledException)
			{
				return "Отменено пользователем";
			}
			if (current is IOException && current.InnerException is SocketException)
			{
				return DescribeError(current.InnerException, agentPort);
			}
			return current.Message;
		}
	}
}
