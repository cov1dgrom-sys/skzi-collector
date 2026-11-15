using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Skzi.Common.Configuration;
using Skzi.Common.Logging;
using Skzi.Common.Network;
using Skzi.Common.Scanning;

namespace Skzi.Agent
{
	/// <summary>
	/// TCP-сервер агента: принимает подписанные запросы панели управления, выполняет сканирование
	/// локального ПК и возвращает подписанный результат. Одновременно выполняется только одно сканирование.
	/// </summary>
	public sealed class AgentServer
	{
		private const int RequestReadTimeoutMilliseconds = 30000;
		private const int ScanQueueTimeoutMilliseconds = 10 * 60 * 1000;
		private static readonly TimeSpan MaxRequestAge = TimeSpan.FromMinutes(10);

		private readonly AgentConfig config;
		private readonly byte[] signingKey;
		private readonly SemaphoreSlim scanSemaphore = new SemaphoreSlim(1, 1);
		private readonly CancellationTokenSource stopSource = new CancellationTokenSource();
		private TcpListener listener;
		private Task acceptLoopTask;

		/// <summary>
		/// Создаёт сервер с указанной конфигурацией агента.
		/// </summary>
		public AgentServer(AgentConfig config)
		{
			this.config = config;
			signingKey = AgentProtocol.DeriveKey(config.SharedKey);
		}

		/// <summary>
		/// Фактический порт, на котором слушает сервер (полезно при порте 0 в тестах).
		/// </summary>
		public int ListeningPort
		{
			get { return listener == null ? 0 : ((IPEndPoint)listener.LocalEndpoint).Port; }
		}

		/// <summary>
		/// Запускает прослушивание порта и цикл приёма подключений.
		/// </summary>
		public void Start()
		{
			listener = new TcpListener(IPAddress.Any, config.ListenPort);
			listener.Start();
			Logger.Info("Агент слушает TCP-порт " + ListeningPort + " (" + AgentProtocol.ProtocolName + ")");
			if (string.IsNullOrWhiteSpace(config.SharedKey) || config.SharedKey == AgentConfig.CreateDefault().SharedKey)
			{
				Logger.Warning("Используется ключ по умолчанию — смените SharedKey в agent.config.xml и в настройках панели");
			}
			acceptLoopTask = Task.Run(new Func<Task>(AcceptLoopAsync));
		}

		/// <summary>
		/// Останавливает сервер и дожидается завершения цикла приёма.
		/// </summary>
		public void Stop()
		{
			stopSource.Cancel();
			if (listener != null)
			{
				listener.Stop();
			}
			try
			{
				if (acceptLoopTask != null)
				{
					acceptLoopTask.Wait(5000);
				}
			}
			catch (AggregateException)
			{
				// Ошибки цикла приёма уже записаны в журнал.
			}
			Logger.Info("Агент остановлен");
		}

		/// <summary>
		/// Цикл приёма входящих подключений; каждое обрабатывается в отдельной задаче.
		/// </summary>
		private async Task AcceptLoopAsync()
		{
			while (!stopSource.IsCancellationRequested)
			{
				TcpClient client;
				try
				{
					client = await listener.AcceptTcpClientAsync().ConfigureAwait(false);
				}
				catch (ObjectDisposedException)
				{
					break;
				}
				catch (SocketException exception)
				{
					if (stopSource.IsCancellationRequested)
					{
						break;
					}
					Logger.Error("Ошибка приёма подключения", exception);
					continue;
				}
				catch (InvalidOperationException)
				{
					break;
				}

				Task clientTask = HandleClientAsync(client);
				TcpHelper.ObserveFault(clientTask);
			}
		}

		/// <summary>
		/// Обрабатывает одно подключение: приветствие, проверка подписи запроса, выполнение команды, подписанный ответ.
		/// </summary>
		private async Task HandleClientAsync(TcpClient client)
		{
			string remoteAddress = "неизвестно";
			try
			{
				using (client)
				{
					IPEndPoint remoteEndPoint = client.Client.RemoteEndPoint as IPEndPoint;
					remoteAddress = remoteEndPoint == null ? remoteAddress : remoteEndPoint.Address.ToString();
					NetworkStream stream = client.GetStream();

					byte[] nonce = AgentProtocol.CreateNonce();
					await AgentProtocol.WriteFrameAsync(stream, AgentProtocol.BuildHello(nonce, Environment.MachineName, CertificateCollector.GetScannerVersion()), stopSource.Token).ConfigureAwait(false);

					if (!IsClientAllowed(remoteEndPoint))
					{
						Logger.Warning("Подключение с адреса " + remoteAddress + " отклонено: адрес не входит в AllowedClients");
						await SendErrorAsync(stream, "адрес " + remoteAddress + " не разрешён в конфигурации агента").ConfigureAwait(false);
						return;
					}

					byte[] requestMessage;
					using (CancellationTokenSource readTimeout = CancellationTokenSource.CreateLinkedTokenSource(stopSource.Token))
					{
						readTimeout.CancelAfter(RequestReadTimeoutMilliseconds);
						using (readTimeout.Token.Register(delegate { client.Close(); }))
						{
							try
							{
								requestMessage = await AgentProtocol.ReadFrameAsync(stream, readTimeout.Token).ConfigureAwait(false);
							}
							catch (Exception)
							{
								// Обычная ситуация для поиска агентов: панель читает приветствие и закрывает соединение.
								return;
							}
						}
					}

					AgentRequest request = null;
					try
					{
						string requestXml = AgentProtocol.VerifySignedMessage(signingKey, nonce, AgentProtocol.DirectionRequest, requestMessage);
						request = XmlMessageSerializer.Deserialize<AgentRequest>(requestXml);
					}
					catch (Exception exception)
					{
						Logger.Warning("Запрос с адреса " + remoteAddress + " отклонён: " + exception.Message);
					}
					if (request == null)
					{
						await SendErrorAsync(stream, "неверный ключ (SharedKey) или повреждённый запрос").ConfigureAwait(false);
						return;
					}

					if (DateTime.UtcNow - request.CreatedAtUtc > MaxRequestAge || request.CreatedAtUtc - DateTime.UtcNow > MaxRequestAge)
					{
						Logger.Warning("Запрос " + request.RequestId + " с адреса " + remoteAddress + " отклонён: расхождение времени больше " + MaxRequestAge.TotalMinutes + " мин");
						await SendErrorAsync(stream, "расхождение времени панели и агента больше " + MaxRequestAge.TotalMinutes + " минут").ConfigureAwait(false);
						return;
					}

					Logger.Info("Получен запрос " + request.Command + " (" + request.RequestId + ") от " + (request.RequestedBy ?? "?") + ", адрес " + remoteAddress);
					AgentResponse response = await ExecuteRequestAsync(request).ConfigureAwait(false);
					string responseXml = XmlMessageSerializer.Serialize(response);
					byte[] responseMessage = AgentProtocol.BuildSignedMessage(signingKey, nonce, AgentProtocol.DirectionResponse, responseXml);
					await AgentProtocol.WriteFrameAsync(stream, responseMessage, stopSource.Token).ConfigureAwait(false);
					Logger.Info("Ответ на запрос " + request.RequestId + " отправлен на " + remoteAddress + " (" + responseMessage.Length + " байт)");
				}
			}
			catch (Exception exception)
			{
				if (!stopSource.IsCancellationRequested)
				{
					Logger.Error("Ошибка обработки подключения от " + remoteAddress, exception);
				}
			}
		}

		/// <summary>
		/// Выполняет команду запроса: Ping — сведения об агенте, Scan — полное сканирование ПК.
		/// </summary>
		private async Task<AgentResponse> ExecuteRequestAsync(AgentRequest request)
		{
			AgentResponse response = new AgentResponse();
			response.ComputerName = Environment.MachineName;
			response.AgentVersion = CertificateCollector.GetScannerVersion();

			if (string.Equals(request.Command, AgentRequest.CommandPing, StringComparison.OrdinalIgnoreCase))
			{
				response.Success = true;
				return response;
			}
			if (!string.Equals(request.Command, AgentRequest.CommandScan, StringComparison.OrdinalIgnoreCase))
			{
				response.Success = false;
				response.ErrorMessage = "Неизвестная команда: " + request.Command;
				return response;
			}

			bool entered = await scanSemaphore.WaitAsync(ScanQueueTimeoutMilliseconds, stopSource.Token).ConfigureAwait(false);
			if (!entered)
			{
				response.Success = false;
				response.ErrorMessage = "Агент занят другим сканированием";
				return response;
			}
			try
			{
				ScanOptions options = BuildScanOptions(request);
				CancellationToken token = stopSource.Token;
				response.Result = await Task.Run(() => CertificateCollector.Scan(new LocalScanTarget(), options, CertificateCollector.ModeAgent, token)).ConfigureAwait(false);
				response.Success = true;
			}
			catch (Exception exception)
			{
				Logger.Error("Ошибка сканирования по запросу " + request.RequestId, exception);
				response.Success = false;
				response.ErrorMessage = exception.GetType().Name + ": " + exception.Message;
			}
			finally
			{
				scanSemaphore.Release();
			}
			return response;
		}

		/// <summary>
		/// Формирует параметры сканирования: из конфигурации агента и (если разрешено) из запроса панели.
		/// Если оператор указал директории и попросил искать только в них, директории агента заменяются.
		/// </summary>
		private ScanOptions BuildScanOptions(AgentRequest request)
		{
			ScanOptions options = ScanOptions.FromAgentConfig(config);
			options.ScanCryptoProContainers = config.ScanCryptoProContainers && request.ScanCryptoProContainers;
			if (!config.AcceptDirectoriesFromPanel)
			{
				return options;
			}
			if (request.UseOnlyRequestedDirectories)
			{
				options.Directories.Clear();
				Logger.Info("Директории для поиска заданы панелью: " + request.ExtraDirectories.Count + " (директории из конфигурации агента не используются)");
			}
			options.AddDirectories(request.ExtraDirectories);
			return options;
		}

		/// <summary>
		/// Проверяет, разрешён ли адрес клиента (если список AllowedClients задан).
		/// </summary>
		private bool IsClientAllowed(IPEndPoint remoteEndPoint)
		{
			if (config.AllowedClients == null || config.AllowedClients.Count == 0 || remoteEndPoint == null)
			{
				return true;
			}
			IPAddress remoteAddress = remoteEndPoint.Address.IsIPv4MappedToIPv6 ? remoteEndPoint.Address.MapToIPv4() : remoteEndPoint.Address;
			foreach (string allowed in config.AllowedClients)
			{
				if (string.IsNullOrWhiteSpace(allowed))
				{
					continue;
				}
				IPAddress allowedAddress;
				if (IPAddress.TryParse(allowed.Trim(), out allowedAddress))
				{
					if (allowedAddress.Equals(remoteAddress))
					{
						return true;
					}
					continue;
				}
				try
				{
					foreach (IPAddress resolved in Dns.GetHostAddresses(allowed.Trim()))
					{
						if (resolved.Equals(remoteAddress))
						{
							return true;
						}
					}
				}
				catch (SocketException)
				{
					// Имя не разрешается — пропускаем.
				}
			}
			return false;
		}

		/// <summary>
		/// Отправляет клиенту неподписанное сообщение об ошибке («ERROR|текст»).
		/// </summary>
		private async Task SendErrorAsync(NetworkStream stream, string message)
		{
			try
			{
				byte[] payload = System.Text.Encoding.UTF8.GetBytes("ERROR|" + message);
				await AgentProtocol.WriteFrameAsync(stream, payload, stopSource.Token).ConfigureAwait(false);
			}
			catch (Exception)
			{
				// Клиент мог уже отключиться.
			}
		}
	}
}
