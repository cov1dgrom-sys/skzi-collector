using System;
using System.IO;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Skzi.Common.Network
{
	/// <summary>
	/// Клиент протокола агента (используется панелью управления): проверка доступности и запуск сканирования.
	/// </summary>
	public static class AgentClient
	{
		/// <summary>
		/// Подключается к агенту и читает только приветствие (без аутентификации).
		/// Используется для поиска агентов в подсети. Возвращает null, если узел — не агент или недоступен.
		/// </summary>
		public static async Task<AgentHello> ProbeAsync(string host, int port, int timeoutMilliseconds, CancellationToken cancellationToken)
		{
			using (TcpClient client = new TcpClient())
			{
				try
				{
					await TcpHelper.ConnectWithTimeoutAsync(client, host, port, timeoutMilliseconds, cancellationToken).ConfigureAwait(false);
					using (CancellationTokenSource timeoutSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken))
					{
						timeoutSource.CancelAfter(timeoutMilliseconds * 2);
						using (timeoutSource.Token.Register(delegate { client.Close(); }))
						{
							NetworkStream stream = client.GetStream();
							byte[] helloFrame = await AgentProtocol.ReadFrameAsync(stream, timeoutSource.Token).ConfigureAwait(false);
							return AgentProtocol.ParseHello(helloFrame);
						}
					}
				}
				catch (Exception exception)
				{
					if (exception is OperationCanceledException && cancellationToken.IsCancellationRequested)
					{
						throw;
					}
					return null;
				}
			}
		}

		/// <summary>
		/// Выполняет подписанный запрос к агенту и возвращает проверенный ответ.
		/// Бросает исключение при недоступности агента, таймауте или неверном ключе.
		/// </summary>
		public static async Task<AgentResponse> SendRequestAsync(string host, int port, string sharedKey, AgentRequest request,
			int timeoutMilliseconds, CancellationToken cancellationToken)
		{
			using (TcpClient client = new TcpClient())
			{
				client.NoDelay = true;
				await TcpHelper.ConnectWithTimeoutAsync(client, host, port, Math.Min(timeoutMilliseconds, 10000), cancellationToken).ConfigureAwait(false);

				using (CancellationTokenSource timeoutSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken))
				{
					timeoutSource.CancelAfter(timeoutMilliseconds);
					using (timeoutSource.Token.Register(delegate { client.Close(); }))
					{
						try
						{
							NetworkStream stream = client.GetStream();
							AgentHello hello = AgentProtocol.ParseHello(await AgentProtocol.ReadFrameAsync(stream, timeoutSource.Token).ConfigureAwait(false));
							byte[] key = AgentProtocol.DeriveKey(sharedKey);

							string requestXml = XmlMessageSerializer.Serialize(request);
							byte[] requestMessage = AgentProtocol.BuildSignedMessage(key, hello.Nonce, AgentProtocol.DirectionRequest, requestXml);
							await AgentProtocol.WriteFrameAsync(stream, requestMessage, timeoutSource.Token).ConfigureAwait(false);

							byte[] responseMessage = await AgentProtocol.ReadFrameAsync(stream, timeoutSource.Token).ConfigureAwait(false);
							string responseXml = UnwrapResponse(key, hello.Nonce, responseMessage);
							return XmlMessageSerializer.Deserialize<AgentResponse>(responseXml);
						}
						catch (Exception exception)
						{
							if (timeoutSource.IsCancellationRequested && !cancellationToken.IsCancellationRequested)
							{
								throw new TimeoutException("Агент " + host + " не ответил за " + (timeoutMilliseconds / 1000) + " с", exception);
							}
							if (cancellationToken.IsCancellationRequested)
							{
								throw new OperationCanceledException("Сканирование отменено пользователем", exception, cancellationToken);
							}
							throw;
						}
					}
				}
			}
		}

		/// <summary>
		/// Проверяет ответ агента: сообщение об ошибке аутентификации или подписанный XML.
		/// </summary>
		private static string UnwrapResponse(byte[] key, byte[] nonce, byte[] responseMessage)
		{
			string prefix = Encoding.UTF8.GetString(responseMessage, 0, Math.Min(responseMessage.Length, 16));
			if (prefix.StartsWith("ERROR|", StringComparison.Ordinal))
			{
				string errorText = Encoding.UTF8.GetString(responseMessage).Substring(6);
				throw new UnauthorizedAccessException("Агент отклонил запрос: " + errorText);
			}
			return AgentProtocol.VerifySignedMessage(key, nonce, AgentProtocol.DirectionResponse, responseMessage);
		}
	}
}
