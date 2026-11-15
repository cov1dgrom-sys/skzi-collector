using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Xml;
using System.Xml.Serialization;
using Skzi.Common.Configuration;
using Skzi.Common.Scanning;

namespace Skzi.Common.Network
{
	/// <summary>
	/// Запрос панели управления к агенту.
	/// </summary>
	[XmlRoot("AgentRequest")]
	public class AgentRequest
	{
		public const string CommandScan = "Scan";
		public const string CommandPing = "Ping";

		/// <summary>Команда: Scan — выполнить сканирование, Ping — проверить доступность и ключ.</summary>
		public string Command { get; set; }

		/// <summary>Уникальный идентификатор запроса (для журналов).</summary>
		public string RequestId { get; set; }

		/// <summary>Кто запросил (пользователь и ПК панели управления).</summary>
		public string RequestedBy { get; set; }

		/// <summary>Время формирования запроса (UTC) — защита от повторного использования.</summary>
		public DateTime CreatedAtUtc { get; set; }

		/// <summary>Директории для сканирования, указанные оператором в панели.</summary>
		[XmlArrayItem("Directory")]
		public List<ScanDirectoryEntry> ExtraDirectories { get; set; }

		/// <summary>
		/// Искать только в директориях из запроса (директории из agent.config.xml не используются).
		/// Применяется, если агенту разрешено принимать директории от панели (AcceptDirectoriesFromPanel).
		/// </summary>
		public bool UseOnlyRequestedDirectories { get; set; }

		/// <summary>Проверять ли ключевые контейнеры КриптоПро (если это разрешено и в конфигурации агента).</summary>
		public bool ScanCryptoProContainers { get; set; }

		/// <summary>
		/// Создаёт запрос сканирования с новым идентификатором и текущим временем.
		/// </summary>
		public AgentRequest()
		{
			Command = CommandScan;
			RequestId = Guid.NewGuid().ToString("N");
			CreatedAtUtc = DateTime.UtcNow;
			ExtraDirectories = new List<ScanDirectoryEntry>();
			ScanCryptoProContainers = true;
		}
	}

	/// <summary>
	/// Ответ агента на запрос панели.
	/// </summary>
	[XmlRoot("AgentResponse")]
	public class AgentResponse
	{
		/// <summary>Успешно ли выполнена команда.</summary>
		public bool Success { get; set; }

		/// <summary>Текст ошибки (если Success = false).</summary>
		public string ErrorMessage { get; set; }

		/// <summary>Имя ПК, на котором работает агент.</summary>
		public string ComputerName { get; set; }

		/// <summary>Версия агента.</summary>
		public string AgentVersion { get; set; }

		/// <summary>Результат сканирования (для команды Scan).</summary>
		public ScanResult Result { get; set; }
	}

	/// <summary>
	/// Приветствие агента, отправляемое сразу после подключения: протокол, одноразовое число (nonce) и имя ПК.
	/// </summary>
	public sealed class AgentHello
	{
		public string Protocol { get; set; }
		public byte[] Nonce { get; set; }
		public string ComputerName { get; set; }
		public string AgentVersion { get; set; }
	}

	/// <summary>
	/// Сетевой протокол «панель ↔ агент» поверх TCP.
	/// Кадр: 4 байта длины (big-endian) + полезная нагрузка UTF-8.
	/// 1) агент → панель: «SKZI-AGENT/1.0|nonce(Base64)|имя ПК|версия»;
	/// 2) панель → агент: «HMAC(Base64)\n» + XML запроса, где HMAC-SHA256(ключ, nonce + 0x01 + запрос);
	/// 3) агент → панель: «HMAC(Base64)\n» + XML ответа, где HMAC-SHA256(ключ, nonce + 0x02 + ответ).
	/// Ключ не передаётся по сети; подпись защищает от подмены запроса и ответа.
	/// </summary>
	public static class AgentProtocol
	{
		public const string ProtocolName = "SKZI-AGENT/1.0";
		public const int DefaultPort = 50555;
		public const int MaxFrameBytes = 64 * 1024 * 1024;
		public const byte DirectionRequest = 1;
		public const byte DirectionResponse = 2;
		public const int NonceLength = 32;

		/// <summary>
		/// Записывает кадр в поток: длина (4 байта, big-endian) и данные.
		/// </summary>
		public static async Task WriteFrameAsync(Stream stream, byte[] payload, CancellationToken cancellationToken)
		{
			if (payload.Length > MaxFrameBytes)
			{
				throw new InvalidDataException("Размер сообщения превышает допустимый (" + MaxFrameBytes + " байт)");
			}
			byte[] header = new byte[4];
			header[0] = (byte)(payload.Length >> 24);
			header[1] = (byte)(payload.Length >> 16);
			header[2] = (byte)(payload.Length >> 8);
			header[3] = (byte)payload.Length;
			await stream.WriteAsync(header, 0, header.Length, cancellationToken).ConfigureAwait(false);
			await stream.WriteAsync(payload, 0, payload.Length, cancellationToken).ConfigureAwait(false);
			await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
		}

		/// <summary>
		/// Читает один кадр из потока. Бросает исключение при обрыве соединения или превышении размера.
		/// </summary>
		public static async Task<byte[]> ReadFrameAsync(Stream stream, CancellationToken cancellationToken)
		{
			byte[] header = await ReadExactAsync(stream, 4, cancellationToken).ConfigureAwait(false);
			int length = (header[0] << 24) | (header[1] << 16) | (header[2] << 8) | header[3];
			if (length < 0 || length > MaxFrameBytes)
			{
				throw new InvalidDataException("Недопустимая длина сообщения: " + length);
			}
			return await ReadExactAsync(stream, length, cancellationToken).ConfigureAwait(false);
		}

		/// <summary>
		/// Читает из потока ровно count байт.
		/// </summary>
		private static async Task<byte[]> ReadExactAsync(Stream stream, int count, CancellationToken cancellationToken)
		{
			byte[] buffer = new byte[count];
			int totalRead = 0;
			while (totalRead < count)
			{
				int bytesRead = await stream.ReadAsync(buffer, totalRead, count - totalRead, cancellationToken).ConfigureAwait(false);
				if (bytesRead == 0)
				{
					throw new EndOfStreamException("Соединение закрыто удалённой стороной");
				}
				totalRead = totalRead + bytesRead;
			}
			return buffer;
		}

		/// <summary>
		/// Формирует текст приветствия агента.
		/// </summary>
		public static byte[] BuildHello(byte[] nonce, string computerName, string agentVersion)
		{
			string hello = ProtocolName + "|" + Convert.ToBase64String(nonce) + "|" + Sanitize(computerName) + "|" + Sanitize(agentVersion);
			return Encoding.UTF8.GetBytes(hello);
		}

		/// <summary>
		/// Разбирает приветствие агента. Бросает InvalidDataException, если это не агент СКЗИ.
		/// </summary>
		public static AgentHello ParseHello(byte[] frame)
		{
			string text = Encoding.UTF8.GetString(frame);
			string[] parts = text.Split('|');
			if (parts.Length < 2 || parts[0] != ProtocolName)
			{
				throw new InvalidDataException("Узел ответил не по протоколу агента СКЗИ");
			}
			AgentHello hello = new AgentHello();
			hello.Protocol = parts[0];
			hello.Nonce = Convert.FromBase64String(parts[1]);
			hello.ComputerName = parts.Length > 2 ? parts[2] : string.Empty;
			hello.AgentVersion = parts.Length > 3 ? parts[3] : string.Empty;
			if (hello.Nonce.Length != NonceLength)
			{
				throw new InvalidDataException("Некорректное одноразовое число в приветствии агента");
			}
			return hello;
		}

		/// <summary>
		/// Генерирует криптографически стойкое одноразовое число.
		/// </summary>
		public static byte[] CreateNonce()
		{
			byte[] nonce = new byte[NonceLength];
			using (RandomNumberGenerator generator = RandomNumberGenerator.Create())
			{
				generator.GetBytes(nonce);
			}
			return nonce;
		}

		/// <summary>
		/// Получает 256-битный ключ HMAC из общего секрета (SHA-256 от UTF-8 строки).
		/// </summary>
		public static byte[] DeriveKey(string sharedKey)
		{
			using (SHA256 sha256 = SHA256.Create())
			{
				return sha256.ComputeHash(Encoding.UTF8.GetBytes("SKZI-AGENT-KEY|" + (sharedKey ?? string.Empty)));
			}
		}

		/// <summary>
		/// Вычисляет подпись HMAC-SHA256(ключ, nonce + направление + тело).
		/// </summary>
		public static byte[] ComputeSignature(byte[] key, byte[] nonce, byte direction, byte[] body)
		{
			using (HMACSHA256 hmac = new HMACSHA256(key))
			{
				byte[] data = new byte[nonce.Length + 1 + body.Length];
				Buffer.BlockCopy(nonce, 0, data, 0, nonce.Length);
				data[nonce.Length] = direction;
				Buffer.BlockCopy(body, 0, data, nonce.Length + 1, body.Length);
				return hmac.ComputeHash(data);
			}
		}

		/// <summary>
		/// Сравнивает подписи за постоянное время (защита от атак по времени).
		/// </summary>
		public static bool SignaturesEqual(byte[] expected, byte[] actual)
		{
			if (expected == null || actual == null || expected.Length != actual.Length)
			{
				return false;
			}
			int difference = 0;
			for (int index = 0; index < expected.Length; index++)
			{
				difference = difference | (expected[index] ^ actual[index]);
			}
			return difference == 0;
		}

		/// <summary>
		/// Собирает подписанное сообщение: «подпись(Base64)\n» + тело.
		/// </summary>
		public static byte[] BuildSignedMessage(byte[] key, byte[] nonce, byte direction, string bodyText)
		{
			byte[] body = Encoding.UTF8.GetBytes(bodyText);
			byte[] signature = ComputeSignature(key, nonce, direction, body);
			byte[] prefix = Encoding.ASCII.GetBytes(Convert.ToBase64String(signature) + "\n");
			byte[] message = new byte[prefix.Length + body.Length];
			Buffer.BlockCopy(prefix, 0, message, 0, prefix.Length);
			Buffer.BlockCopy(body, 0, message, prefix.Length, body.Length);
			return message;
		}

		/// <summary>
		/// Проверяет подпись сообщения и возвращает его тело. Бросает UnauthorizedAccessException при неверной подписи.
		/// </summary>
		public static string VerifySignedMessage(byte[] key, byte[] nonce, byte direction, byte[] message)
		{
			int separatorIndex = Array.IndexOf(message, (byte)'\n');
			if (separatorIndex <= 0 || separatorIndex > 128)
			{
				throw new InvalidDataException("Сообщение не содержит подписи");
			}
			byte[] receivedSignature;
			try
			{
				receivedSignature = Convert.FromBase64String(Encoding.ASCII.GetString(message, 0, separatorIndex));
			}
			catch (FormatException)
			{
				throw new InvalidDataException("Подпись сообщения повреждена");
			}
			byte[] body = new byte[message.Length - separatorIndex - 1];
			Buffer.BlockCopy(message, separatorIndex + 1, body, 0, body.Length);
			byte[] expectedSignature = ComputeSignature(key, nonce, direction, body);
			if (!SignaturesEqual(expectedSignature, receivedSignature))
			{
				throw new UnauthorizedAccessException("Неверная подпись сообщения: ключи панели и агента не совпадают");
			}
			return Encoding.UTF8.GetString(body);
		}

		/// <summary>
		/// Убирает из строки символы-разделители протокола.
		/// </summary>
		private static string Sanitize(string value)
		{
			return (value ?? string.Empty).Replace("|", "/").Replace("\n", " ").Replace("\r", " ");
		}
	}

	/// <summary>
	/// Сериализация объектов протокола в XML и обратно с безопасными настройками парсера.
	/// </summary>
	public static class XmlMessageSerializer
	{
		/// <summary>
		/// Сериализует объект в строку XML.
		/// </summary>
		public static string Serialize<T>(T value)
		{
			XmlSerializer serializer = new XmlSerializer(typeof(T));
			XmlWriterSettings settings = new XmlWriterSettings();
			settings.Encoding = new UTF8Encoding(false);
			settings.Indent = false;
			settings.CheckCharacters = false;
			using (StringWriter stringWriter = new StringWriter())
			using (XmlWriter xmlWriter = XmlWriter.Create(stringWriter, settings))
			{
				XmlSerializerNamespaces namespaces = new XmlSerializerNamespaces();
				namespaces.Add(string.Empty, string.Empty);
				serializer.Serialize(xmlWriter, value, namespaces);
				xmlWriter.Flush();
				return stringWriter.ToString();
			}
		}

		/// <summary>
		/// Восстанавливает объект из XML (DTD и внешние сущности запрещены).
		/// </summary>
		public static T Deserialize<T>(string xml) where T : class
		{
			XmlSerializer serializer = new XmlSerializer(typeof(T));
			XmlReaderSettings settings = new XmlReaderSettings();
			settings.DtdProcessing = DtdProcessing.Prohibit;
			settings.XmlResolver = null;
			settings.CheckCharacters = false;
			using (StringReader stringReader = new StringReader(xml))
			using (XmlReader xmlReader = XmlReader.Create(stringReader, settings))
			{
				T value = serializer.Deserialize(xmlReader) as T;
				if (value == null)
				{
					throw new InvalidDataException("Пустое XML-сообщение");
				}
				return value;
			}
		}
	}

	/// <summary>
	/// Вспомогательные методы для работы с TCP-соединениями.
	/// </summary>
	public static class TcpHelper
	{
		/// <summary>
		/// Подключается к узлу с ограничением времени ожидания.
		/// </summary>
		public static async Task ConnectWithTimeoutAsync(TcpClient client, string host, int port, int timeoutMilliseconds, CancellationToken cancellationToken)
		{
			Task connectTask = client.ConnectAsync(host, port);
			Task timeoutTask = Task.Delay(timeoutMilliseconds, cancellationToken);
			Task completedTask = await Task.WhenAny(connectTask, timeoutTask).ConfigureAwait(false);
			if (completedTask != connectTask)
			{
				ObserveFault(connectTask);
				cancellationToken.ThrowIfCancellationRequested();
				throw new TimeoutException("Узел " + host + ":" + port + " не ответил за " + timeoutMilliseconds + " мс");
			}
			await connectTask.ConfigureAwait(false);
		}

		/// <summary>
		/// Помечает исключение задачи как обработанное, чтобы оно не всплыло как UnobservedTaskException.
		/// </summary>
		public static void ObserveFault(Task task)
		{
			task.ContinueWith(delegate (Task completed)
			{
				AggregateException ignored = completed.Exception;
			}, TaskContinuationOptions.OnlyOnFaulted);
		}
	}
}
