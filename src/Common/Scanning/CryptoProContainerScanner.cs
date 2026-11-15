using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.Win32;

namespace Skzi.Common.Scanning
{
	/// <summary>
	/// Сертификат, прочитанный из ключевого контейнера КриптоПро CSP.
	/// </summary>
	public sealed class ContainerCertificate
	{
		public X509Certificate2 Certificate { get; set; }
		public string ContainerName { get; set; }
	}

	/// <summary>
	/// Сбор сертификатов из ключевых контейнеров КриптоПро CSP (реестр, съёмные диски, токены и смарт-карты),
	/// в том числе тех, что не установлены в хранилище «Личное».
	/// Работает только на локальном ПК (агент или «Этот ПК») и только через штатный интерфейс CryptoAPI:
	/// перечисляет контейнеры провайдера и запрашивает у CSP открытый сертификат ключа (KP_CERTIFICATE).
	/// Закрытые ключи и файлы ключей не читаются, PIN-код не запрашивается (CRYPT_SILENT).
	/// </summary>
	public static class CryptoProContainerScanner
	{
		private const string CryptoProvidersPath = @"SOFTWARE\Microsoft\Cryptography\Defaults\Provider";

		private const int PpEnumContainers = 2;
		private const uint CryptFirst = 1;
		private const uint CryptNext = 2;
		private const uint CryptFullyQualifiedContainerName = 0x10;
		private const uint CryptVerifyContext = 0xF0000000;
		private const uint CryptSilent = 0x40;
		private const uint CryptMachineKeySet = 0x20;
		private const int KeyParameterCertificate = 26;
		private const int KeySpecExchange = 1;
		private const int KeySpecSignature = 2;
		private const int ErrorNoMoreItems = 259;
		private const int ErrorMoreData = 234;
		private const int MaxContainersPerProvider = 5000;

		/// <summary>
		/// Перечисляет контейнеры всех установленных провайдеров КриптоПро (пользовательские и компьютера)
		/// и возвращает сертификаты, записанные в контейнеры. Проблемы пишутся в warnings, исключения не бросаются.
		/// </summary>
		public static List<ContainerCertificate> CollectCertificates(List<string> warnings)
		{
			List<ContainerCertificate> certificates = new List<ContainerCertificate>();
			HashSet<string> processedContainers = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
			foreach (KeyValuePair<string, int> provider in FindCryptoProProviders())
			{
				foreach (bool machineKeySet in new[] { false, true })
				{
					List<string> containerNames = EnumerateContainers(provider.Key, provider.Value, machineKeySet, warnings);
					foreach (string containerName in containerNames)
					{
						string uniqueKey = (machineKeySet ? "M|" : "U|") + containerName;
						if (!processedContainers.Add(uniqueKey))
						{
							continue;
						}
						ReadContainerCertificates(provider.Key, provider.Value, containerName, machineKeySet, certificates, warnings);
					}
				}
			}
			return certificates;
		}

		/// <summary>
		/// Находит зарегистрированные в Windows криптопровайдеры КриптоПро и их типы (75, 80, 81).
		/// </summary>
		public static List<KeyValuePair<string, int>> FindCryptoProProviders()
		{
			List<KeyValuePair<string, int>> providers = new List<KeyValuePair<string, int>>();
			try
			{
				using (RegistryKey providersKey = Registry.LocalMachine.OpenSubKey(CryptoProvidersPath, false))
				{
					if (providersKey == null)
					{
						return providers;
					}
					foreach (string providerName in providersKey.GetSubKeyNames())
					{
						if (providerName.IndexOf("Crypto-Pro", StringComparison.OrdinalIgnoreCase) < 0
							&& providerName.IndexOf("CryptoPro", StringComparison.OrdinalIgnoreCase) < 0)
						{
							continue;
						}
						using (RegistryKey providerKey = providersKey.OpenSubKey(providerName, false))
						{
							object typeValue = providerKey == null ? null : providerKey.GetValue("Type");
							if (typeValue is int)
							{
								providers.Add(new KeyValuePair<string, int>(providerName, (int)typeValue));
							}
						}
					}
				}
			}
			catch (Exception)
			{
				// Нет доступа к списку провайдеров — считаем, что КриптоПро не установлен.
			}
			return providers;
		}

		/// <summary>
		/// Возвращает полные имена контейнеров провайдера (\\.\REGISTRY\..., \\.\FLASH\..., \\.\Aktiv Rutoken ...\...).
		/// </summary>
		private static List<string> EnumerateContainers(string providerName, int providerType, bool machineKeySet, List<string> warnings)
		{
			List<string> names = new List<string>();
			IntPtr providerHandle;
			uint contextFlags = CryptVerifyContext | CryptSilent | (machineKeySet ? CryptMachineKeySet : 0);
			if (!NativeMethods.CryptAcquireContext(out providerHandle, null, providerName, providerType, contextFlags))
			{
				warnings.Add("Не удалось открыть провайдер «" + providerName + "» для перечисления контейнеров: код " + Marshal.GetLastWin32Error());
				return names;
			}
			try
			{
				byte[] buffer = new byte[4096];
				uint flags = CryptFirst | CryptFullyQualifiedContainerName;
				for (int attempt = 0; attempt < MaxContainersPerProvider; attempt++)
				{
					int length = buffer.Length;
					if (!NativeMethods.CryptGetProvParam(providerHandle, PpEnumContainers, buffer, ref length, flags))
					{
						int error = Marshal.GetLastWin32Error();
						if (error == ErrorMoreData && length > buffer.Length)
						{
							buffer = new byte[length];
							continue;
						}
						if (error != ErrorNoMoreItems)
						{
							warnings.Add("Перечисление контейнеров «" + providerName + "» прервано: код " + error);
						}
						break;
					}
					string name = DecodeContainerName(buffer, length);
					if (name.Length > 0 && !names.Contains(name))
					{
						names.Add(name);
					}
					flags = CryptNext | CryptFullyQualifiedContainerName;
				}
			}
			finally
			{
				NativeMethods.CryptReleaseContext(providerHandle, 0);
			}
			return names;
		}

		/// <summary>
		/// Открывает контейнер без интерфейса и читает сертификаты ключей обмена и подписи.
		/// </summary>
		private static void ReadContainerCertificates(string providerName, int providerType, string containerName, bool machineKeySet,
			List<ContainerCertificate> certificates, List<string> warnings)
		{
			IntPtr containerHandle;
			uint contextFlags = CryptSilent | (machineKeySet ? CryptMachineKeySet : 0);
			if (!NativeMethods.CryptAcquireContext(out containerHandle, containerName, providerName, providerType, contextFlags))
			{
				warnings.Add("Контейнер КриптоПро «" + containerName + "» не открыт без ввода PIN-кода или недоступен (код " + Marshal.GetLastWin32Error() + ")");
				return;
			}
			try
			{
				foreach (int keySpec in new[] { KeySpecExchange, KeySpecSignature })
				{
					byte[] encodedCertificate = TryReadKeyCertificate(containerHandle, keySpec);
					if (encodedCertificate == null)
					{
						continue;
					}
					try
					{
						ContainerCertificate found = new ContainerCertificate();
						found.Certificate = new X509Certificate2(encodedCertificate);
						found.ContainerName = containerName + (machineKeySet ? " (ключи компьютера)" : string.Empty);
						certificates.Add(found);
					}
					catch (Exception exception)
					{
						warnings.Add("Сертификат в контейнере «" + containerName + "» не разобран: " + exception.Message);
					}
				}
			}
			finally
			{
				NativeMethods.CryptReleaseContext(containerHandle, 0);
			}
		}

		/// <summary>
		/// Запрашивает у CSP сертификат, записанный в контейнер для ключа указанного типа. Возвращает null, если его нет.
		/// </summary>
		private static byte[] TryReadKeyCertificate(IntPtr containerHandle, int keySpec)
		{
			IntPtr keyHandle;
			if (!NativeMethods.CryptGetUserKey(containerHandle, keySpec, out keyHandle))
			{
				return null;
			}
			try
			{
				int length = 0;
				if (!NativeMethods.CryptGetKeyParam(keyHandle, KeyParameterCertificate, null, ref length, 0) || length <= 0)
				{
					return null;
				}
				byte[] data = new byte[length];
				if (!NativeMethods.CryptGetKeyParam(keyHandle, KeyParameterCertificate, data, ref length, 0))
				{
					return null;
				}
				if (length != data.Length)
				{
					byte[] trimmed = new byte[length];
					Buffer.BlockCopy(data, 0, trimmed, 0, length);
					return trimmed;
				}
				return data;
			}
			finally
			{
				NativeMethods.CryptDestroyKey(keyHandle);
			}
		}

		/// <summary>
		/// Преобразует имя контейнера из буфера CryptoAPI (строка ANSI с нулевым символом в конце) в строку .NET.
		/// </summary>
		public static string DecodeContainerName(byte[] buffer, int length)
		{
			int end = 0;
			int limit = Math.Min(length, buffer.Length);
			while (end < limit && buffer[end] != 0)
			{
				end = end + 1;
			}
			return Encoding.Default.GetString(buffer, 0, end).Trim();
		}

		/// <summary>
		/// Вызовы CryptoAPI (advapi32.dll).
		/// </summary>
		private static class NativeMethods
		{
			[DllImport("advapi32.dll", EntryPoint = "CryptAcquireContextW", CharSet = CharSet.Unicode, SetLastError = true)]
			public static extern bool CryptAcquireContext(out IntPtr providerHandle, string containerName, string providerName, int providerType, uint flags);

			[DllImport("advapi32.dll", SetLastError = true)]
			public static extern bool CryptGetProvParam(IntPtr providerHandle, int parameter, [Out] byte[] data, ref int dataLength, uint flags);

			[DllImport("advapi32.dll", SetLastError = true)]
			public static extern bool CryptGetUserKey(IntPtr providerHandle, int keySpec, out IntPtr keyHandle);

			[DllImport("advapi32.dll", SetLastError = true)]
			public static extern bool CryptGetKeyParam(IntPtr keyHandle, int parameter, [Out] byte[] data, ref int dataLength, int flags);

			[DllImport("advapi32.dll", SetLastError = true)]
			public static extern bool CryptDestroyKey(IntPtr keyHandle);

			[DllImport("advapi32.dll", SetLastError = true)]
			public static extern bool CryptReleaseContext(IntPtr providerHandle, int flags);
		}
	}
}
