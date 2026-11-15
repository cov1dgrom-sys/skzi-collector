using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using Microsoft.Win32;
using Skzi.Common.Certificates;

namespace Skzi.Common.Scanning
{
	/// <summary>
	/// Сертификат, найденный в хранилище Windows, вместе с описанием источника.
	/// </summary>
	public sealed class StoreCertificate
	{
		public X509Certificate2 Certificate { get; set; }
		public string Source { get; set; }
		public bool HasPrivateKeyLink { get; set; }
	}

	/// <summary>
	/// Сбор личных сертификатов (хранилище «Личное» / My), установленных на ПК:
	/// текущего пользователя, локального компьютера, всех пользователей с загруженными профилями (HKEY_USERS)
	/// и всех профилей пользователей на диске (файловая часть хранилища — в том числе тех, кто сейчас не вошёл в систему).
	/// </summary>
	public static class CertificateStoreScanner
	{
		private const string PersonalStoreRegistryPath = @"Software\Microsoft\SystemCertificates\My\Certificates";
		private const string ProfileListRegistryPath = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList";
		private const string ProfilePersonalStorePath = @"AppData\Roaming\Microsoft\SystemCertificates\My\Certificates";
		private const int MaxStoreFileSizeBytes = 1024 * 1024;

		/// <summary>
		/// Собирает личные сертификаты целевого ПК. Ошибки доступа фиксируются в warnings и не прерывают сбор.
		/// </summary>
		public static List<StoreCertificate> CollectPersonalCertificates(IScanTarget target, List<string> warnings)
		{
			List<StoreCertificate> certificates = new List<StoreCertificate>();
			string currentUserSid = null;

			if (target.IsLocal)
			{
				WindowsIdentity identity = WindowsIdentity.GetCurrent();
				currentUserSid = identity.User == null ? null : identity.User.Value;
				ReadX509Store(StoreLocation.CurrentUser, "Личное хранилище пользователя " + identity.Name, certificates, warnings);
				ReadX509Store(StoreLocation.LocalMachine, "Личное хранилище компьютера", certificates, warnings);
			}
			else
			{
				ReadRegistryStore(target, RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\SystemCertificates\My\Certificates",
					"Личное хранилище компьютера (реестр)", certificates, warnings);
			}

			ReadAllUserHives(target, currentUserSid, certificates, warnings);
			ReadAllProfileFileStores(target, certificates, warnings);
			return certificates;
		}

		/// <summary>
		/// Читает файловую часть хранилища «Личное» в профиле каждого пользователя ПК
		/// (%APPDATA%\Microsoft\SystemCertificates\My\Certificates). Профиль не обязательно должен быть загружен.
		/// </summary>
		private static void ReadAllProfileFileStores(IScanTarget target, List<StoreCertificate> certificates, List<string> warnings)
		{
			Dictionary<string, string> profiles = ReadProfileList(target, warnings);
			foreach (KeyValuePair<string, string> profile in profiles)
			{
				string storeDirectory = target.MapPath(Path.Combine(profile.Value, ProfilePersonalStorePath), new List<string>());
				if (storeDirectory == null)
				{
					continue;
				}
				string[] files;
				try
				{
					if (!Directory.Exists(storeDirectory))
					{
						continue;
					}
					files = Directory.GetFiles(storeDirectory);
				}
				catch (Exception exception)
				{
					warnings.Add("Нет доступа к хранилищу сертификатов в профиле " + profile.Value + ": " + exception.Message);
					continue;
				}

				string sourceDescription = "Личное хранилище пользователя " + ResolveAccountName(target, profile.Key) + " (профиль на диске)";
				foreach (string filePath in files)
				{
					try
					{
						FileInfo fileInfo = new FileInfo(filePath);
						if (fileInfo.Length == 0 || fileInfo.Length > MaxStoreFileSizeBytes)
						{
							continue;
						}
						bool hasPrivateKeyLink;
						X509Certificate2 certificate = CertificateFileLoader.LoadFromSerializedStoreElement(File.ReadAllBytes(filePath), out hasPrivateKeyLink);
						StoreCertificate found = new StoreCertificate();
						found.Certificate = certificate;
						found.Source = sourceDescription;
						found.HasPrivateKeyLink = hasPrivateKeyLink;
						certificates.Add(found);
					}
					catch (Exception exception)
					{
						warnings.Add("Не удалось прочитать сертификат из профиля " + profile.Value + " (" + Path.GetFileName(filePath) + "): " + exception.Message);
					}
				}
			}
		}

		/// <summary>
		/// Возвращает профили пользователей ПК: SID → папка профиля (только обычные учётные записи S-1-5-21-...).
		/// </summary>
		private static Dictionary<string, string> ReadProfileList(IScanTarget target, List<string> warnings)
		{
			Dictionary<string, string> profiles = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
			try
			{
				using (RegistryKey machineRoot = target.OpenRegistryBase(RegistryHive.LocalMachine, RegistryView.Default))
				using (RegistryKey profileListKey = machineRoot.OpenSubKey(ProfileListRegistryPath, false))
				{
					if (profileListKey == null)
					{
						return profiles;
					}
					foreach (string sid in profileListKey.GetSubKeyNames())
					{
						if (!sid.StartsWith("S-1-5-21-", StringComparison.OrdinalIgnoreCase))
						{
							continue;
						}
						using (RegistryKey profileKey = profileListKey.OpenSubKey(sid, false))
						{
							string profilePath = profileKey == null ? null : profileKey.GetValue("ProfileImagePath") as string;
							if (!string.IsNullOrWhiteSpace(profilePath))
							{
								profiles[sid] = profilePath.Trim();
							}
						}
					}
				}
			}
			catch (Exception exception)
			{
				warnings.Add("Не удалось получить список профилей пользователей " + target.ComputerName + ": " + exception.Message);
			}
			return profiles;
		}

		/// <summary>
		/// Читает хранилище «Личное» штатными средствами .NET (локальный ПК).
		/// </summary>
		private static void ReadX509Store(StoreLocation location, string sourceDescription, List<StoreCertificate> certificates, List<string> warnings)
		{
			X509Store store = new X509Store(StoreName.My, location);
			try
			{
				store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
				foreach (X509Certificate2 certificate in store.Certificates)
				{
					StoreCertificate found = new StoreCertificate();
					found.Certificate = certificate;
					found.Source = sourceDescription;
					found.HasPrivateKeyLink = SafeHasPrivateKey(certificate);
					certificates.Add(found);
				}
			}
			catch (Exception exception)
			{
				warnings.Add("Не удалось открыть хранилище «" + sourceDescription + "»: " + exception.Message);
			}
			finally
			{
				store.Close();
			}
		}

		/// <summary>
		/// Перебирает загруженные профили пользователей в HKEY_USERS и читает их личные хранилища из реестра.
		/// Так агент, работающий как служба (SYSTEM), видит сертификаты всех вошедших пользователей.
		/// </summary>
		private static void ReadAllUserHives(IScanTarget target, string skipSid, List<StoreCertificate> certificates, List<string> warnings)
		{
			RegistryKey usersRoot;
			try
			{
				usersRoot = target.OpenRegistryBase(RegistryHive.Users, RegistryView.Default);
			}
			catch (Exception exception)
			{
				warnings.Add("Нет доступа к разделу реестра HKEY_USERS на " + target.ComputerName + ": " + exception.Message);
				return;
			}

			using (usersRoot)
			{
				string[] userSids;
				try
				{
					userSids = usersRoot.GetSubKeyNames();
				}
				catch (Exception exception)
				{
					warnings.Add("Не удалось перечислить профили пользователей: " + exception.Message);
					return;
				}

				foreach (string sid in userSids)
				{
					if (!sid.StartsWith("S-1-5-21-", StringComparison.OrdinalIgnoreCase) || sid.EndsWith("_Classes", StringComparison.OrdinalIgnoreCase))
					{
						continue;
					}
					if (skipSid != null && string.Equals(sid, skipSid, StringComparison.OrdinalIgnoreCase))
					{
						continue;
					}
					string accountName = ResolveAccountName(target, sid);
					ReadRegistryStoreFromKey(usersRoot, sid + @"\" + PersonalStoreRegistryPath,
						"Личное хранилище пользователя " + accountName, certificates, warnings, false);
				}
			}
		}

		/// <summary>
		/// Открывает корень реестра и читает хранилище сертификатов по указанному пути.
		/// </summary>
		private static void ReadRegistryStore(IScanTarget target, RegistryHive hive, string storePath, string sourceDescription,
			List<StoreCertificate> certificates, List<string> warnings)
		{
			try
			{
				using (RegistryKey root = target.OpenRegistryBase(hive, RegistryView.Default))
				{
					ReadRegistryStoreFromKey(root, storePath, sourceDescription, certificates, warnings, true);
				}
			}
			catch (Exception exception)
			{
				warnings.Add("Нет доступа к реестру " + target.ComputerName + " (" + sourceDescription + "): " + exception.Message);
			}
		}

		/// <summary>
		/// Читает сертификаты из раздела реестра хранилища: каждый подраздел — отпечаток, значение Blob — сертификат.
		/// </summary>
		private static void ReadRegistryStoreFromKey(RegistryKey root, string storePath, string sourceDescription,
			List<StoreCertificate> certificates, List<string> warnings, bool reportMissingStore)
		{
			RegistryKey storeKey;
			try
			{
				storeKey = root.OpenSubKey(storePath, false);
			}
			catch (Exception exception)
			{
				warnings.Add("Нет доступа к «" + sourceDescription + "»: " + exception.Message);
				return;
			}
			if (storeKey == null)
			{
				if (reportMissingStore)
				{
					warnings.Add("Хранилище не найдено: " + sourceDescription);
				}
				return;
			}

			using (storeKey)
			{
				foreach (string thumbprint in storeKey.GetSubKeyNames())
				{
					try
					{
						using (RegistryKey certificateKey = storeKey.OpenSubKey(thumbprint, false))
						{
							byte[] blob = certificateKey == null ? null : certificateKey.GetValue("Blob") as byte[];
							if (blob == null || blob.Length == 0)
							{
								continue;
							}
							bool hasPrivateKeyLink;
							X509Certificate2 certificate = CertificateFileLoader.LoadFromSerializedStoreElement(blob, out hasPrivateKeyLink);
							StoreCertificate found = new StoreCertificate();
							found.Certificate = certificate;
							found.Source = sourceDescription;
							found.HasPrivateKeyLink = hasPrivateKeyLink;
							certificates.Add(found);
						}
					}
					catch (Exception exception)
					{
						warnings.Add("Не удалось прочитать сертификат " + thumbprint + " из «" + sourceDescription + "»: " + exception.Message);
					}
				}
			}
		}

		/// <summary>
		/// Определяет имя учётной записи по SID: через Windows (локально/в домене), иначе по папке профиля, иначе SID.
		/// </summary>
		private static string ResolveAccountName(IScanTarget target, string sid)
		{
			try
			{
				SecurityIdentifier securityIdentifier = new SecurityIdentifier(sid);
				NTAccount account = (NTAccount)securityIdentifier.Translate(typeof(NTAccount));
				if (target.IsLocal || !account.Value.StartsWith(Environment.MachineName + "\\", StringComparison.OrdinalIgnoreCase))
				{
					return account.Value;
				}
			}
			catch (Exception)
			{
				// SID локальной учётной записи удалённого ПК не разрешается — пробуем путь профиля.
			}

			try
			{
				using (RegistryKey machineRoot = target.OpenRegistryBase(RegistryHive.LocalMachine, RegistryView.Default))
				using (RegistryKey profileKey = machineRoot.OpenSubKey(ProfileListRegistryPath + @"\" + sid, false))
				{
					string profilePath = profileKey == null ? null : profileKey.GetValue("ProfileImagePath") as string;
					if (!string.IsNullOrWhiteSpace(profilePath))
					{
						return Path.GetFileName(profilePath.TrimEnd('\\')) + " (" + sid + ")";
					}
				}
			}
			catch (Exception)
			{
				// Нет доступа к списку профилей — вернём SID.
			}
			return sid;
		}

		/// <summary>
		/// Безопасно проверяет наличие закрытого ключа у сертификата.
		/// </summary>
		private static bool SafeHasPrivateKey(X509Certificate2 certificate)
		{
			try
			{
				return certificate.HasPrivateKey;
			}
			catch (Exception)
			{
				return false;
			}
		}
	}
}
