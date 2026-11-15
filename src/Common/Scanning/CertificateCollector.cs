using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.Threading;
using Skzi.Common.Certificates;
using Skzi.Common.Configuration;
using Skzi.Common.Logging;

namespace Skzi.Common.Scanning
{
	/// <summary>
	/// Выполняет полное сканирование одного ПК: версия КриптоПро, личные хранилища сертификатов,
	/// ключевые контейнеры КриптоПро, файлы сертификатов в указанных директориях, парсинг и устранение дублей.
	/// </summary>
	public static class CertificateCollector
	{
		public const string ModeLocal = "Local";
		public const string ModeAgent = "Agent";
		public const string ModeAgentless = "Agentless";

		/// <summary>
		/// Сканирует целевой ПК и возвращает результат. Отмена — через cancellationToken (OperationCanceledException).
		/// </summary>
		public static ScanResult Scan(IScanTarget target, ScanOptions options, string scanMode, CancellationToken cancellationToken)
		{
			Stopwatch stopwatch = Stopwatch.StartNew();
			ScanResult result = new ScanResult();
			result.ComputerName = target.IsLocal ? Environment.MachineName : target.ComputerName;
			result.ScanMode = scanMode;
			result.ScannedAs = GetCurrentAccountName();
			result.OperatingSystem = target.IsLocal ? Environment.OSVersion.VersionString : null;
			result.ScannerVersion = GetScannerVersion();
			result.StartedAt = DateTime.Now;

			Logger.Info("Начато сканирование ПК " + result.ComputerName + " (режим: " + scanMode + ", директорий в задании: " + options.Directories.Count + ")");

			result.CryptoPro = CryptoProDetector.Detect(target, result.Warnings);
			Logger.Info("КриптоПро на " + result.ComputerName + ": " + result.CryptoPro.DisplayText);
			cancellationToken.ThrowIfCancellationRequested();

			Dictionary<string, CertificateRecord> recordsByThumbprint = new Dictionary<string, CertificateRecord>(StringComparer.OrdinalIgnoreCase);

			if (options.ScanCertificateStores)
			{
				CollectFromStores(target, result, recordsByThumbprint);
				result.CertificateStoresScanned = true;
			}
			cancellationToken.ThrowIfCancellationRequested();

			if (options.ScanCryptoProContainers)
			{
				CollectFromContainers(target, result, recordsByThumbprint);
			}
			cancellationToken.ThrowIfCancellationRequested();

			List<string> candidateFiles = DirectoryScanner.FindCertificateFiles(target, options, result, cancellationToken);
			Logger.Info("На " + result.ComputerName + " найдено файлов-кандидатов: " + candidateFiles.Count + " (просмотрено директорий: " + result.DirectoriesScanned + ")");
			foreach (string filePath in candidateFiles)
			{
				cancellationToken.ThrowIfCancellationRequested();
				CollectFromFile(target, filePath, options, result, recordsByThumbprint);
			}

			result.Certificates.AddRange(recordsByThumbprint.Values);
			result.Certificates.Sort(delegate (CertificateRecord left, CertificateRecord right)
			{
				return string.Compare(left.OwnerName, right.OwnerName, StringComparison.CurrentCultureIgnoreCase);
			});
			result.FinishedAt = DateTime.Now;
			stopwatch.Stop();

			Logger.Info("Сканирование ПК " + result.ComputerName + " завершено за " + stopwatch.ElapsedMilliseconds + " мс: сертификатов " + result.Certificates.Count
				+ ", файлов обработано " + result.FilesScanned + ", ошибок разбора " + result.FilesFailed + ", предупреждений " + result.Warnings.Count);
			return result;
		}

		/// <summary>
		/// Добавляет в результат сертификаты из личных хранилищ Windows.
		/// </summary>
		private static void CollectFromStores(IScanTarget target, ScanResult result, Dictionary<string, CertificateRecord> recordsByThumbprint)
		{
			List<StoreCertificate> storeCertificates = CertificateStoreScanner.CollectPersonalCertificates(target, result.Warnings);
			foreach (StoreCertificate storeCertificate in storeCertificates)
			{
				try
				{
					CertificateRecord record = MergeCertificate(storeCertificate.Certificate, storeCertificate.Source, recordsByThumbprint);
					record.HasPrivateKey = record.HasPrivateKey || storeCertificate.HasPrivateKeyLink;
					result.StoreCertificatesFound = result.StoreCertificatesFound + 1;
				}
				catch (Exception exception)
				{
					result.Warnings.Add("Ошибка разбора сертификата из «" + storeCertificate.Source + "»: " + exception.Message);
					Logger.Error("Ошибка разбора сертификата из хранилища «" + storeCertificate.Source + "»", exception);
				}
				finally
				{
					storeCertificate.Certificate.Reset();
				}
			}
			Logger.Info("В хранилищах сертификатов " + result.ComputerName + " найдено: " + storeCertificates.Count);
		}

		/// <summary>
		/// Добавляет в результат сертификаты из ключевых контейнеров КриптоПро (только локально: агент или «Этот ПК»).
		/// </summary>
		private static void CollectFromContainers(IScanTarget target, ScanResult result, Dictionary<string, CertificateRecord> recordsByThumbprint)
		{
			if (!target.IsLocal)
			{
				result.Warnings.Add("Контейнеры КриптоПро (токены, флешки, реестр) проверяются только агентом на самом ПК — в безагентном режиме пропущены.");
				return;
			}
			result.CryptoProContainersScanned = true;
			if (!result.CryptoPro.IsInstalled)
			{
				Logger.Info("КриптоПро CSP на " + result.ComputerName + " не установлен — ключевые контейнеры не проверялись");
				return;
			}

			List<ContainerCertificate> containerCertificates = CryptoProContainerScanner.CollectCertificates(result.Warnings);
			foreach (ContainerCertificate containerCertificate in containerCertificates)
			{
				try
				{
					CertificateRecord record = MergeCertificate(containerCertificate.Certificate,
						CertificateSources.ForContainer(containerCertificate.ContainerName), recordsByThumbprint);
					record.HasPrivateKey = true;
					result.ContainerCertificatesFound = result.ContainerCertificatesFound + 1;
				}
				catch (Exception exception)
				{
					result.Warnings.Add("Ошибка разбора сертификата из контейнера «" + containerCertificate.ContainerName + "»: " + exception.Message);
					Logger.Error("Ошибка разбора сертификата из контейнера КриптоПро «" + containerCertificate.ContainerName + "»", exception);
				}
				finally
				{
					containerCertificate.Certificate.Reset();
				}
			}
			Logger.Info("В ключевых контейнерах КриптоПро на " + result.ComputerName + " найдено сертификатов: " + containerCertificates.Count);
		}

		/// <summary>
		/// Загружает и разбирает сертификаты из одного файла; неудачи учитываются в статистике и предупреждениях.
		/// В результат путь записывается так, как он выглядит на сканируемом ПК (C:\...), а не \\ПК\C$\...
		/// </summary>
		private static void CollectFromFile(IScanTarget target, string filePath, ScanOptions options, ScanResult result,
			Dictionary<string, CertificateRecord> recordsByThumbprint)
		{
			result.FilesScanned = result.FilesScanned + 1;
			string displayPath = target.ToTargetPath(filePath);
			List<X509Certificate2> certificates;
			try
			{
				certificates = CertificateFileLoader.LoadFromFile(filePath, options.Pkcs12Passwords);
			}
			catch (PasswordProtectedFileException exception)
			{
				result.FilesFailed = result.FilesFailed + 1;
				DirectoryScanner.AddWarning(result, exception.Message + ": " + displayPath);
				Logger.Warning("Файл " + displayPath + " не прочитан: " + exception.Message);
				return;
			}
			catch (Exception exception)
			{
				result.FilesFailed = result.FilesFailed + 1;
				DirectoryScanner.AddWarning(result, "Файл не является корректным сертификатом: " + displayPath + " (" + exception.Message.Trim() + ")");
				Logger.Warning("Не удалось разобрать файл " + displayPath + ": " + exception.GetType().Name + ": " + exception.Message.Trim());
				return;
			}

			foreach (X509Certificate2 certificate in certificates)
			{
				try
				{
					CertificateRecord record = MergeCertificate(certificate, CertificateSources.ForFile(displayPath), recordsByThumbprint);
					// Один и тот же сертификат может встретиться и как .cer (без ключа), и как .p12 (с ключом).
					// Отметку о закрытом ключе проставляем, если ключ есть хотя бы в одном источнике — как для хранилищ и контейнеров.
					if (!record.HasPrivateKey && FileCertificateHasPrivateKey(certificate))
					{
						record.HasPrivateKey = true;
					}
				}
				catch (Exception exception)
				{
					result.FilesFailed = result.FilesFailed + 1;
					DirectoryScanner.AddWarning(result, "Ошибка парсинга сертификата в файле " + displayPath + ": " + exception.Message);
					Logger.Error("Ошибка парсинга сертификата в файле " + displayPath, exception);
				}
				finally
				{
					certificate.Reset();
				}
			}
		}

		/// <summary>
		/// Безопасно проверяет наличие закрытого ключа у сертификата из файла (.p12/.pfx): обращение к ключу
		/// может бросить исключение для некоторых провайдеров, поэтому ошибки трактуем как «ключа нет».
		/// </summary>
		private static bool FileCertificateHasPrivateKey(X509Certificate2 certificate)
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

		/// <summary>
		/// Разбирает сертификат и объединяет его с уже найденным (по отпечатку), дополняя список источников.
		/// </summary>
		private static CertificateRecord MergeCertificate(X509Certificate2 certificate, string source, Dictionary<string, CertificateRecord> recordsByThumbprint)
		{
			CertificateRecord existing;
			if (recordsByThumbprint.TryGetValue(certificate.Thumbprint, out existing))
			{
				existing.AddSource(source);
				return existing;
			}
			CertificateRecord record = CertificateParser.Parse(certificate);
			record.AddSource(source);
			recordsByThumbprint[record.Thumbprint] = record;
			return record;
		}

		/// <summary>
		/// Возвращает имя текущей учётной записи Windows.
		/// </summary>
		public static string GetCurrentAccountName()
		{
			try
			{
				return WindowsIdentity.GetCurrent().Name;
			}
			catch (Exception)
			{
				return Environment.UserDomainName + "\\" + Environment.UserName;
			}
		}

		/// <summary>
		/// Версия сборки, выполняющей сканирование.
		/// </summary>
		public static string GetScannerVersion()
		{
			Assembly entryAssembly = Assembly.GetEntryAssembly() ?? Assembly.GetExecutingAssembly();
			AssemblyName assemblyName = entryAssembly.GetName();
			return assemblyName.Name + " " + assemblyName.Version;
		}
	}
}
