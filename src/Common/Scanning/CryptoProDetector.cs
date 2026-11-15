using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Win32;
using Skzi.Common.Certificates;

namespace Skzi.Common.Scanning
{
	/// <summary>
	/// Определение установленной версии КриптоПро CSP и сведений о её лицензии на целевом ПК.
	/// Источники: список установленных программ (Uninstall), данные установщика MSI (серийный номер),
	/// зарегистрированные криптопровайдеры (версия файла CSP) и утилита cpconfig (только локально).
	/// </summary>
	public static class CryptoProDetector
	{
		private const string UninstallPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
		private const string InstallerProductsPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products";
		private const string CryptoProvidersPath = @"SOFTWARE\Microsoft\Cryptography\Defaults\Provider";

		private static readonly Regex CryptoProProductRegex = new Regex(@"crypto-?pro|криптопро|крипто-про", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
		private static readonly Regex CspProductRegex = new Regex(@"(crypto-?pro|криптопро|крипто-про)\s*CSP", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
		private static readonly Regex LicenseKeyRegex = new Regex(@"[0-9A-Z]{5}-[0-9A-Z]{5}-[0-9A-Z]{5}-[0-9A-Z]{5}-[0-9A-Z]{5}", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
		private static readonly Regex PermanentLicenseRegex = new Regex(@"постоянн|бессрочн|permanent|unlimited", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
		private static readonly Regex ExpiryDateRegex = new Regex(
			@"(истека\w*|истечени\w*|действ\w*\s+до|срок\w*\s+действ\w*|окончани\w*|expire\w*|expiration|valid\s+(until|till|to))[^0-9]{0,40}(?<date>\d{1,2}[./]\d{1,2}[./]\d{4})",
			RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
		private static readonly Regex RemainingTimeRegex = new Regex(
			@"(?<months>\d+)\s*(мес\w*|month\w*)[^0-9]{0,12}(?<days>\d+)\s*(дн\w*|день|day\w*)",
			RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
		private static readonly Regex ExpiredRegex = new Regex(@"истекл|истёк|expired", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

		/// <summary>Длительность пробной лицензии КриптоПро CSP, если серийный номер не введён.</summary>
		public const int TrialPeriodDays = 90;

		/// <summary>
		/// Собирает сведения о КриптоПро CSP на целевом ПК. Не бросает исключений — проблемы пишет в warnings.
		/// </summary>
		public static CryptoProInfo Detect(IScanTarget target, List<string> warnings)
		{
			CryptoProInfo info = new CryptoProInfo();
			RegistryView[] views = Environment.Is64BitOperatingSystem || !target.IsLocal
				? new[] { RegistryView.Registry64, RegistryView.Registry32 }
				: new[] { RegistryView.Registry32 };

			foreach (RegistryView view in views)
			{
				try
				{
					using (RegistryKey machineRoot = target.OpenRegistryBase(RegistryHive.LocalMachine, view))
					{
						ReadUninstallEntries(machineRoot, info);
						if (view == views[0])
						{
							ReadInstallerLicense(machineRoot, info);
						}
						if (!info.IsInstalled)
						{
							ReadCryptoProviders(target, machineRoot, info);
						}
					}
				}
				catch (Exception exception)
				{
					warnings.Add("Не удалось прочитать реестр " + target.ComputerName + " (" + view + ") для определения КриптоПро: " + exception.Message);
				}
			}

			if (info.IsInstalled && target.IsLocal)
			{
				TryReadLicenseWithCpconfig(info, warnings);
			}
			if (info.IsInstalled && string.IsNullOrEmpty(info.LicenseValidity))
			{
				info.LicenseValidity = EstimateLicenseValidity(info, target.IsLocal, DateTime.Today);
			}
			return info;
		}

		/// <summary>
		/// Определяет срок действия лицензии по выводу «cpconfig -license -view»:
		/// «бессрочная», «до ДД.ММ.ГГГГ», «осталось N мес. M дн.» или «истекла». Возвращает null, если срок не найден.
		/// </summary>
		public static string ParseLicenseValidity(string cpconfigOutput)
		{
			if (string.IsNullOrWhiteSpace(cpconfigOutput))
			{
				return null;
			}
			if (PermanentLicenseRegex.IsMatch(cpconfigOutput))
			{
				return "бессрочная";
			}
			Match dateMatch = ExpiryDateRegex.Match(cpconfigOutput);
			if (dateMatch.Success)
			{
				return "до " + dateMatch.Groups["date"].Value.Replace('/', '.');
			}
			Match remainingMatch = RemainingTimeRegex.Match(cpconfigOutput);
			if (remainingMatch.Success)
			{
				int months = int.Parse(remainingMatch.Groups["months"].Value, CultureInfo.InvariantCulture);
				int days = int.Parse(remainingMatch.Groups["days"].Value, CultureInfo.InvariantCulture);
				DateTime estimatedEnd = DateTime.Today.AddMonths(months).AddDays(days);
				return "осталось " + months + " мес. " + days + " дн. (≈ до " + estimatedEnd.ToString("dd.MM.yyyy", CultureInfo.InvariantCulture) + ")";
			}
			if (ExpiredRegex.IsMatch(cpconfigOutput))
			{
				return "истекла";
			}
			return null;
		}

		/// <summary>
		/// Оценивает срок действия лицензии, если cpconfig недоступен: без серийного номера — пробный период 90 дней
		/// с даты установки; с серийным номером — срок можно узнать только на самом ПК (агентом или «Этот ПК»).
		/// </summary>
		public static string EstimateLicenseValidity(CryptoProInfo info, bool isLocal, DateTime today)
		{
			if (string.IsNullOrEmpty(info.LicenseSerialMasked))
			{
				DateTime installDate;
				if (DateTime.TryParseExact(info.InstallDate, "dd.MM.yyyy", CultureInfo.InvariantCulture, DateTimeStyles.None, out installDate))
				{
					DateTime trialEnd = installDate.AddDays(TrialPeriodDays);
					return "серийный номер не введён: пробный период " + TrialPeriodDays + " дн. с установки — "
						+ (trialEnd < today ? "истёк " : "до ") + trialEnd.ToString("dd.MM.yyyy", CultureInfo.InvariantCulture);
				}
				return "серийный номер не введён (вероятно, пробная лицензия)";
			}
			return isLocal
				? "не определён (cpconfig не сообщил срок)"
				: "не определён: срок виден при сканировании через агент";
		}

		/// <summary>
		/// Ищет КриптоПро в списке установленных программ (Программы и компоненты).
		/// </summary>
		private static void ReadUninstallEntries(RegistryKey machineRoot, CryptoProInfo info)
		{
			using (RegistryKey uninstallKey = machineRoot.OpenSubKey(UninstallPath, false))
			{
				if (uninstallKey == null)
				{
					return;
				}
				foreach (string productKeyName in uninstallKey.GetSubKeyNames())
				{
					using (RegistryKey productKey = uninstallKey.OpenSubKey(productKeyName, false))
					{
						if (productKey == null)
						{
							continue;
						}
						string displayName = productKey.GetValue("DisplayName") as string;
						if (string.IsNullOrWhiteSpace(displayName) || !CryptoProProductRegex.IsMatch(displayName))
						{
							continue;
						}
						string displayVersion = Convert.ToString(productKey.GetValue("DisplayVersion"));
						if (CspProductRegex.IsMatch(displayName))
						{
							if (!info.IsInstalled || CompareVersions(displayVersion, info.Version) > 0)
							{
								info.IsInstalled = true;
								info.ProductName = displayName.Trim();
								info.Version = displayVersion;
								info.DetectionSource = "Реестр: установленные программы";
								info.InstallDate = FormatInstallDate(productKey.GetValue("InstallDate") as string);
							}
						}
						else
						{
							AddOtherProduct(info, displayName.Trim() + (string.IsNullOrWhiteSpace(displayVersion) ? string.Empty : " " + displayVersion));
						}
					}
				}
			}
		}

		/// <summary>
		/// Преобразует дату установки из реестра (ГГГГММДД) в вид ДД.ММ.ГГГГ; некорректная дата — null.
		/// </summary>
		public static string FormatInstallDate(string registryValue)
		{
			DateTime installDate;
			if (string.IsNullOrWhiteSpace(registryValue)
				|| !DateTime.TryParseExact(registryValue.Trim(), "yyyyMMdd", CultureInfo.InvariantCulture, DateTimeStyles.None, out installDate))
			{
				return null;
			}
			return installDate.ToString("dd.MM.yyyy", CultureInfo.InvariantCulture);
		}

		/// <summary>
		/// Читает серийный номер лицензии КриптоПро CSP из данных установщика Windows (ProductID).
		/// </summary>
		private static void ReadInstallerLicense(RegistryKey machineRoot, CryptoProInfo info)
		{
			using (RegistryKey productsKey = machineRoot.OpenSubKey(InstallerProductsPath, false))
			{
				if (productsKey == null)
				{
					return;
				}
				foreach (string productCode in productsKey.GetSubKeyNames())
				{
					using (RegistryKey propertiesKey = productsKey.OpenSubKey(productCode + @"\InstallProperties", false))
					{
						if (propertiesKey == null)
						{
							continue;
						}
						string displayName = propertiesKey.GetValue("DisplayName") as string;
						if (string.IsNullOrWhiteSpace(displayName) || !CspProductRegex.IsMatch(displayName))
						{
							continue;
						}
						string productId = propertiesKey.GetValue("ProductID") as string;
						if (!string.IsNullOrWhiteSpace(productId) && LicenseKeyRegex.IsMatch(productId))
						{
							string serial = LicenseKeyRegex.Match(productId).Value.ToUpperInvariant();
							info.LicenseSerialMasked = MaskSerial(serial);
							info.LicenseVersion = CertificateParser.ExtractCryptoProVersion(new[] { serial });
						}
					}
				}
			}
		}

		/// <summary>
		/// Резервный способ: ищет зарегистрированный криптопровайдер КриптоПро и берёт версию его DLL.
		/// </summary>
		private static void ReadCryptoProviders(IScanTarget target, RegistryKey machineRoot, CryptoProInfo info)
		{
			using (RegistryKey providersKey = machineRoot.OpenSubKey(CryptoProvidersPath, false))
			{
				if (providersKey == null)
				{
					return;
				}
				foreach (string providerName in providersKey.GetSubKeyNames())
				{
					if (!CryptoProProductRegex.IsMatch(providerName))
					{
						continue;
					}
					info.IsInstalled = true;
					info.ProductName = "КриптоПро CSP";
					info.DetectionSource = "Реестр: криптопровайдер «" + providerName + "»";
					using (RegistryKey providerKey = providersKey.OpenSubKey(providerName, false))
					{
						string imagePath = providerKey == null ? null : providerKey.GetValue("Image Path") as string;
						string fileVersion = TryGetFileVersion(target, imagePath);
						if (!string.IsNullOrEmpty(fileVersion))
						{
							info.Version = fileVersion;
							return;
						}
					}
				}
			}
		}

		/// <summary>
		/// Получает версию файла криптопровайдера (локально или через административный ресурс).
		/// </summary>
		private static string TryGetFileVersion(IScanTarget target, string imagePath)
		{
			if (string.IsNullOrWhiteSpace(imagePath))
			{
				return null;
			}
			try
			{
				string fullPath = imagePath;
				if (!Path.IsPathRooted(fullPath))
				{
					fullPath = Path.Combine(@"%SystemRoot%\System32", fullPath);
				}
				List<string> ignoredWarnings = new List<string>();
				string accessiblePath = target.MapPath(fullPath, ignoredWarnings);
				if (accessiblePath == null || !File.Exists(accessiblePath))
				{
					return null;
				}
				FileVersionInfo versionInfo = FileVersionInfo.GetVersionInfo(accessiblePath);
				return string.IsNullOrWhiteSpace(versionInfo.ProductVersion) ? versionInfo.FileVersion : versionInfo.ProductVersion;
			}
			catch (Exception)
			{
				return null;
			}
		}

		/// <summary>
		/// Только для локального ПК: запускает «cpconfig -license -view» и сохраняет сведения о лицензии (срок действия и т.п.).
		/// </summary>
		private static void TryReadLicenseWithCpconfig(CryptoProInfo info, List<string> warnings)
		{
			string[] candidatePaths =
			{
				Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), @"Crypto Pro\CSP\cpconfig.exe"),
				Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), @"Crypto Pro\CSP\cpconfig.exe")
			};
			foreach (string candidatePath in candidatePaths)
			{
				if (string.IsNullOrEmpty(candidatePath) || !File.Exists(candidatePath))
				{
					continue;
				}
				try
				{
					ProcessStartInfo startInfo = new ProcessStartInfo(candidatePath, "-license -view");
					startInfo.UseShellExecute = false;
					startInfo.RedirectStandardOutput = true;
					startInfo.RedirectStandardError = true;
					startInfo.CreateNoWindow = true;
					startInfo.StandardOutputEncoding = Encoding.GetEncoding(866);
					using (Process process = Process.Start(startInfo))
					{
						string output = process.StandardOutput.ReadToEnd();
						if (!process.WaitForExit(10000))
						{
							process.Kill();
						}
						string cleaned = CertificateParser.MaskLicenseKeys(output);
						cleaned = LicenseKeyRegex.Replace(cleaned, delegate (Match match) { return MaskSerial(match.Value); });
						cleaned = Regex.Replace(cleaned, @"\s+", " ").Trim();
						if (cleaned.Length > 0)
						{
							info.LicenseDetails = cleaned.Length > 500 ? cleaned.Substring(0, 500) : cleaned;
						}
						info.LicenseValidity = ParseLicenseValidity(output);
						Match keyMatch = LicenseKeyRegex.Match(output);
						if (keyMatch.Success && string.IsNullOrEmpty(info.LicenseSerialMasked))
						{
							info.LicenseSerialMasked = MaskSerial(keyMatch.Value.ToUpperInvariant());
							info.LicenseVersion = CertificateParser.ExtractCryptoProVersion(new[] { keyMatch.Value });
						}
					}
				}
				catch (Exception exception)
				{
					warnings.Add("Не удалось получить сведения о лицензии через cpconfig: " + exception.Message);
				}
				return;
			}
		}

		/// <summary>
		/// Маскирует серийный номер: XXXXX-*****-*****-*****-XXXXX.
		/// </summary>
		public static string MaskSerial(string serial)
		{
			string[] groups = serial.Split('-');
			if (groups.Length < 3)
			{
				return "*****";
			}
			StringBuilder builder = new StringBuilder(groups[0]);
			for (int index = 1; index < groups.Length - 1; index++)
			{
				builder.Append("-*****");
			}
			builder.Append('-').Append(groups[groups.Length - 1]);
			return builder.ToString();
		}

		/// <summary>
		/// Добавляет продукт в список «других продуктов КриптоПро» без повторов.
		/// </summary>
		private static void AddOtherProduct(CryptoProInfo info, string product)
		{
			foreach (string existing in info.OtherProducts)
			{
				if (string.Equals(existing, product, StringComparison.OrdinalIgnoreCase))
				{
					return;
				}
			}
			info.OtherProducts.Add(product);
		}

		/// <summary>
		/// Сравнивает строки версий вида 5.0.12000; некорректные версии считаются меньшими.
		/// </summary>
		public static int CompareVersions(string left, string right)
		{
			Version leftVersion;
			Version rightVersion;
			bool leftParsed = Version.TryParse(NormalizeVersion(left), out leftVersion);
			bool rightParsed = Version.TryParse(NormalizeVersion(right), out rightVersion);
			if (!leftParsed && !rightParsed)
			{
				return 0;
			}
			if (!leftParsed)
			{
				return -1;
			}
			if (!rightParsed)
			{
				return 1;
			}
			return leftVersion.CompareTo(rightVersion);
		}

		/// <summary>
		/// Оставляет в строке версии только цифры и точки (не более 4 компонентов).
		/// </summary>
		private static string NormalizeVersion(string version)
		{
			if (string.IsNullOrWhiteSpace(version))
			{
				return null;
			}
			Match match = Regex.Match(version, @"\d+(\.\d+){0,3}");
			if (!match.Success)
			{
				return null;
			}
			return match.Value.Contains(".") ? match.Value : match.Value + ".0";
		}
	}
}
