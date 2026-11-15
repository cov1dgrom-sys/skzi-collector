using System;
using System.Collections.Generic;
using System.IO;
using System.Text.RegularExpressions;
using Microsoft.Win32;

namespace Skzi.Common.Scanning
{
	/// <summary>
	/// Сканируемый компьютер: даёт доступ к его файловой системе и реестру.
	/// </summary>
	public interface IScanTarget
	{
		/// <summary>Имя компьютера.</summary>
		string ComputerName { get; }

		/// <summary>Признак локального компьютера.</summary>
		bool IsLocal { get; }

		/// <summary>
		/// Преобразует путь «как на целевом ПК» (C:\Certs) в путь, доступный текущему процессу.
		/// Возвращает null, если путь преобразовать нельзя (причина добавляется в warnings).
		/// </summary>
		string MapPath(string targetPath, List<string> warnings);

		/// <summary>
		/// Обратное преобразование: путь, доступный текущему процессу (\\ПК\C$\Certs), в путь «как на целевом ПК» (C:\Certs).
		/// Используется в отчётах и БД, чтобы один и тот же файл записывался одинаково при любом способе сканирования.
		/// </summary>
		string ToTargetPath(string accessiblePath);

		/// <summary>
		/// Открывает корневой раздел реестра целевого ПК в указанном представлении (32/64 бит).
		/// </summary>
		RegistryKey OpenRegistryBase(RegistryHive hive, RegistryView view);
	}

	/// <summary>
	/// Локальный компьютер (сканирование агентом или панелью «Этот ПК»).
	/// </summary>
	public sealed class LocalScanTarget : IScanTarget
	{
		public string ComputerName
		{
			get { return Environment.MachineName; }
		}

		public bool IsLocal
		{
			get { return true; }
		}

		/// <summary>
		/// Раскрывает переменные окружения в пути; путь с нераскрытыми переменными пропускается.
		/// </summary>
		public string MapPath(string targetPath, List<string> warnings)
		{
			string expanded = Environment.ExpandEnvironmentVariables(targetPath.Trim());
			if (expanded.Contains("%"))
			{
				warnings.Add("Не удалось раскрыть переменные окружения в пути: " + targetPath);
				return null;
			}
			if (!Path.IsPathRooted(expanded))
			{
				expanded = Path.GetFullPath(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, expanded));
			}
			return expanded;
		}

		/// <summary>
		/// Локальный путь не требует преобразования.
		/// </summary>
		public string ToTargetPath(string accessiblePath)
		{
			return accessiblePath;
		}

		/// <summary>
		/// Открывает локальный раздел реестра.
		/// </summary>
		public RegistryKey OpenRegistryBase(RegistryHive hive, RegistryView view)
		{
			return RegistryKey.OpenBaseKey(hive, view);
		}
	}

	/// <summary>
	/// Удалённый компьютер без агента: файлы читаются через административные ресурсы (\\ПК\C$),
	/// реестр — через службу «Удалённый реестр». Требуются права администратора на целевом ПК.
	/// </summary>
	public sealed class RemoteAdminShareTarget : IScanTarget
	{
		private static readonly Regex DriveLetterPathRegex = new Regex(@"^(?<drive>[A-Za-z]):\\?(?<rest>.*)$", RegexOptions.CultureInvariant);

		private readonly string hostName;

		/// <summary>
		/// Создаёт цель сканирования для удалённого ПК по имени или IP-адресу.
		/// </summary>
		public RemoteAdminShareTarget(string hostName)
		{
			if (string.IsNullOrWhiteSpace(hostName))
			{
				throw new ArgumentException("Не указано имя компьютера", "hostName");
			}
			this.hostName = hostName.Trim().TrimStart('\\');
		}

		public string ComputerName
		{
			get { return hostName; }
		}

		public bool IsLocal
		{
			get { return false; }
		}

		/// <summary>
		/// Преобразует «C:\Certs» в «\\ПК\C$\Certs». Переменные окружения целевого ПК раскрываются
		/// только системные (%SystemDrive%, %SystemRoot%, %ProgramData%, %Public%), пользовательские — нельзя.
		/// </summary>
		public string MapPath(string targetPath, List<string> warnings)
		{
			string path = targetPath.Trim();
			path = ReplaceVariable(path, "%SystemDrive%", "C:");
			path = ReplaceVariable(path, "%SystemRoot%", @"C:\Windows");
			path = ReplaceVariable(path, "%WinDir%", @"C:\Windows");
			path = ReplaceVariable(path, "%ProgramData%", @"C:\ProgramData");
			path = ReplaceVariable(path, "%Public%", @"C:\Users\Public");
			path = ReplaceVariable(path, "%ProgramFiles%", @"C:\Program Files");
			if (path.Contains("%"))
			{
				warnings.Add("Путь с пользовательскими переменными окружения нельзя просканировать без агента (используйте маску C:\\Users\\*\\...): " + targetPath);
				return null;
			}
			if (path.StartsWith(@"\\", StringComparison.Ordinal))
			{
				return path;
			}
			Match match = DriveLetterPathRegex.Match(path);
			if (!match.Success)
			{
				warnings.Add("Относительный путь нельзя просканировать на удалённом ПК: " + targetPath);
				return null;
			}
			return @"\\" + hostName + @"\" + match.Groups["drive"].Value.ToUpperInvariant() + @"$\" + match.Groups["rest"].Value;
		}

		/// <summary>
		/// Преобразует «\\ПК\C$\Certs\a.cer» обратно в «C:\Certs\a.cer»; другие пути возвращает без изменений.
		/// </summary>
		public string ToTargetPath(string accessiblePath)
		{
			if (string.IsNullOrEmpty(accessiblePath))
			{
				return accessiblePath;
			}
			string prefix = @"\\" + hostName + @"\";
			if (!accessiblePath.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
			{
				return accessiblePath;
			}
			string rest = accessiblePath.Substring(prefix.Length);
			if (rest.Length >= 2 && char.IsLetter(rest[0]) && rest[1] == '$')
			{
				string tail = rest.Length > 2 ? rest.Substring(2).TrimStart('\\') : string.Empty;
				return char.ToUpperInvariant(rest[0]) + @":\" + tail;
			}
			return accessiblePath;
		}

		/// <summary>
		/// Открывает раздел реестра удалённого ПК (нужна запущенная служба RemoteRegistry).
		/// </summary>
		public RegistryKey OpenRegistryBase(RegistryHive hive, RegistryView view)
		{
			return RegistryKey.OpenRemoteBaseKey(hive, hostName, view);
		}

		/// <summary>
		/// Заменяет переменную окружения в пути без учёта регистра.
		/// </summary>
		private static string ReplaceVariable(string path, string variable, string value)
		{
			return Regex.Replace(path, Regex.Escape(variable), value.Replace("$", "$$"), RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
		}
	}
}
