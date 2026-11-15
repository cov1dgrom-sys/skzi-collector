using System;
using System.Collections.Generic;
using Microsoft.Win32;

namespace Skzi.Common.Database
{
	/// <summary>
	/// Поиск экземпляров Microsoft SQL Server, установленных на этом ПК (полные выпуски, Express и LocalDB).
	/// Нужен, чтобы на ПК проверяющего сервер подставлялся в настройки без ручного ввода.
	/// </summary>
	public static class SqlServerLocator
	{
		public const string FallbackServer = @"localhost\SQLEXPRESS";
		public const string LocalDbServer = @"(localdb)\MSSQLLocalDB";

		private const string InstanceNamesPath = @"SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL";
		private const string LocalDbVersionsPath = @"SOFTWARE\Microsoft\Microsoft SQL Server Local DB\Installed Versions";

		/// <summary>
		/// Возвращает имена серверов для строки подключения: «localhost», «localhost\SQLEXPRESS», «(localdb)\MSSQLLocalDB».
		/// Ошибки чтения реестра не пробрасываются.
		/// </summary>
		public static List<string> FindLocalServers()
		{
			List<string> servers = new List<string>();
			foreach (RegistryView view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
			{
				try
				{
					using (RegistryKey machineRoot = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view))
					using (RegistryKey instancesKey = machineRoot.OpenSubKey(InstanceNamesPath, false))
					{
						if (instancesKey == null)
						{
							continue;
						}
						foreach (string instanceName in instancesKey.GetValueNames())
						{
							string server = string.Equals(instanceName, "MSSQLSERVER", StringComparison.OrdinalIgnoreCase)
								? "localhost"
								: @"localhost\" + instanceName;
							AddUnique(servers, server);
						}
					}
				}
				catch (Exception)
				{
					// Нет доступа к реестру — пропускаем это представление.
				}
			}
			if (IsLocalDbInstalled())
			{
				AddUnique(servers, LocalDbServer);
			}
			return servers;
		}

		/// <summary>
		/// Сервер по умолчанию для новой конфигурации: первый найденный на этом ПК, иначе localhost\SQLEXPRESS.
		/// </summary>
		public static string SuggestDefaultServer()
		{
			List<string> servers = FindLocalServers();
			return servers.Count > 0 ? servers[0] : FallbackServer;
		}

		/// <summary>
		/// Проверяет, установлен ли SQL Server Express LocalDB.
		/// </summary>
		private static bool IsLocalDbInstalled()
		{
			foreach (RegistryView view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
			{
				try
				{
					using (RegistryKey machineRoot = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view))
					using (RegistryKey versionsKey = machineRoot.OpenSubKey(LocalDbVersionsPath, false))
					{
						if (versionsKey != null && versionsKey.SubKeyCount > 0)
						{
							return true;
						}
					}
				}
				catch (Exception)
				{
					// Нет доступа к реестру — считаем, что LocalDB нет.
				}
			}
			return false;
		}

		/// <summary>
		/// Добавляет имя сервера в список без повторов.
		/// </summary>
		private static void AddUnique(List<string> servers, string server)
		{
			foreach (string existing in servers)
			{
				if (string.Equals(existing, server, StringComparison.OrdinalIgnoreCase))
				{
					return;
				}
			}
			servers.Add(server);
		}
	}
}
