using System;
using System.Collections.Generic;
using System.IO;
using Skzi.Common.Configuration;

namespace Skzi.Common.Scanning
{
	/// <summary>
	/// Описание мест, где найден сертификат («Файл: C:\...», «Личное хранилище ...», «Контейнер КриптоПро: ...»),
	/// и правило, по которому сертификат считается пропавшим: место входило в область сканирования, но сертификат там не найден.
	/// </summary>
	public static class CertificateSources
	{
		public const string FilePrefix = "Файл: ";
		public const string StorePrefix = "Личное хранилище";
		public const string ContainerPrefix = "Контейнер КриптоПро: ";

		/// <summary>
		/// Формирует описание источника «файл».
		/// </summary>
		public static string ForFile(string targetPath)
		{
			return FilePrefix + targetPath;
		}

		/// <summary>
		/// Формирует описание источника «ключевой контейнер КриптоПро».
		/// </summary>
		public static string ForContainer(string containerName)
		{
			return ContainerPrefix + containerName;
		}

		/// <summary>
		/// Проверяет, входило ли место в область этого сканирования ПК. Только такие места можно помечать
		/// как «сертификат пропал»: если папку в этот раз не просматривали, о судьбе файла в ней ничего не известно.
		/// </summary>
		public static bool IsCoveredByScan(string source, ScanResult result)
		{
			if (string.IsNullOrEmpty(source) || result == null)
			{
				return false;
			}
			if (source.StartsWith(FilePrefix, StringComparison.Ordinal))
			{
				return IsFileCovered(source.Substring(FilePrefix.Length), result);
			}
			if (source.StartsWith(StorePrefix, StringComparison.Ordinal))
			{
				return result.CertificateStoresScanned;
			}
			if (source.StartsWith(ContainerPrefix, StringComparison.Ordinal))
			{
				return result.CryptoProContainersScanned;
			}
			return false;
		}

		/// <summary>
		/// Файл входит в область сканирования, если искались файлы с его расширением и он лежит в просмотренной директории
		/// (с подпапками — где угодно внутри неё, без подпапок — непосредственно в ней).
		/// </summary>
		private static bool IsFileCovered(string filePath, ScanResult result)
		{
			if (!string.IsNullOrEmpty(result.ScannedFileExtensions))
			{
				HashSet<string> extensions = ScanOptions.ParseExtensions(result.ScannedFileExtensions);
				string extension = SafeGetExtension(filePath);
				if (string.IsNullOrEmpty(extension) || !extensions.Contains(extension.ToLowerInvariant()))
				{
					return false;
				}
			}
			string fileDirectory = SafeGetDirectoryName(filePath);
			if (fileDirectory == null)
			{
				return false;
			}
			foreach (ScanDirectoryEntry root in result.ScannedDirectories)
			{
				if (root == null || string.IsNullOrEmpty(root.Path))
				{
					continue;
				}
				string rootPath = root.Path.TrimEnd('\\');
				if (string.Equals(fileDirectory.TrimEnd('\\'), rootPath, StringComparison.OrdinalIgnoreCase))
				{
					return true;
				}
				if (root.Recursive && filePath.StartsWith(rootPath + "\\", StringComparison.OrdinalIgnoreCase))
				{
					return true;
				}
			}
			return false;
		}

		/// <summary>
		/// Расширение файла без исключений на недопустимых символах.
		/// </summary>
		private static string SafeGetExtension(string filePath)
		{
			try
			{
				return Path.GetExtension(filePath);
			}
			catch (ArgumentException)
			{
				return null;
			}
		}

		/// <summary>
		/// Папка файла без исключений на недопустимых символах.
		/// </summary>
		private static string SafeGetDirectoryName(string filePath)
		{
			try
			{
				return Path.GetDirectoryName(filePath);
			}
			catch (ArgumentException)
			{
				return null;
			}
			catch (PathTooLongException)
			{
				return null;
			}
		}
	}
}
