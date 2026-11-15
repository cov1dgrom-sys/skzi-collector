using System;
using System.Collections.Generic;
using System.IO;
using System.Security;
using System.Threading;
using Skzi.Common.Configuration;

namespace Skzi.Common.Scanning
{
	/// <summary>
	/// Поиск файлов сертификатов в директориях из конфигурации. Поддерживает маски в пути
	/// (C:\Users\*\Desktop), рекурсивный обход, пропуск недоступных папок и символических ссылок.
	/// </summary>
	public static class DirectoryScanner
	{
		private const int MaxDirectoriesPerScan = 300000;

		/// <summary>
		/// Возвращает список файлов-кандидатов (по расширению и размеру) во всех директориях из параметров.
		/// Статистика (число просмотренных папок) записывается в result, проблемы — в result.Warnings.
		/// </summary>
		public static List<string> FindCertificateFiles(IScanTarget target, ScanOptions options, ScanResult result, CancellationToken cancellationToken)
		{
			List<string> foundFiles = new List<string>();
			HashSet<string> seenFiles = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
			HashSet<string> visitedDirectories = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
			result.ScannedFileExtensions = options.FileExtensionsText;

			foreach (ScanDirectoryEntry entry in options.Directories)
			{
				cancellationToken.ThrowIfCancellationRequested();
				if (entry == null || string.IsNullOrWhiteSpace(entry.Path))
				{
					continue;
				}

				string mappedPath = target.MapPath(entry.Path, result.Warnings);
				if (mappedPath == null)
				{
					continue;
				}

				List<string> rootDirectories = ExpandPathPattern(mappedPath);
				if (rootDirectories.Count == 0)
				{
					result.Warnings.Add("Директория не найдена: " + entry.Path);
					continue;
				}

				foreach (string rootDirectory in rootDirectories)
				{
					result.ScannedDirectories.Add(new ScanDirectoryEntry(target.ToTargetPath(rootDirectory), entry.Recursive));
					ScanDirectoryTree(rootDirectory, entry.Recursive, options, result, foundFiles, seenFiles, visitedDirectories, cancellationToken);
				}
			}
			return foundFiles;
		}

		/// <summary>
		/// Раскрывает маски «*» и «?» в сегментах пути и возвращает существующие директории.
		/// Пример: C:\Users\*\Desktop → C:\Users\ivanov\Desktop, C:\Users\petrova\Desktop.
		/// </summary>
		public static List<string> ExpandPathPattern(string pathPattern)
		{
			List<string> result = new List<string>();
			string root = Path.GetPathRoot(pathPattern);
			if (string.IsNullOrEmpty(root))
			{
				return result;
			}

			string relativePart = pathPattern.Substring(root.Length);
			string[] segments = relativePart.Split(new[] { '\\', '/' }, StringSplitOptions.RemoveEmptyEntries);
			List<string> currentLevel = new List<string>();
			currentLevel.Add(root);

			foreach (string segment in segments)
			{
				List<string> nextLevel = new List<string>();
				bool hasWildcard = segment.IndexOfAny(new[] { '*', '?' }) >= 0;
				foreach (string directory in currentLevel)
				{
					if (!hasWildcard)
					{
						nextLevel.Add(Path.Combine(directory, segment));
						continue;
					}
					try
					{
						nextLevel.AddRange(Directory.GetDirectories(directory, segment));
					}
					catch (Exception exception)
					{
						if (!IsExpectedFileSystemException(exception))
						{
							throw;
						}
					}
				}
				currentLevel = nextLevel;
				if (currentLevel.Count == 0)
				{
					break;
				}
			}

			foreach (string directory in currentLevel)
			{
				if (SafeDirectoryExists(directory))
				{
					result.Add(directory);
				}
			}
			return result;
		}

		/// <summary>
		/// Обходит дерево директорий (без рекурсии вызовов — через стек) и собирает подходящие файлы.
		/// </summary>
		private static void ScanDirectoryTree(string rootDirectory, bool recursive, ScanOptions options, ScanResult result,
			List<string> foundFiles, HashSet<string> seenFiles, HashSet<string> visitedDirectories, CancellationToken cancellationToken)
		{
			Stack<string> pendingDirectories = new Stack<string>();
			pendingDirectories.Push(rootDirectory);

			while (pendingDirectories.Count > 0)
			{
				cancellationToken.ThrowIfCancellationRequested();
				string directory = pendingDirectories.Pop();
				if (!visitedDirectories.Add(directory.TrimEnd('\\')))
				{
					continue;
				}
				if (visitedDirectories.Count > MaxDirectoriesPerScan)
				{
					result.Warnings.Add("Превышен лимит просматриваемых директорий (" + MaxDirectoriesPerScan + "), обход остановлен.");
					return;
				}
				result.DirectoriesScanned = result.DirectoriesScanned + 1;

				CollectMatchingFiles(directory, options, result, foundFiles, seenFiles);

				if (recursive)
				{
					foreach (string subdirectory in SafeGetSubdirectories(directory, result))
					{
						pendingDirectories.Push(subdirectory);
					}
				}
			}
		}

		/// <summary>
		/// Добавляет в список файлы директории с подходящим расширением и допустимым размером.
		/// </summary>
		private static void CollectMatchingFiles(string directory, ScanOptions options, ScanResult result, List<string> foundFiles, HashSet<string> seenFiles)
		{
			try
			{
				foreach (string filePath in Directory.EnumerateFiles(directory))
				{
					string extension = Path.GetExtension(filePath);
					if (string.IsNullOrEmpty(extension) || !options.FileExtensions.Contains(extension.ToLowerInvariant()))
					{
						continue;
					}
					FileInfo fileInfo = new FileInfo(filePath);
					if (fileInfo.Length == 0)
					{
						continue;
					}
					if (fileInfo.Length > options.MaxFileSizeBytes)
					{
						AddWarning(result, "Файл пропущен (превышен размер " + (options.MaxFileSizeBytes / 1024) + " КБ): " + filePath);
						continue;
					}
					if (seenFiles.Add(filePath))
					{
						foundFiles.Add(filePath);
					}
				}
			}
			catch (Exception exception)
			{
				if (!IsExpectedFileSystemException(exception))
				{
					throw;
				}
				AddWarning(result, "Нет доступа к файлам директории " + directory + ": " + exception.Message);
			}
		}

		/// <summary>
		/// Возвращает подкаталоги, пропуская символические ссылки/точки соединения (защита от циклов).
		/// </summary>
		private static List<string> SafeGetSubdirectories(string directory, ScanResult result)
		{
			List<string> subdirectories = new List<string>();
			try
			{
				foreach (string subdirectory in Directory.EnumerateDirectories(directory))
				{
					try
					{
						FileAttributes attributes = File.GetAttributes(subdirectory);
						if ((attributes & FileAttributes.ReparsePoint) != 0)
						{
							continue;
						}
					}
					catch (Exception exception)
					{
						if (!IsExpectedFileSystemException(exception))
						{
							throw;
						}
						continue;
					}
					subdirectories.Add(subdirectory);
				}
			}
			catch (Exception exception)
			{
				if (!IsExpectedFileSystemException(exception))
				{
					throw;
				}
				AddWarning(result, "Нет доступа к подкаталогам " + directory + ": " + exception.Message);
			}
			return subdirectories;
		}

		/// <summary>
		/// Проверяет существование директории без исключений.
		/// </summary>
		private static bool SafeDirectoryExists(string directory)
		{
			try
			{
				return Directory.Exists(directory);
			}
			catch (Exception)
			{
				return false;
			}
		}

		/// <summary>
		/// Ожидаемые ошибки файловой системы (нет доступа, путь не найден, длинный путь), которые не прерывают сканирование.
		/// </summary>
		public static bool IsExpectedFileSystemException(Exception exception)
		{
			return exception is UnauthorizedAccessException
				|| exception is IOException
				|| exception is SecurityException
				|| exception is ArgumentException
				|| exception is NotSupportedException;
		}

		/// <summary>
		/// Добавляет предупреждение, ограничивая их общее количество, чтобы результат не разрастался.
		/// </summary>
		public static void AddWarning(ScanResult result, string warning)
		{
			const int MaxWarnings = 300;
			if (result.Warnings.Count < MaxWarnings)
			{
				result.Warnings.Add(warning);
			}
			else if (result.Warnings.Count == MaxWarnings)
			{
				result.Warnings.Add("Слишком много предупреждений, остальные не показаны (см. журнал).");
			}
		}
	}
}
