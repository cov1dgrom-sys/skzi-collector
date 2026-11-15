using System;
using System.Collections.Generic;
using System.Data.SqlClient;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using Skzi.Agent;
using Skzi.Common.Certificates;
using Skzi.Common.Configuration;
using Skzi.Common.Database;
using Skzi.Common.Logging;
using Skzi.Common.Network;
using Skzi.Common.Scanning;
using Skzi.ControlPanel;

namespace Skzi.Tests
{
	/// <summary>
	/// Автотесты модуля (без внешних фреймворков): запуск — bin\SkziTests.exe [путь к samples\certs].
	/// Тест MSSQL выполняется, если задана переменная окружения SKZI_TEST_SQL (строка подключения).
	/// </summary>
	public static class TestProgram
	{
		private static int passedCount;
		private static int failedCount;
		private static int skippedCount;
		private static string samplesDirectory;

		/// <summary>
		/// Запускает все тесты и возвращает 0, если ошибок нет.
		/// </summary>
		public static int Main(string[] args)
		{
			Console.OutputEncoding = Encoding.UTF8;
			string temporaryLogs = Path.Combine(Path.GetTempPath(), "SkziTests", "logs");
			Logger.Initialize("SkziTests", temporaryLogs, false);
			samplesDirectory = args.Length > 0 ? Path.GetFullPath(args[0]) : FindSamplesDirectory();
			Console.WriteLine("Тестовые сертификаты: " + samplesDirectory);
			Console.WriteLine();

			Run("Журнал: формат «дд.ММ.гг чч:мм:сс.мсс - [УРОВЕНЬ] текст» и запись исключений", TestLogFormat);
			Run("Журнал: ротация по размеру и удаление старых файлов", TestLogRotation);
			Run("ASN.1: декодирование OID и строк", TestAsn1);
			Run("Лицензия КриптоПро: версия по ключу и тексту, маскирование", TestLicenseVersionExtraction);
			Run("Загрузка файлов: DER, PEM-цепочка, Base64, PKCS#7, повреждённый файл", TestFileFormats);
			Run("Парсинг: владелец, ИНН, СНИЛС, ОГРН, УЦ, встроенная лицензия", TestCertificateParsing);
			Run("Файлы куратора: ФИО из CN, УЦ полностью, .p12 с паролем changeit и без пароля", TestCuratorSamples);
			Run("PKCS#12: чтение с паролем оператора, без пароля — понятная ошибка", TestPkcs12Passwords);
			Run("Пропавшие сертификаты: что входит в область сканирования", TestScanScopeRules);
			Run("Лицензия КриптоПро на ПК: срок действия", TestCryptoProLicenseValidity);
			Run("Контейнеры КриптоПро: без установленного CSP — пусто и без ошибок", TestContainerScannerWithoutCryptoPro);
			Run("Директории: маски C:\\Users\\*\\Desktop", TestPathPatterns);
			Run("Безагентный режим: пути \\\\ПК\\C$", TestRemotePathMapping);
			Run("Сканирование папки: дубли, статистика, предупреждения", TestCollectorOnSamples);
			Run("Конфигурация: запись/чтение XML без задвоения списков, пароль DPAPI", TestConfigRoundtrip);
			Run("Сериализация результата сканирования (кириллица, даты)", TestScanResultSerialization);
			Run("Протокол: Ping и Scan агента с верным ключом", TestAgentRoundtrip);
			Run("Протокол: агент ищет только в папках, указанных в панели", TestAgentUsesOnlyPanelDirectories);
			Run("Протокол: неверный ключ отклоняется", TestAgentWrongKey);
			Run("Протокол: поиск агента по приветствию", TestAgentProbe);
			Run("Агент: режим запуска по командной строке (без параметров — в фоне)", TestAgentCommandLine);
			Run("Установка агента: одинаковая служба локально и из панели (имя, скрытие от пользователей)", TestAgentServiceParametersMatch);
			RunBackgroundModeTest();
			Run("Имя таблицы: защита от SQL-инъекций", TestTableNameValidation);
			Run("Панель: диапазоны IP и определение локального ПК", TestPanelHelpers);
			RunDatabaseTests();

			Console.WriteLine();
			Console.ForegroundColor = failedCount == 0 ? ConsoleColor.Green : ConsoleColor.Red;
			Console.WriteLine("Итог: успешно " + passedCount + ", ошибок " + failedCount + ", пропущено " + skippedCount);
			Console.ResetColor();
			return failedCount == 0 ? 0 : 1;
		}

		/// <summary>
		/// Выполняет один тест и печатает результат.
		/// </summary>
		private static void Run(string name, Action test)
		{
			Stopwatch stopwatch = Stopwatch.StartNew();
			try
			{
				test();
				passedCount = passedCount + 1;
				Console.ForegroundColor = ConsoleColor.Green;
				Console.Write("  [OK]   ");
				Console.ResetColor();
				Console.WriteLine(name + " (" + stopwatch.ElapsedMilliseconds + " мс)");
			}
			catch (Exception exception)
			{
				failedCount = failedCount + 1;
				Console.ForegroundColor = ConsoleColor.Red;
				Console.Write("  [FAIL] ");
				Console.ResetColor();
				Console.WriteLine(name);
				Console.WriteLine("         " + exception.GetType().Name + ": " + exception.Message);
				if (!(exception is AssertionException))
				{
					Console.WriteLine(exception.StackTrace);
				}
			}
		}

		// ---------- Тесты ----------

		/// <summary>
		/// Проверяет формат строк журнала и запись стека исключения.
		/// </summary>
		private static void TestLogFormat()
		{
			string marker = "проверка журнала " + Guid.NewGuid().ToString("N");
			Logger.Info(marker);
			try
			{
				throw new InvalidOperationException("тестовое исключение");
			}
			catch (Exception exception)
			{
				Logger.Error("ошибка для теста", exception);
			}
			Logger.Warning("предупреждение для теста");
			string content = ReadShared(Logger.CurrentLogFilePath);
			Match match = Regex.Match(content, @"^(\d{2}\.\d{2}\.\d{2} \d{2}:\d{2}:\d{2}\.\d{3}) - \[INFO\] " + Regex.Escape(marker) + @"\r?$", RegexOptions.Multiline);
			Assert(match.Success, "строка журнала не соответствует формату");
			Assert(Regex.IsMatch(content, @" - \[ERROR\] ошибка для теста"), "нет строки ошибки с уровнем");
			Assert(Regex.IsMatch(content, @" - \[WARN\] предупреждение для теста"), "нет строки предупреждения с уровнем");
			Assert(content.Contains("System.InvalidOperationException: тестовое исключение"), "нет типа и текста исключения");
			Assert(content.Contains("Стек вызовов"), "нет стека вызовов");
			AssertEqual("16.09.25 08:43:23.739 - [INFO] Приложение запущено",
				Logger.FormatLine(new DateTime(2025, 9, 16, 8, 43, 23, 739), LogLevel.Info, "Приложение запущено"), "формат как в примере задания");
		}

		/// <summary>
		/// Проверяет ротацию журнала: при превышении размера начинается следующая часть, файлы старше срока удаляются.
		/// </summary>
		private static void TestLogRotation()
		{
			string directory = Path.Combine(Path.GetTempPath(), "SkziTests", "rotation_" + Guid.NewGuid().ToString("N").Substring(0, 8));
			Directory.CreateDirectory(directory);
			string oldFile = Path.Combine(directory, "SkziRotation_2020-01-01.log");
			string oldPartFile = Path.Combine(directory, "SkziRotation_2020-01-01_2.log");
			string otherAppFile = Path.Combine(directory, "Other_2020-01-01.log");
			File.WriteAllText(oldFile, "старый журнал");
			File.WriteAllText(oldPartFile, "старый журнал, часть 2");
			File.WriteAllText(otherAppFile, "чужой журнал");
			try
			{
				Logger.Initialize("SkziRotation", directory, false);
				Logger.ConfigureRotation(30, 1);
				// 1200 строк по ~1 КБ (латиница — 1 байт на символ) ≈ 1,2 МБ: должно получиться ровно две части по 1 МБ.
				string longText = new string('z', 1000);
				for (int index = 0; index < 1200; index++)
				{
					Logger.Info(longText);
				}
				string firstPart = Path.Combine(directory, "SkziRotation_" + DateTime.Today.ToString("yyyy-MM-dd") + ".log");
				string secondPart = Path.Combine(directory, "SkziRotation_" + DateTime.Today.ToString("yyyy-MM-dd") + "_2.log");
				Assert(File.Exists(firstPart), "первая часть журнала");
				Assert(File.Exists(secondPart), "при превышении 1 МБ начата вторая часть");
				Assert(new FileInfo(firstPart).Length < 2 * 1024 * 1024, "первая часть не растёт бесконечно");
				AssertEqual(secondPart, Logger.CurrentLogFilePath, "текущий файл — вторая часть");
				Assert(!File.Exists(oldFile) && !File.Exists(oldPartFile), "журналы старше 30 суток удалены");
				Assert(File.Exists(otherAppFile), "журналы другого приложения не трогаются");
				DateTime parsedDate;
				Assert(Logger.TryGetLogFileDate("SkziRotation_2026-11-13_3", out parsedDate) && parsedDate == new DateTime(2026, 11, 13), "дата из имени части журнала");
			}
			finally
			{
				Logger.Initialize("SkziTests", Path.Combine(Path.GetTempPath(), "SkziTests", "logs"), false);
				Logger.ConfigureRotation(Logger.DefaultRetentionDays, Logger.DefaultMaxFileSizeMb);
				Directory.Delete(directory, true);
			}
		}

		/// <summary>
		/// Проверяет разбор OID и строковых типов ASN.1.
		/// </summary>
		private static void TestAsn1()
		{
			// OID 1.2.643.100.3 (СНИЛС) в DER: 06 05 2A 85 03 64 03
			byte[] oidBytes = { 0x06, 0x05, 0x2A, 0x85, 0x03, 0x64, 0x03 };
			Asn1Node oid = Asn1Node.Parse(oidBytes);
			AssertEqual("1.2.643.100.3", oid.ReadObjectIdentifier(), "OID СНИЛС");

			byte[] utf8 = Encoding.UTF8.GetBytes("Иванов");
			byte[] utf8Node = new byte[2 + utf8.Length];
			utf8Node[0] = 0x0C;
			utf8Node[1] = (byte)utf8.Length;
			Buffer.BlockCopy(utf8, 0, utf8Node, 2, utf8.Length);
			AssertEqual("Иванов", Asn1Node.Parse(utf8Node).ReadString(), "UTF8String");

			Assert(Asn1Node.TryParseExact(new byte[] { 0x30, 0x05, 0x01 }) == null, "обрезанные данные должны отклоняться");
		}

		/// <summary>
		/// Проверяет определение версии лицензии и маскирование ключей.
		/// </summary>
		private static void TestLicenseVersionExtraction()
		{
			AssertEqual("5.0", CertificateParser.ExtractCryptoProVersion(new[] { "50500-ABCDE-12345-FGHIJ-67890" }), "ключ 5050…");
			AssertEqual("4.0", CertificateParser.ExtractCryptoProVersion(new[] { "КриптоПро", "40400-QWERT-00000-00000-00001" }), "ключ 4040…");
			AssertEqual("5.0", CertificateParser.ExtractCryptoProVersion(new[] { "Лицензия КриптоПро CSP 5.0 на рабочее место" }), "текст CSP 5.0");
			AssertEqual("4.0", CertificateParser.ExtractCryptoProVersion(new[] { "Crypto-Pro license v4.0" }), "Crypto-Pro … 4.0");
			Assert(CertificateParser.ExtractCryptoProVersion(new[] { "Документ 3.1 от 2020 года" }) == null, "без упоминания КриптоПро версия не должна определяться");
			string masked = CertificateParser.MaskLicenseKeys("ключ 50500-ABCDE-12345-FGHIJ-67890.");
			AssertEqual("ключ 50500-*****-*****-*****-67890.", masked, "маскирование ключа");
			AssertEqual("40400-*****-*****-*****-ZZZZZ", CryptoProDetector.MaskSerial("40400-AAAAA-BBBBB-CCCCC-ZZZZZ"), "маскирование серийного номера CSP");
		}

		/// <summary>
		/// Проверяет загрузку сертификатов из файлов разных форматов.
		/// </summary>
		private static void TestFileFormats()
		{
			AssertEqual(1, CertificateFileLoader.LoadFromFile(SamplePath("ivanov_ii.cer")).Count, "DER");
			AssertEqual(2, CertificateFileLoader.LoadFromFile(SamplePath("romashka_chain.pem")).Count, "PEM-цепочка");
			AssertEqual(1, CertificateFileLoader.LoadFromFile(SamplePath("sidorov_po_base64.cer")).Count, "Base64 без заголовков");
			AssertEqual(2, CertificateFileLoader.LoadFromFile(SamplePath("bundle.p7b")).Count, "PKCS#7");
			AssertEqual(1, CertificateFileLoader.LoadFromFile(SamplePath(Path.Combine("Отдел кадров", "petrova_as.crt"))).Count, "PEM в папке с кириллицей");
			bool brokenRejected = false;
			try
			{
				CertificateFileLoader.LoadFromFile(SamplePath("broken.cer"));
			}
			catch (Exception)
			{
				brokenRejected = true;
			}
			Assert(brokenRejected, "повреждённый файл должен вызывать исключение");
		}

		/// <summary>
		/// Проверяет извлечение полей из тестовых сертификатов.
		/// </summary>
		private static void TestCertificateParsing()
		{
			CertificateRecord ivanov = CertificateParser.Parse(CertificateFileLoader.LoadFromFile(SamplePath("ivanov_ii.cer"))[0]);
			AssertEqual("Иванов Иван Иванович", ivanov.OwnerName, "имя владельца (SN + G)");
			AssertEqual("667012345678", ivanov.OwnerInn, "ИНН ФЛ");
			AssertEqual("12345678901", ivanov.OwnerSnils, "СНИЛС");
			AssertEqual("Генеральный директор", ivanov.OwnerTitle, "должность");
			Assert(ivanov.CertificationAuthority.StartsWith("CN=Тестовый УЦ Red Flag, ", StringComparison.Ordinal), "удостоверяющий центр — полное имя: " + ivanov.CertificationAuthority);
			AssertEqual(ivanov.IssuerDn, ivanov.CertificationAuthority, "УЦ совпадает с полным именем издателя");
			Assert(ivanov.HasEmbeddedCryptoProLicense, "у Иванова должна быть встроенная лицензия");
			AssertEqual("5.0", ivanov.CryptoProLicenseVersion, "версия встроенной лицензии");
			Assert(ivanov.CryptoProLicenseDetails.Contains("*****"), "ключ лицензии в подробностях должен быть замаскирован");
			Assert(Regex.IsMatch(ivanov.SerialNumber, "^[0-9A-F]+$"), "серийный номер должен быть HEX");
			Assert(ivanov.SubjectDn.StartsWith("E=", StringComparison.Ordinal) || ivanov.SubjectDn.Contains("CN=Иванов Иван Иванович"), "DN субъекта");

			CertificateRecord romashka = CertificateParser.Parse(CertificateFileLoader.LoadFromFile(SamplePath("romashka_chain.pem"))[0]);
			AssertEqual("6670000123", romashka.OwnerInn, "ИНН ЮЛ");
			AssertEqual("1166600000123", romashka.OwnerOgrn, "ОГРН");
			AssertEqual("4.0", romashka.CryptoProLicenseVersion, "версия лицензии 4.0");

			CertificateRecord sidorov = CertificateParser.Parse(CertificateFileLoader.LoadFromFile(SamplePath("sidorov_po_base64.cer"))[0]);
			Assert(sidorov.HasEmbeddedCryptoProLicense, "у Сидорова лицензия есть");
			AssertEqual(CertificateParser.UnknownLicenseVersion, sidorov.CryptoProLicenseVersion, "версия неизвестна");

			CertificateRecord petrova = CertificateParser.Parse(CertificateFileLoader.LoadFromFile(SamplePath(Path.Combine("Отдел кадров", "petrova_as.crt")))[0]);
			Assert(!petrova.HasEmbeddedCryptoProLicense, "у Петровой лицензии нет");
			Assert(petrova.CryptoProLicenseVersion == null, "без лицензии версия пустая");

			CertificateRecord kuznetsova = CertificateParser.Parse(CertificateFileLoader.LoadFromFile(SamplePath(Path.Combine("archive", "2024", "kuznetsova_mp.cer")))[0]);
			Assert(kuznetsova.IsExpired, "сертификат Кузнецовой истёк");
		}

		/// <summary>
		/// Проверяет, что установка агента из панели по сети регистрирует службу так же, как локальная установка:
		/// то же имя и тот же дескриптор безопасности, скрывающий службу от обычных пользователей.
		/// </summary>
		private static void TestAgentServiceParametersMatch()
		{
			AssertEqual(ServiceSetup.ServiceName, AgentDeployer.ServiceName, "имя службы");
			AssertEqual(ServiceSetup.RestrictedServiceSecurity, AgentDeployer.ServiceSecurityDescriptor, "дескриптор безопасности службы");
			Assert(!ServiceSetup.RestrictedServiceSecurity.Contains(";;;IU)") && !ServiceSetup.RestrictedServiceSecurity.Contains(";;;AU)")
				&& !ServiceSetup.RestrictedServiceSecurity.Contains(";;;BU)"), "у обычных пользователей нет доступа к службе");
			Assert(ServiceSetup.RestrictedServiceSecurity.Contains(";;;SY)") && ServiceSetup.RestrictedServiceSecurity.Contains(";;;BA)"),
				"система и администраторы управляют службой");
			Assert(ServiceSetup.RestrictedServiceSecurity.Contains("S:(AU;FA;"), "обращения к службе пишутся в аудит");
		}

		/// <summary>
		/// Проверяет сертификаты, присланные куратором: ФИО в CN, полный УЦ, защищённые паролем .p12.
		/// </summary>
		private static void TestCuratorSamples()
		{
			string curatorDirectory = Path.Combine(Path.GetDirectoryName(samplesDirectory), "curator");
			Assert(Directory.Exists(curatorDirectory), "нет папки samples\\curator");
			CertificateRecord ivanov = CertificateParser.Parse(CertificateFileLoader.LoadFromFile(Path.Combine(curatorDirectory, "Ivanov_Ivan_Ivanovich.cer"))[0]);
			AssertEqual("Иванов Иван Иванович", ivanov.OwnerName, "ФИО владельца из CN");
			AssertEqual("03A14016", ivanov.SerialNumber, "серийный номер");
			AssertEqual("CN=Иванов Иван Иванович, OU=Dev, O=MyCompany, L=Moscow, C=RU", ivanov.CertificationAuthority, "УЦ полностью");
			AssertEqual("MyCompany", ivanov.OwnerOrganization, "организация");
			Assert(!ivanov.HasEmbeddedCryptoProLicense, "лицензии КриптоПро в сертификате нет");

			CertificateRecord petrov = CertificateParser.Parse(CertificateFileLoader.LoadFromFile(Path.Combine(curatorDirectory, "Petrov_Petr_Petrovich.cer"))[0]);
			AssertEqual("Петров Петр Петрович", petrov.OwnerName, "ФИО Петрова");
			AssertEqual("378F0E85", petrov.SerialNumber, "серийный номер Петрова");

			bool protectedDetected = false;
			try
			{
				CertificateFileLoader.LoadFromFile(Path.Combine(curatorDirectory, "Ivanov_Ivan_Ivanovich.p12"));
			}
			catch (PasswordProtectedFileException)
			{
				protectedDetected = true;
			}
			Assert(protectedDetected, ".p12 без пароля должен давать PasswordProtectedFileException");

			ScanOptions options = new ScanOptions();
			options.ScanCertificateStores = false;
			options.ScanCryptoProContainers = false;
			options.Directories.Add(new ScanDirectoryEntry(curatorDirectory, true));
			ScanResult result = CertificateCollector.Scan(new LocalScanTarget(), options, CertificateCollector.ModeLocal, CancellationToken.None);
			AssertEqual(2, result.Certificates.Count, "сертификатов в папке куратора (из .cer)");
			AssertEqual(2, result.FilesFailed, "два .p12 не прочитаны без пароля");
			Assert(result.Warnings.Exists(delegate (string warning) { return warning.Contains("защищён паролем"); }), "понятное предупреждение о пароле");

			// Пароль к .p12 кураторов — "changeit" (сообщён оператором). С ним оба контейнера читаются,
			// причём с привязкой к закрытому ключу; дубли с .cer объединяются по отпечатку.
			List<X509Certificate2> ivanovFromP12 = CertificateFileLoader.LoadFromFile(
				Path.Combine(curatorDirectory, "Ivanov_Ivan_Ivanovich.p12"), new List<string> { "changeit" });
			try
			{
				CertificateRecord ivanovRecord = CertificateParser.Parse(ivanovFromP12[0]);
				AssertEqual("Иванов Иван Иванович", ivanovRecord.OwnerName, "владелец из .p12 куратора");
				AssertEqual("03A14016", ivanovRecord.SerialNumber, "серийный номер из .p12 совпадает с .cer");
				Assert(ivanovRecord.HasPrivateKey, "в .p12 куратора есть закрытый ключ");
			}
			finally
			{
				foreach (X509Certificate2 certificate in ivanovFromP12) { certificate.Reset(); }
			}

			ScanOptions withPassword = new ScanOptions();
			withPassword.ScanCertificateStores = false;
			withPassword.ScanCryptoProContainers = false;
			withPassword.Directories.Add(new ScanDirectoryEntry(curatorDirectory, true));
			withPassword.Pkcs12Passwords.Add("changeit");
			ScanResult withPasswordResult = CertificateCollector.Scan(new LocalScanTarget(), withPassword, CertificateCollector.ModeLocal, CancellationToken.None);
			AssertEqual(2, withPasswordResult.Certificates.Count, "с паролем .cer и .p12 одного лица объединяются в 2 записи");
			AssertEqual(0, withPasswordResult.FilesFailed, "с паролем непрочитанных файлов нет");
			Assert(withPasswordResult.Certificates.TrueForAll(delegate (CertificateRecord record) { return record.HasPrivateKey; }),
				"с паролем у обеих записей проставлен закрытый ключ (из .p12)");
		}

		/// <summary>
		/// Проверяет чтение PKCS#12 с паролем, заданным оператором.
		/// </summary>
		private static void TestPkcs12Passwords()
		{
			string p12Path = Path.Combine(Path.GetDirectoryName(samplesDirectory), "pkcs12", "testov_tt.p12");
			Assert(File.Exists(p12Path), "нет samples\\pkcs12\\testov_tt.p12");
			Assert(CertificateFileLoader.IsPkcs12(File.ReadAllBytes(p12Path)), "файл распознан как PKCS#12");
			Assert(!CertificateFileLoader.IsPkcs12(File.ReadAllBytes(SamplePath("ivanov_ii.cer"))), "DER-сертификат — не PKCS#12");

			bool protectedDetected = false;
			try
			{
				CertificateFileLoader.LoadFromFile(p12Path, new List<string> { "неверный" });
			}
			catch (PasswordProtectedFileException exception)
			{
				protectedDetected = exception.Message.Contains("ни один из заданных паролей");
			}
			Assert(protectedDetected, "неверный пароль — понятная ошибка");

			List<X509Certificate2> certificates = CertificateFileLoader.LoadFromFile(p12Path, new List<string> { "неверный", "RedFlag-2026" });
			try
			{
				AssertEqual(1, certificates.Count, "сертификатов в .p12");
				CertificateRecord record = CertificateParser.Parse(certificates[0]);
				AssertEqual("Тестов Тест Тестович", record.OwnerName, "владелец из .p12");
				AssertEqual("07E57001", record.SerialNumber, "серийный номер из .p12");
				Assert(record.HasPrivateKey, "в .p12 есть закрытый ключ");
			}
			finally
			{
				foreach (X509Certificate2 certificate in certificates)
				{
					certificate.Reset();
				}
			}

			PanelConfig config = new PanelConfig();
			config.SetPfxPasswords(new[] { "RedFlag-2026", "второй пароль", "RedFlag-2026" });
			string xml = XmlMessageSerializer.Serialize(config);
			Assert(!xml.Contains("RedFlag-2026"), "пароли PKCS#12 не хранятся открытым текстом");
			PanelConfig restored = XmlMessageSerializer.Deserialize<PanelConfig>(xml);
			AssertEqual(2, restored.GetPfxPasswords().Count, "пароли PKCS#12 после DPAPI (без повторов)");
			AssertEqual(2, ScanOptions.FromPanelConfig(restored).Pkcs12Passwords.Count, "пароли попадают в параметры сканирования");
		}

		/// <summary>
		/// Проверяет правило «место входило в область сканирования» для пометки пропавших сертификатов.
		/// </summary>
		private static void TestScanScopeRules()
		{
			ScanResult result = new ScanResult();
			result.ScannedDirectories.Add(new ScanDirectoryEntry(@"C:\Certs", true));
			result.ScannedDirectories.Add(new ScanDirectoryEntry(@"D:\Ключи", false));
			result.ScannedFileExtensions = ".cer;.crt";
			result.CertificateStoresScanned = true;
			result.CryptoProContainersScanned = false;

			Assert(CertificateSources.IsCoveredByScan(@"Файл: C:\Certs\a.cer", result), "файл в корне папки");
			Assert(CertificateSources.IsCoveredByScan(@"Файл: c:\certs\2026\Отдел\b.CRT", result), "файл в подпапке (рекурсивно, без учёта регистра)");
			Assert(!CertificateSources.IsCoveredByScan(@"Файл: C:\Certs\a.p7b", result), "расширение не искалось");
			Assert(!CertificateSources.IsCoveredByScan(@"Файл: C:\CertsOld\a.cer", result), "похожее имя папки — не та папка");
			Assert(CertificateSources.IsCoveredByScan(@"Файл: D:\Ключи\c.cer", result), "файл в папке без подпапок");
			Assert(!CertificateSources.IsCoveredByScan(@"Файл: D:\Ключи\Архив\c.cer", result), "подпапка не просматривалась");
			Assert(!CertificateSources.IsCoveredByScan(@"Файл: E:\Другое\c.cer", result), "папка не просматривалась");
			Assert(CertificateSources.IsCoveredByScan("Личное хранилище пользователя PC\\ivanov", result), "хранилища просматривались");
			Assert(!CertificateSources.IsCoveredByScan(CertificateSources.ForContainer(@"\\.\REGISTRY\ivanov"), result), "контейнеры не просматривались");
			Assert(!CertificateSources.IsCoveredByScan("Неизвестный источник", result), "неизвестный источник не помечается");
		}

		/// <summary>
		/// Проверяет определение срока действия лицензии КриптоПро CSP на ПК.
		/// </summary>
		private static void TestCryptoProLicenseValidity()
		{
			AssertEqual("бессрочная", CryptoProDetector.ParseLicenseValidity("Серийный номер: 5050X-*****-*****-*****-XXXXX\nСрок действия: Постоянная\nТип лицензии: Клиентская"), "постоянная");
			AssertEqual("бессрочная", CryptoProDetector.ParseLicenseValidity("License validity: Permanent"), "permanent");
			AssertEqual("до 31.12.2026", CryptoProDetector.ParseLicenseValidity("Лицензия истекает: 31.12.2026"), "дата окончания");
			AssertEqual("до 01.03.2027", CryptoProDetector.ParseLicenseValidity("Expires: 01/03/2027"), "дата окончания (англ.)");
			string remaining = CryptoProDetector.ParseLicenseValidity("Expires: 2 month(s) 15 day(s)");
			Assert(remaining != null && remaining.StartsWith("осталось 2 мес. 15 дн.", StringComparison.Ordinal), "оставшийся срок: " + remaining);
			AssertEqual("истекла", CryptoProDetector.ParseLicenseValidity("License expired"), "истекла");
			Assert(CryptoProDetector.ParseLicenseValidity("Текст без сведений о сроке") == null, "нет сведений — null");

			AssertEqual("01.10.2026", CryptoProDetector.FormatInstallDate("20261001"), "дата установки из реестра");
			Assert(CryptoProDetector.FormatInstallDate("2026-10") == null, "некорректная дата установки");

			CryptoProInfo trial = new CryptoProInfo();
			trial.IsInstalled = true;
			trial.InstallDate = "01.10.2026";
			string trialText = CryptoProDetector.EstimateLicenseValidity(trial, true, new DateTime(2026, 11, 13));
			Assert(trialText.Contains("пробный период") && trialText.Contains("до 30.12.2026"), "пробный период 90 дней: " + trialText);
			string expiredTrial = CryptoProDetector.EstimateLicenseValidity(trial, true, new DateTime(2027, 2, 1));
			Assert(expiredTrial.Contains("истёк 30.12.2026"), "пробный период истёк: " + expiredTrial);

			CryptoProInfo licensed = new CryptoProInfo();
			licensed.IsInstalled = true;
			licensed.LicenseSerialMasked = "50500-*****-*****-*****-ZZZZZ";
			Assert(CryptoProDetector.EstimateLicenseValidity(licensed, false, DateTime.Today).Contains("через агент"), "без агента срок не определяется");
		}

		/// <summary>
		/// На ПК без КриптоПро перечисление контейнеров ничего не находит и не пишет ошибок.
		/// </summary>
		private static void TestContainerScannerWithoutCryptoPro()
		{
			byte[] buffer = Encoding.Default.GetBytes("\\\\.\\REGISTRY\\test-container\0мусор");
			AssertEqual("\\\\.\\REGISTRY\\test-container", CryptoProContainerScanner.DecodeContainerName(buffer, buffer.Length), "имя контейнера до нулевого символа");
			if (CryptoProContainerScanner.FindCryptoProProviders().Count > 0)
			{
				Console.WriteLine("         (на этом ПК установлен КриптоПро — проверка «без CSP» пропущена)");
				return;
			}
			List<string> warnings = new List<string>();
			AssertEqual(0, CryptoProContainerScanner.CollectCertificates(warnings).Count, "контейнеров нет");
			AssertEqual(0, warnings.Count, "без предупреждений");
		}

		/// <summary>
		/// Проверяет раскрытие масок в путях директорий.
		/// </summary>
		private static void TestPathPatterns()
		{
			string root = Path.Combine(Path.GetTempPath(), "SkziTests", "paths_" + Guid.NewGuid().ToString("N").Substring(0, 8));
			Directory.CreateDirectory(Path.Combine(root, @"Users\ivanov\Desktop"));
			Directory.CreateDirectory(Path.Combine(root, @"Users\petrova\Desktop"));
			Directory.CreateDirectory(Path.Combine(root, @"Users\guest"));
			try
			{
				List<string> expanded = DirectoryScanner.ExpandPathPattern(Path.Combine(root, @"Users\*\Desktop"));
				AssertEqual(2, expanded.Count, "две папки Desktop");
				AssertEqual(1, DirectoryScanner.ExpandPathPattern(Path.Combine(root, @"Users\iv*\Desktop")).Count, "маска iv*");
				AssertEqual(0, DirectoryScanner.ExpandPathPattern(Path.Combine(root, @"Нет\*\Desktop")).Count, "несуществующий путь");
			}
			finally
			{
				Directory.Delete(root, true);
			}
		}

		/// <summary>
		/// Проверяет преобразование путей для безагентного режима.
		/// </summary>
		private static void TestRemotePathMapping()
		{
			RemoteAdminShareTarget target = new RemoteAdminShareTarget("PC-042");
			List<string> warnings = new List<string>();
			AssertEqual(@"\\PC-042\C$\Certs", target.MapPath(@"C:\Certs", warnings), "C:\\Certs");
			AssertEqual(@"\\PC-042\D$\Ключи\2026", target.MapPath(@"d:\Ключи\2026", warnings), "D:\\Ключи");
			AssertEqual(@"\\PC-042\C$\Users\*\Desktop", target.MapPath(@"%SystemDrive%\Users\*\Desktop", warnings), "%SystemDrive%");
			Assert(target.MapPath(@"%USERPROFILE%\Desktop", warnings) == null, "%USERPROFILE% нельзя раскрыть удалённо");
			Assert(warnings.Count == 1, "должно быть одно предупреждение");
			AssertEqual(@"C:\Certs\a.cer", target.ToTargetPath(@"\\PC-042\C$\Certs\a.cer"), "обратное преобразование пути");
			AssertEqual(@"D:\", target.ToTargetPath(@"\\pc-042\d$"), "корень диска");
			AssertEqual(@"\\OTHER\C$\x.cer", target.ToTargetPath(@"\\OTHER\C$\x.cer"), "чужой ПК не преобразуется");
			AssertEqual(@"C:\x.cer", new LocalScanTarget().ToTargetPath(@"C:\x.cer"), "локальный путь без изменений");
		}

		/// <summary>
		/// Проверяет полное сканирование папки с тестовыми сертификатами.
		/// </summary>
		private static void TestCollectorOnSamples()
		{
			ScanOptions options = new ScanOptions();
			options.ScanCertificateStores = false;
			options.Directories.Add(new ScanDirectoryEntry(samplesDirectory, true));
			options.Directories.Add(new ScanDirectoryEntry(samplesDirectory.ToUpperInvariant() + "\\", true));
			options.Directories.Add(new ScanDirectoryEntry(@"C:\НесуществующаяПапка_" + Guid.NewGuid().ToString("N"), true));
			ScanResult result = CertificateCollector.Scan(new LocalScanTarget(), options, CertificateCollector.ModeLocal, CancellationToken.None);

			AssertEqual(6, result.Certificates.Count, "уникальных сертификатов");
			AssertEqual(8, result.FilesScanned, "файлов-кандидатов (readme.txt не учитывается, повторная папка не сканируется)");
			AssertEqual(1, result.FilesFailed, "повреждённых файлов");
			Assert(result.ScannedDirectories.Exists(delegate (ScanDirectoryEntry entry) { return string.Equals(entry.Path, samplesDirectory, StringComparison.OrdinalIgnoreCase); }),
				"просмотренная папка записана в результат");
			Assert(result.ScannedFileExtensions.Contains(".p12"), "расширения по умолчанию включают .p12");
			Assert(result.CertificateStoresScanned == false, "хранилища не просматривались");
			Assert(result.Warnings.Exists(delegate (string warning) { return warning.StartsWith("Директория не найдена", StringComparison.Ordinal); }), "предупреждение о несуществующей папке");

			CertificateRecord ivanov = result.Certificates.Find(delegate (CertificateRecord record) { return record.OwnerName == "Иванов Иван Иванович"; });
			Assert(ivanov != null, "Иванов найден");
			AssertEqual(2, ivanov.Sources.Count, "Иванов найден в двух файлах (ivanov_ii.cer и bundle.p7b)");

			HashSet<string> serials = new HashSet<string>();
			foreach (CertificateRecord record in result.Certificates)
			{
				Assert(serials.Add(record.SerialNumber), "дубль серийного номера " + record.SerialNumber);
			}
		}

		/// <summary>
		/// Проверяет сохранение и чтение конфигурации.
		/// </summary>
		private static void TestConfigRoundtrip()
		{
			string path = Path.Combine(Path.GetTempPath(), "SkziTests", "panel_" + Guid.NewGuid().ToString("N") + ".xml");
			PanelConfig original = PanelConfig.CreateDefault();
			original.Database.SetPassword("Пароль-123");
			ConfigFile.Save(path, original);
			PanelConfig loaded = ConfigFile.Load<PanelConfig>(path);
			AssertEqual(original.ScanDirectories.Count, loaded.ScanDirectories.Count, "директорий после чтения (без задвоения)");
			AssertEqual(original.Hosts.Count, loaded.Hosts.Count, "ПК после чтения");
			AssertEqual("Пароль-123", loaded.Database.GetPassword(), "пароль после DPAPI");
			Assert(!ReadShared(path).Contains("Пароль-123"), "пароль не должен храниться открытым текстом");

			string agentPath = Path.Combine(Path.GetTempPath(), "SkziTests", "agent_" + Guid.NewGuid().ToString("N") + ".xml");
			File.WriteAllText(agentPath, "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<AgentConfig>\n\t<!-- комментарий -->\n\t<ListenPort>51000</ListenPort>\n\t<ScanDirectories>\n\t\t<Directory Recursive=\"false\">C:\\Ключи</Directory>\n\t</ScanDirectories>\n</AgentConfig>", Encoding.UTF8);
			AgentConfig agentConfig = ConfigFile.Load<AgentConfig>(agentPath);
			AssertEqual(51000, agentConfig.ListenPort, "порт агента");
			AssertEqual(1, agentConfig.ScanDirectories.Count, "директорий агента");
			Assert(!agentConfig.ScanDirectories[0].Recursive, "Recursive=false");
			AssertEqual(@"C:\Ключи", agentConfig.ScanDirectories[0].Path, "путь с кириллицей");
			File.Delete(path);
			File.Delete(agentPath);
		}

		/// <summary>
		/// Проверяет XML-сериализацию результата сканирования.
		/// </summary>
		private static void TestScanResultSerialization()
		{
			ScanResult result = new ScanResult();
			result.ComputerName = "ПК-БУХГАЛТЕРИЯ";
			result.StartedAt = new DateTime(2026, 11, 13, 10, 20, 30, 456);
			CertificateRecord record = new CertificateRecord();
			record.SerialNumber = "00ABCDEF";
			record.OwnerName = "Иванов \"И.И.\" <тест> & Ко";
			record.HasEmbeddedCryptoProLicense = true;
			record.CryptoProLicenseVersion = "5.0";
			record.Sources.Add(@"Файл: C:\Ключи\a.cer");
			result.Certificates.Add(record);
			result.CryptoPro.IsInstalled = true;
			result.CryptoPro.Version = "5.0.12000";

			ScanResult restored = XmlMessageSerializer.Deserialize<ScanResult>(XmlMessageSerializer.Serialize(result));
			AssertEqual("ПК-БУХГАЛТЕРИЯ", restored.ComputerName, "имя ПК");
			AssertEqual(record.OwnerName, restored.Certificates[0].OwnerName, "спецсимволы и кириллица");
			AssertEqual(1, restored.Certificates[0].Sources.Count, "источники");
			AssertEqual(456, restored.StartedAt.Millisecond, "миллисекунды даты");
			AssertEqual("5.0.12000", restored.CryptoPro.Version, "версия КриптоПро");
		}

		/// <summary>
		/// Поднимает агент на свободном порту и проверяет команды Ping и Scan.
		/// </summary>
		private static void TestAgentRoundtrip()
		{
			AgentServer server = StartTestAgent("unit-test-key-1");
			try
			{
				AgentRequest ping = new AgentRequest();
				ping.Command = AgentRequest.CommandPing;
				AgentResponse pingResponse = AgentClient.SendRequestAsync("127.0.0.1", server.ListeningPort, "unit-test-key-1", ping, 10000, CancellationToken.None).Result;
				Assert(pingResponse.Success, "Ping успешен");
				AssertEqual(Environment.MachineName, pingResponse.ComputerName, "имя ПК агента");

				AgentRequest scan = new AgentRequest();
				scan.ExtraDirectories.Add(new ScanDirectoryEntry(samplesDirectory, true));
				AgentResponse scanResponse = AgentClient.SendRequestAsync("127.0.0.1", server.ListeningPort, "unit-test-key-1", scan, 60000, CancellationToken.None).Result;
				Assert(scanResponse.Success, "Scan успешен: " + scanResponse.ErrorMessage);
				AssertEqual(6, scanResponse.Result.Certificates.Count, "сертификатов от агента");
				AssertEqual(CertificateCollector.ModeAgent, scanResponse.Result.ScanMode, "режим Agent");
			}
			finally
			{
				server.Stop();
			}
		}

		/// <summary>
		/// Если панель просит искать только в своих папках, папки из конфигурации агента не используются.
		/// </summary>
		private static void TestAgentUsesOnlyPanelDirectories()
		{
			string agentOnlyDirectory = @"C:\ПапкаАгента_" + Guid.NewGuid().ToString("N");
			AgentConfig config = new AgentConfig();
			config.ListenPort = 0;
			config.SharedKey = "only-panel-dirs-key";
			config.ScanCertificateStores = false;
			config.ScanCryptoProContainers = false;
			config.AcceptDirectoriesFromPanel = true;
			config.ScanDirectories.Add(new ScanDirectoryEntry(agentOnlyDirectory, true));
			AgentServer server = new AgentServer(config);
			server.Start();
			try
			{
				AgentRequest merged = new AgentRequest();
				merged.ExtraDirectories.Add(new ScanDirectoryEntry(samplesDirectory, true));
				AgentResponse mergedResponse = AgentClient.SendRequestAsync("127.0.0.1", server.ListeningPort, config.SharedKey, merged, 60000, CancellationToken.None).Result;
				Assert(mergedResponse.Result.Warnings.Exists(delegate (string warning) { return warning.Contains(agentOnlyDirectory); }), "без флага используется и папка агента");

				AgentRequest onlyPanel = new AgentRequest();
				onlyPanel.UseOnlyRequestedDirectories = true;
				onlyPanel.ExtraDirectories.Add(new ScanDirectoryEntry(samplesDirectory, true));
				AgentResponse onlyPanelResponse = AgentClient.SendRequestAsync("127.0.0.1", server.ListeningPort, config.SharedKey, onlyPanel, 60000, CancellationToken.None).Result;
				Assert(onlyPanelResponse.Success, "Scan успешен");
				Assert(!onlyPanelResponse.Result.Warnings.Exists(delegate (string warning) { return warning.Contains(agentOnlyDirectory); }), "папка агента не просматривалась");
				AssertEqual(1, onlyPanelResponse.Result.ScannedDirectories.Count, "просмотрена только папка из панели");
				AssertEqual(6, onlyPanelResponse.Result.Certificates.Count, "сертификатов из папки панели");
			}
			finally
			{
				server.Stop();
			}
		}

		/// <summary>
		/// Проверяет, что агент отклоняет запрос с неверным ключом.
		/// </summary>
		private static void TestAgentWrongKey()
		{
			AgentServer server = StartTestAgent("correct-key-123");
			try
			{
				AgentRequest ping = new AgentRequest();
				ping.Command = AgentRequest.CommandPing;
				bool rejected = false;
				try
				{
					AgentClient.SendRequestAsync("127.0.0.1", server.ListeningPort, "wrong-key-456", ping, 10000, CancellationToken.None).Wait();
				}
				catch (AggregateException exception)
				{
					rejected = exception.InnerException is UnauthorizedAccessException;
				}
				Assert(rejected, "запрос с неверным ключом должен отклоняться с UnauthorizedAccessException");
			}
			finally
			{
				server.Stop();
			}
		}

		/// <summary>
		/// Проверяет обнаружение агента по приветствию и отсутствие ответа на закрытом порту.
		/// </summary>
		private static void TestAgentProbe()
		{
			AgentServer server = StartTestAgent("probe-key-123");
			try
			{
				AgentHello hello = AgentClient.ProbeAsync("127.0.0.1", server.ListeningPort, 2000, CancellationToken.None).Result;
				Assert(hello != null, "агент найден");
				AssertEqual(Environment.MachineName, hello.ComputerName, "имя ПК в приветствии");
			}
			finally
			{
				server.Stop();
			}
			AgentHello none = AgentClient.ProbeAsync("127.0.0.1", 1, 500, CancellationToken.None).Result;
			Assert(none == null, "на закрытом порту агента нет");
		}

		/// <summary>
		/// Проверяет выбор режима агента: без параметров (двойной щелчок) — работа в фоне, консоль — только по --console.
		/// </summary>
		private static void TestAgentCommandLine()
		{
			AssertEqual(AgentCommand.Default, BackgroundAgent.ResolveCommand(new string[0]), "без параметров — в фоне");
			AssertEqual(AgentCommand.Default, BackgroundAgent.ResolveCommand(new string[] { "--config", "D:\\a.xml" }), "только --config — тоже в фоне");
			AssertEqual(AgentCommand.Default, BackgroundAgent.ResolveCommand(new string[] { BackgroundAgent.NoWindowFlag, "--config", "D:\\a.xml" }), "перезапуск без окна");
			AssertEqual(AgentCommand.Console, BackgroundAgent.ResolveCommand(new string[] { "--console" }), "консоль только по --console");
			AssertEqual(AgentCommand.Service, BackgroundAgent.ResolveCommand(new string[] { "--config", "x.xml", "--service" }), "служба");
			AssertEqual(AgentCommand.Scan, BackgroundAgent.ResolveCommand(new string[] { "--SCAN", "--dir", "D:\\Certs" }), "регистр не важен");
			AssertEqual(AgentCommand.Background, BackgroundAgent.ResolveCommand(new string[] { "--background" }), "фон без службы");
			AssertEqual(AgentCommand.BackgroundWorker, BackgroundAgent.ResolveCommand(new string[] { BackgroundAgent.WorkerFlag, "--config", "x.xml" }), "скрытая копия");
			AssertEqual(AgentCommand.Stop, BackgroundAgent.ResolveCommand(new string[] { "--stop" }), "остановка");
			AssertEqual(AgentCommand.Status, BackgroundAgent.ResolveCommand(new string[] { "--status" }), "состояние");
			AssertEqual(AgentCommand.Help, BackgroundAgent.ResolveCommand(new string[] { "/?" }), "справка");
			AssertEqual(AgentCommand.Install, BackgroundAgent.ResolveCommand(new string[] { "--install", "--console" }), "установка важнее консоли");
		}

		/// <summary>
		/// Запускает проверку фонового режима на настоящем SkziAgent.exe, если он собран рядом с тестами
		/// и на этом ПК агент ещё не работает (иначе тест пропускается, чтобы не мешать рабочему агенту).
		/// </summary>
		private static void RunBackgroundModeTest()
		{
			string name = "Агент: --background без окна, отвечает на порту, --status, --stop";
			string agentPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "SkziAgent.exe");
			string skipReason = null;
			if (!File.Exists(agentPath))
			{
				skipReason = "нет " + agentPath;
			}
			else if (BackgroundAgent.IsBackgroundCopyRunning())
			{
				skipReason = "агент уже работает в фоне на этом ПК";
			}
			else if (BackgroundAgent.GetServiceStatus() == System.ServiceProcess.ServiceControllerStatus.Running)
			{
				skipReason = "на этом ПК работает служба агента";
			}
			if (skipReason != null)
			{
				skippedCount = skippedCount + 1;
				Console.ForegroundColor = ConsoleColor.Yellow;
				Console.Write("  [SKIP] ");
				Console.ResetColor();
				Console.WriteLine(name + ": " + skipReason);
				return;
			}
			Run(name, delegate { TestAgentBackgroundMode(agentPath); });
		}

		/// <summary>
		/// «SkziAgent.exe --background» сразу возвращает управление (не держит консоль и чужой вывод),
		/// агент отвечает на порту, «--status» его видит, «--stop» останавливает.
		/// </summary>
		private static void TestAgentBackgroundMode(string agentPath)
		{
			string workDirectory = Path.Combine(Path.GetTempPath(), "SkziTests", "background-" + Guid.NewGuid().ToString("N").Substring(0, 8));
			Directory.CreateDirectory(workDirectory);
			AgentConfig config = AgentConfig.CreateDefault();
			config.ListenPort = FindFreePort();
			config.ScanDirectories.Clear();
			config.ScanCertificateStores = false;
			config.LogDirectory = Path.Combine(workDirectory, "logs");
			string configPath = Path.Combine(workDirectory, "agent.config.xml");
			ConfigFile.Save(configPath, config);
			string quotedConfig = " --config \"" + configPath + "\"";
			try
			{
				string output;
				Stopwatch stopwatch = Stopwatch.StartNew();
				int exitCode = RunAgentProcess(agentPath, "--background" + quotedConfig, out output);
				AssertEqual(0, exitCode, "--background: код выхода (" + output + ")");
				Assert(stopwatch.ElapsedMilliseconds < 15000, "--background возвращает управление, а не висит");
				Assert(BackgroundAgent.IsBackgroundCopyRunning(), "скрытая копия агента работает");
				AgentHello hello = AgentClient.ProbeAsync("127.0.0.1", config.ListenPort, 2000, CancellationToken.None).Result;
				Assert(hello != null, "агент в фоне отвечает на порту " + config.ListenPort);

				exitCode = RunAgentProcess(agentPath, "--background" + quotedConfig, out output);
				AssertEqual(0, exitCode, "повторный --background");
				Assert(output.Contains("уже работает"), "вторая копия не запускается: " + output);

				exitCode = RunAgentProcess(agentPath, "--status" + quotedConfig, out output);
				AssertEqual(0, exitCode, "--status: агент отвечает (" + output + ")");
				Assert(output.Contains("Агент в фоне без службы: работает"), "--status видит фоновый агент: " + output);
			}
			finally
			{
				string stopOutput;
				RunAgentProcess(agentPath, "--stop" + quotedConfig, out stopOutput);
			}
			Assert(!BackgroundAgent.IsBackgroundCopyRunning(), "после --stop скрытой копии нет");
			Assert(AgentClient.ProbeAsync("127.0.0.1", config.ListenPort, 1000, CancellationToken.None).Result == null, "после --stop порт закрыт");
			string logText = ReadAllLogs(config.LogDirectory);
			Assert(logText.Contains("Агент работает в фоне без окна"), "запуск записан в журнал");
			Assert(logText.Contains("Фоновый агент остановлен командой --stop"), "остановка записана в журнал");
		}

		/// <summary>
		/// Запускает SkziAgent.exe с параметрами без окна, ждёт завершения (до 30 с) и возвращает код выхода и вывод.
		/// </summary>
		private static int RunAgentProcess(string agentPath, string arguments, out string output)
		{
			ProcessStartInfo startInfo = new ProcessStartInfo(agentPath, arguments);
			startInfo.UseShellExecute = false;
			startInfo.CreateNoWindow = true;
			startInfo.RedirectStandardOutput = true;
			startInfo.RedirectStandardError = true;
			startInfo.StandardOutputEncoding = Encoding.UTF8;
			startInfo.StandardErrorEncoding = Encoding.UTF8;
			using (Process process = Process.Start(startInfo))
			{
				System.Threading.Tasks.Task<string> errorReader = process.StandardError.ReadToEndAsync();
				System.Threading.Tasks.Task<string> outputReader = process.StandardOutput.ReadToEndAsync();
				if (!process.WaitForExit(30000))
				{
					process.Kill();
					throw new AssertionException("SkziAgent.exe " + arguments + " не завершился за 30 с");
				}
				if (!System.Threading.Tasks.Task.WaitAll(new System.Threading.Tasks.Task[] { outputReader, errorReader }, 10000))
				{
					throw new AssertionException("SkziAgent.exe " + arguments + ": вывод не закрылся — фоновая копия унаследовала канал");
				}
				output = (outputReader.Result + " " + errorReader.Result).Trim();
				return process.ExitCode;
			}
		}

		/// <summary>
		/// Возвращает свободный TCP-порт на этом ПК.
		/// </summary>
		private static int FindFreePort()
		{
			System.Net.Sockets.TcpListener listener = new System.Net.Sockets.TcpListener(IPAddress.Loopback, 0);
			listener.Start();
			int port = ((IPEndPoint)listener.LocalEndpoint).Port;
			listener.Stop();
			return port;
		}

		/// <summary>
		/// Читает все файлы журнала из папки (для проверки записей).
		/// </summary>
		private static string ReadAllLogs(string logDirectory)
		{
			StringBuilder text = new StringBuilder();
			if (Directory.Exists(logDirectory))
			{
				foreach (string file in Directory.GetFiles(logDirectory, "*.log"))
				{
					using (FileStream stream = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
					using (StreamReader reader = new StreamReader(stream, Encoding.UTF8))
					{
						text.AppendLine(reader.ReadToEnd());
					}
				}
			}
			return text.ToString();
		}

		/// <summary>
		/// Проверяет валидацию имени таблицы.
		/// </summary>
		private static void TestTableNameValidation()
		{
			string schema;
			string table;
			CertificateRepository.ParseTableName("dbo.SkziCertificates", out schema, out table);
			AssertEqual("dbo", schema, "схема");
			AssertEqual("SkziCertificates", table, "таблица");
			CertificateRepository.ParseTableName("[inv].[Certs]", out schema, out table);
			AssertEqual("inv", schema, "схема в скобках");
			bool rejected = false;
			try
			{
				CertificateRepository.ParseTableName("dbo.Certs; DROP TABLE x", out schema, out table);
			}
			catch (ArgumentException)
			{
				rejected = true;
			}
			Assert(rejected, "инъекция в имени таблицы должна отклоняться");
		}

		/// <summary>
		/// Проверяет вспомогательные функции панели.
		/// </summary>
		private static void TestPanelHelpers()
		{
			AssertEqual(3, DiscoveryDialog.ParseAddressRanges("192.168.1.1-3").Count, "диапазон последнего октета");
			AssertEqual(2, DiscoveryDialog.ParseAddressRanges("10.0.0.0/30").Count, "CIDR /30");
			AssertEqual(254, DiscoveryDialog.ParseAddressRanges("10.1.2.0/24").Count, "CIDR /24");
			AssertEqual(4, DiscoveryDialog.ParseAddressRanges("10.0.0.5, 10.0.0.7-10.0.0.9").Count, "список");
			Assert(ScanCoordinator.IsLocalHost("localhost"), "localhost локальный");
			Assert(ScanCoordinator.IsLocalHost("127.0.0.1"), "127.0.0.1 локальный");
			Assert(ScanCoordinator.IsLocalHost(Environment.MachineName.ToLowerInvariant()), "имя ПК локальное");
			Assert(!ScanCoordinator.IsLocalHost("some-other-pc-" + Guid.NewGuid().ToString("N").Substring(0, 6)), "чужой ПК не локальный");
			AgentConfig agentConfig = AgentDeployer.BuildAgentConfig(PanelConfig.CreateDefault());
			AssertEqual(PanelConfig.CreateDefault().SharedKey, agentConfig.SharedKey, "ключ передаётся в конфигурацию агента");
		}

		/// <summary>
		/// Тесты MSSQL: создание таблицы, upsert без дублей, обновление даты, дополнение старой таблицы столбцами.
		/// </summary>
		private static void RunDatabaseTests()
		{
			string connectionString = Environment.GetEnvironmentVariable("SKZI_TEST_SQL");
			if (string.IsNullOrWhiteSpace(connectionString))
			{
				skippedCount = skippedCount + 1;
				Console.ForegroundColor = ConsoleColor.Yellow;
				Console.Write("  [SKIP] ");
				Console.ResetColor();
				Console.WriteLine("MSSQL: задайте SKZI_TEST_SQL=\"Server=...;Database=SkziTest;Integrated Security=true\"");
				return;
			}
			Run("MSSQL: создание БД и таблицы, upsert по серийному номеру без дублей", delegate { TestDatabaseUpsert(connectionString); });
			Run("MSSQL: существующая таблица со старой структурой дополняется столбцами", delegate { TestDatabaseExistingTable(connectionString); });
			Run("MSSQL: пропавшие сертификаты помечаются, вернувшиеся — снимается отметка; места «сертификат — ПК»", delegate { TestDatabaseMissingMarks(connectionString); });
		}

		/// <summary>
		/// Сертификат удалили из папки — строка помечается пропавшей; сканирование другой папки отметок не ставит;
		/// файл вернули — отметка снимается. Время внесения, обновления и «последний раз найден» при первой записи совпадают.
		/// </summary>
		private static void TestDatabaseMissingMarks(string connectionString)
		{
			string tableName = "dbo.SkziMissing_" + Guid.NewGuid().ToString("N").Substring(0, 8);
			CertificateRepository repository = new CertificateRepository(connectionString, tableName);
			string workDirectory = Path.Combine(Path.GetTempPath(), "SkziTests", "missing_" + Guid.NewGuid().ToString("N").Substring(0, 8));
			string certsDirectory = Path.Combine(workDirectory, "certs");
			string otherDirectory = Path.Combine(workDirectory, "other");
			Directory.CreateDirectory(certsDirectory);
			Directory.CreateDirectory(otherDirectory);
			string petrovaCopy = Path.Combine(certsDirectory, "petrova.crt");
			File.Copy(SamplePath("ivanov_ii.cer"), Path.Combine(certsDirectory, "ivanov.cer"));
			File.Copy(SamplePath(Path.Combine("Отдел кадров", "petrova_as.crt")), petrovaCopy);
			try
			{
				repository.EnsureDatabaseExists();
				repository.EnsureTableExists();

				SaveStatistics first = repository.SaveScanResult(ScanDirectoryOnly(certsDirectory));
				AssertEqual(2, first.Inserted, "вставлено");
				AssertEqual(0, first.MarkedMissing, "пропавших нет");
				AssertEqual(ReadDate(connectionString, repository, "InsertedAt"), ReadDate(connectionString, repository, "LastSeenAt"), "одно время для всех полей записи");

				string petrovaSerial = CertificateParser.Parse(CertificateFileLoader.LoadFromFile(petrovaCopy)[0]).SerialNumber;
				File.Delete(petrovaCopy);
				SaveStatistics second = repository.SaveScanResult(ScanDirectoryOnly(certsDirectory));
				AssertEqual(1, second.MarkedMissing, "Петрова помечена пропавшей");
				AssertEqual(1, repository.LoadCertificates(null, CertificateStatusFilter.Missing, 100).Rows.Count, "фильтр «Пропавшие»");
				AssertEqual(1, repository.LoadCertificates(null, CertificateStatusFilter.Present, 100).Rows.Count, "фильтр «Найденные»");
				System.Data.DataTable locations = repository.LoadLocations(petrovaSerial);
				AssertEqual(1, locations.Rows.Count, "одно место Петровой");
				Assert((bool)locations.Rows[0]["IsMissing"], "место Петровой помечено пропавшим");
				AssertEqual(Environment.MachineName, Convert.ToString(locations.Rows[0]["ComputerName"]), "ПК в таблице мест");

				SaveStatistics otherFolder = repository.SaveScanResult(ScanDirectoryOnly(otherDirectory));
				AssertEqual(0, otherFolder.MarkedMissing, "сканирование другой папки не помечает Иванова");
				AssertEqual(1, repository.LoadCertificates(null, CertificateStatusFilter.Present, 100).Rows.Count, "Иванов по-прежнему найден");

				File.Copy(SamplePath(Path.Combine("Отдел кадров", "petrova_as.crt")), petrovaCopy);
				repository.SaveScanResult(ScanDirectoryOnly(certsDirectory));
				AssertEqual(0, repository.LoadCertificates(null, CertificateStatusFilter.Missing, 100).Rows.Count, "вернувшийся сертификат не помечен");
				System.Data.DataTable all = repository.LoadCertificates(null, 100);
				AssertEqual(2, all.Rows.Count, "строк без дублей");
				AssertEqual(Environment.MachineName, Convert.ToString(all.Rows[0]["FoundOnComputers"]), "список ПК, где сертификат есть сейчас");
			}
			finally
			{
				DropTables(connectionString, repository);
				Directory.Delete(workDirectory, true);
			}
		}

		/// <summary>
		/// Сканирует только одну папку (без хранилищ и контейнеров).
		/// </summary>
		private static ScanResult ScanDirectoryOnly(string directory)
		{
			ScanOptions options = new ScanOptions();
			options.ScanCertificateStores = false;
			options.ScanCryptoProContainers = false;
			options.Directories.Add(new ScanDirectoryEntry(directory, true));
			return CertificateCollector.Scan(new LocalScanTarget(), options, CertificateCollector.ModeLocal, CancellationToken.None);
		}

		/// <summary>
		/// Удаляет основную таблицу и таблицу мест после теста.
		/// </summary>
		private static void DropTables(string connectionString, CertificateRepository repository)
		{
			ExecuteSql(connectionString, "IF OBJECT_ID(N'" + repository.QuotedTableName + "', N'U') IS NOT NULL DROP TABLE " + repository.QuotedTableName);
			ExecuteSql(connectionString, "IF OBJECT_ID(N'" + repository.QuotedLocationsTableName + "', N'U') IS NOT NULL DROP TABLE " + repository.QuotedLocationsTableName);
		}

		/// <summary>
		/// Двойная запись одного результата: строки не дублируются, InsertedAt сохраняется, UpdatedAt растёт.
		/// </summary>
		private static void TestDatabaseUpsert(string connectionString)
		{
			string tableName = "dbo.SkziTest_" + Guid.NewGuid().ToString("N").Substring(0, 8);
			CertificateRepository repository = new CertificateRepository(connectionString, tableName);
			try
			{
				repository.EnsureDatabaseExists();
				Assert(repository.EnsureTableExists(), "таблица должна быть создана");
				Assert(!repository.EnsureTableExists(), "повторная проверка не создаёт таблицу");

				ScanResult result = ScanSamplesWithoutStores();
				SaveStatistics first = repository.SaveScanResult(result);
				AssertEqual(6, first.Inserted, "первая запись: вставлено");
				AssertEqual(0, first.Updated, "первая запись: обновлено");
				DateTime insertedBefore = ReadDate(connectionString, repository, "InsertedAt");
				DateTime updatedBefore = ReadDate(connectionString, repository, "UpdatedAt");
				AssertEqual(insertedBefore, updatedBefore, "при первой записи UpdatedAt = InsertedAt");

				Thread.Sleep(50);
				SaveStatistics second = repository.SaveScanResult(result);
				AssertEqual(0, second.Inserted, "вторая запись: вставлено");
				AssertEqual(6, second.Updated, "вторая запись: обновлено");
				AssertEqual(6, CountRows(connectionString, repository), "строк в таблице (без дублей)");
				AssertEqual(insertedBefore, ReadDate(connectionString, repository, "InsertedAt"), "InsertedAt не меняется");
				Assert(ReadDate(connectionString, repository, "UpdatedAt") > updatedBefore, "UpdatedAt увеличился");
				AssertEqual(6, repository.LoadCertificates(null, 100).Rows.Count, "выборка для панели");
				AssertEqual(1, repository.LoadCertificates("Иванов", 100).Rows.Count, "фильтр по владельцу");
				AssertEqual(1, repository.LoadCertificates(null, CertificateStatusFilter.Expired, 100).Rows.Count, "фильтр «Истёкшие»");
				int totalCount;
				int withLicenseCount;
				int expiredCount;
				int missingCount;
				repository.GetSummary(out totalCount, out withLicenseCount, out expiredCount, out missingCount);
				AssertEqual(6, totalCount, "итог: всего");
				AssertEqual(3, withLicenseCount, "итог: с лицензией");
				AssertEqual(0, missingCount, "итог: пропавших");
			}
			finally
			{
				DropTables(connectionString, repository);
			}
		}

		/// <summary>
		/// Таблица с минимальным набором столбцов из задания дополняется недостающими и принимает данные.
		/// </summary>
		private static void TestDatabaseExistingTable(string connectionString)
		{
			string tableName = "dbo.SkziLegacy_" + Guid.NewGuid().ToString("N").Substring(0, 8);
			CertificateRepository repository = new CertificateRepository(connectionString, tableName);
			try
			{
				repository.EnsureDatabaseExists();
				ExecuteSql(connectionString, "CREATE TABLE " + repository.QuotedTableName + " (Id INT IDENTITY PRIMARY KEY, SerialNumber NVARCHAR(128) NOT NULL UNIQUE, " +
					"InsertedAt DATETIME2(3) NOT NULL, UpdatedAt DATETIME2(3) NOT NULL, OwnerName NVARCHAR(512), CertificationAuthority NVARCHAR(512), " +
					"CryptoProLicenseVersion NVARCHAR(64), HasEmbeddedCryptoProLicense BIT NOT NULL DEFAULT 0)");
				Assert(!repository.EnsureTableExists(), "существующая таблица не пересоздаётся");
				SaveStatistics statistics = repository.SaveScanResult(ScanSamplesWithoutStores());
				AssertEqual(6, statistics.Inserted, "вставлено в старую таблицу");
				using (SqlConnection connection = new SqlConnection(connectionString))
				using (SqlCommand command = new SqlCommand("SELECT COL_LENGTH(@Table, 'CertificationAuthority')", connection))
				{
					command.Parameters.AddWithValue("@Table", repository.QuotedTableName);
					connection.Open();
					AssertEqual(2000, Convert.ToInt32(command.ExecuteScalar()), "столбец УЦ расширен до NVARCHAR(1000)");
				}
			}
			finally
			{
				DropTables(connectionString, repository);
			}
		}

		// ---------- Вспомогательные методы ----------

		/// <summary>
		/// Запускает агент на свободном порту с тестовым ключом (без сканирования хранилищ Windows).
		/// </summary>
		private static AgentServer StartTestAgent(string sharedKey)
		{
			AgentConfig config = new AgentConfig();
			config.ListenPort = 0;
			config.SharedKey = sharedKey;
			config.ScanCertificateStores = false;
			config.AcceptDirectoriesFromPanel = true;
			AgentServer server = new AgentServer(config);
			server.Start();
			return server;
		}

		/// <summary>
		/// Сканирует папку тестовых сертификатов без хранилищ Windows.
		/// </summary>
		private static ScanResult ScanSamplesWithoutStores()
		{
			ScanOptions options = new ScanOptions();
			options.ScanCertificateStores = false;
			options.ScanCryptoProContainers = false;
			options.Directories.Add(new ScanDirectoryEntry(samplesDirectory, true));
			return CertificateCollector.Scan(new LocalScanTarget(), options, CertificateCollector.ModeLocal, CancellationToken.None);
		}

		/// <summary>
		/// Читает дату из строки сертификата Иванова (по фильтру владельца).
		/// </summary>
		private static DateTime ReadDate(string connectionString, CertificateRepository repository, string column)
		{
			using (SqlConnection connection = new SqlConnection(connectionString))
			using (SqlCommand command = new SqlCommand("SELECT [" + column + "] FROM " + repository.QuotedTableName + " WHERE OwnerName = N'Иванов Иван Иванович'", connection))
			{
				connection.Open();
				return (DateTime)command.ExecuteScalar();
			}
		}

		/// <summary>
		/// Возвращает число строк таблицы.
		/// </summary>
		private static int CountRows(string connectionString, CertificateRepository repository)
		{
			using (SqlConnection connection = new SqlConnection(connectionString))
			using (SqlCommand command = new SqlCommand("SELECT COUNT(*) FROM " + repository.QuotedTableName, connection))
			{
				connection.Open();
				return (int)command.ExecuteScalar();
			}
		}

		/// <summary>
		/// Выполняет произвольный SQL (для подготовки и очистки тестов).
		/// </summary>
		private static void ExecuteSql(string connectionString, string sql)
		{
			using (SqlConnection connection = new SqlConnection(connectionString))
			using (SqlCommand command = new SqlCommand(sql, connection))
			{
				connection.Open();
				command.ExecuteNonQuery();
			}
		}

		/// <summary>
		/// Ищет папку samples\certs вверх от каталога exe.
		/// </summary>
		private static string FindSamplesDirectory()
		{
			DirectoryInfo current = new DirectoryInfo(AppDomain.CurrentDomain.BaseDirectory);
			while (current != null)
			{
				string candidate = Path.Combine(current.FullName, "samples", "certs");
				if (Directory.Exists(candidate))
				{
					return candidate;
				}
				current = current.Parent;
			}
			throw new DirectoryNotFoundException("Не найдена папка samples\\certs — передайте путь первым аргументом");
		}

		/// <summary>
		/// Полный путь к тестовому файлу.
		/// </summary>
		private static string SamplePath(string relativePath)
		{
			return Path.Combine(samplesDirectory, relativePath);
		}

		/// <summary>
		/// Читает файл, открытый на запись другим кодом (журнал).
		/// </summary>
		private static string ReadShared(string path)
		{
			using (FileStream stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
			using (StreamReader reader = new StreamReader(stream, Encoding.UTF8))
			{
				return reader.ReadToEnd();
			}
		}

		/// <summary>
		/// Проверка условия.
		/// </summary>
		private static void Assert(bool condition, string message)
		{
			if (!condition)
			{
				throw new AssertionException(message);
			}
		}

		/// <summary>
		/// Проверка равенства ожидаемого и фактического значений.
		/// </summary>
		private static void AssertEqual<T>(T expected, T actual, string message)
		{
			if (!EqualityComparer<T>.Default.Equals(expected, actual))
			{
				throw new AssertionException(message + ": ожидалось «" + expected + "», получено «" + actual + "»");
			}
		}
	}

	/// <summary>
	/// Исключение проваленной проверки.
	/// </summary>
	public sealed class AssertionException : Exception
	{
		/// <summary>
		/// Создаёт исключение с текстом проваленной проверки.
		/// </summary>
		public AssertionException(string message) : base(message)
		{
		}
	}
}
