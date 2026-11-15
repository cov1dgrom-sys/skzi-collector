using System;
using System.Collections.Generic;
using System.Data;
using System.Data.SqlClient;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Skzi.Common.Certificates;
using Skzi.Common.Logging;
using Skzi.Common.Scanning;

namespace Skzi.Common.Database
{
	/// <summary>
	/// Итог записи результата сканирования в БД.
	/// </summary>
	public sealed class SaveStatistics
	{
		public int Inserted { get; set; }
		public int Updated { get; set; }

		/// <summary>Сколько сертификатов помечено как пропавшие (не найдены там, где были раньше).</summary>
		public int MarkedMissing { get; set; }

		/// <summary>
		/// Краткое описание итога записи в БД для журнала и интерфейса.
		/// </summary>
		public override string ToString()
		{
			return "добавлено " + Inserted + ", обновлено " + Updated + (MarkedMissing > 0 ? ", помечено пропавшими " + MarkedMissing : string.Empty);
		}
	}

	/// <summary>
	/// Какие строки показывать на вкладке «Сертификаты в БД».
	/// </summary>
	public enum CertificateStatusFilter
	{
		All,
		Present,
		Missing,
		Expired
	}

	/// <summary>
	/// Описание столбца таблицы: имя, тип SQL, русское описание и (необязательно) значение по умолчанию.
	/// </summary>
	public sealed class ColumnDefinition
	{
		public string Name { get; private set; }
		public string SqlType { get; private set; }
		public string Description { get; private set; }
		public string DefaultExpression { get; private set; }

		/// <summary>
		/// Создаёт описание столбца таблицы без значения по умолчанию.
		/// </summary>
		public ColumnDefinition(string name, string sqlType, string description)
			: this(name, sqlType, description, null)
		{
		}

		/// <summary>
		/// Создаёт описание столбца таблицы со значением по умолчанию (например, «0» для флажков).
		/// </summary>
		public ColumnDefinition(string name, string sqlType, string description, string defaultExpression)
		{
			Name = name;
			SqlType = sqlType;
			Description = description;
			DefaultExpression = defaultExpression;
		}
	}

	/// <summary>
	/// Работа с таблицами сертификатов в MSSQL:
	/// создание БД и таблиц при отсутствии, добавление недостающих столбцов,
	/// вставка/обновление строки по серийному номеру (без дублей), учёт мест «сертификат — ПК — источник»,
	/// пометка пропавших сертификатов, выборка для панели управления.
	/// </summary>
	public sealed class CertificateRepository
	{
		private const string LocationsTableSuffix = "Locations";
		private static readonly Regex IdentifierRegex = new Regex(@"^[A-Za-z_][A-Za-z0-9_]{0,127}$", RegexOptions.CultureInvariant);

		/// <summary>
		/// Структура основной таблицы. Первые 8 столбцов — обязательные по заданию (п. 4.1), остальные — расширенные сведения.
		/// </summary>
		public static readonly ColumnDefinition[] Columns =
		{
			new ColumnDefinition("Id", "BIGINT IDENTITY(1,1) NOT NULL", "Идентификатор строки"),
			new ColumnDefinition("SerialNumber", "NVARCHAR(128) NOT NULL", "Серийный номер сертификата"),
			new ColumnDefinition("InsertedAt", "DATETIME2(3) NOT NULL", "Дата и время внесения в таблицу"),
			new ColumnDefinition("UpdatedAt", "DATETIME2(3) NOT NULL", "Дата и время обновления данных"),
			new ColumnDefinition("OwnerName", "NVARCHAR(512) NULL", "Имя владельца (ФИО)"),
			new ColumnDefinition("CertificationAuthority", "NVARCHAR(1000) NULL", "Удостоверяющий центр (полное имя издателя)"),
			new ColumnDefinition("CryptoProLicenseVersion", "NVARCHAR(64) NULL", "Версия КриптоПро CSP, если сертификат содержит лицензию"),
			new ColumnDefinition("HasEmbeddedCryptoProLicense", "BIT NOT NULL", "Встроена ли лицензия КриптоПро CSP в сертификат", "0"),
			new ColumnDefinition("IsMissing", "BIT NOT NULL", "Сертификат не найден при последнем сканировании ни в одном из мест, где был раньше (1 — пропал)", "0"),
			new ColumnDefinition("MissingSince", "DATETIME2(3) NULL", "С какого сканирования сертификат не находится"),
			new ColumnDefinition("LastSeenAt", "DATETIME2(3) NULL", "Когда сертификат последний раз найден при сканировании"),
			new ColumnDefinition("Thumbprint", "NVARCHAR(64) NULL", "Отпечаток сертификата (SHA-1)"),
			new ColumnDefinition("ValidFrom", "DATETIME2(0) NULL", "Действителен с"),
			new ColumnDefinition("ValidTo", "DATETIME2(0) NULL", "Действителен по"),
			new ColumnDefinition("OwnerInn", "NVARCHAR(16) NULL", "ИНН владельца"),
			new ColumnDefinition("OwnerSnils", "NVARCHAR(16) NULL", "СНИЛС владельца"),
			new ColumnDefinition("OwnerOgrn", "NVARCHAR(16) NULL", "ОГРН/ОГРНИП владельца"),
			new ColumnDefinition("OwnerOrganization", "NVARCHAR(512) NULL", "Организация владельца"),
			new ColumnDefinition("OwnerTitle", "NVARCHAR(256) NULL", "Должность владельца"),
			new ColumnDefinition("SubjectDn", "NVARCHAR(2000) NULL", "Субъект (полное имя)"),
			new ColumnDefinition("IssuerDn", "NVARCHAR(2000) NULL", "Издатель (полное имя)"),
			new ColumnDefinition("SignatureAlgorithm", "NVARCHAR(256) NULL", "Алгоритм подписи"),
			new ColumnDefinition("CryptoProLicenseDetails", "NVARCHAR(1000) NULL", "Содержимое расширения лицензии (ключ замаскирован)"),
			new ColumnDefinition("HasPrivateKey", "BIT NULL", "Есть привязка к закрытому ключу"),
			new ColumnDefinition("ComputerName", "NVARCHAR(256) NULL", "ПК, на котором сертификат найден при последнем сканировании"),
			new ColumnDefinition("InstalledCryptoProVersion", "NVARCHAR(256) NULL", "Версия КриптоПро CSP, установленная на этом ПК"),
			new ColumnDefinition("InstalledCryptoProLicenseSerial", "NVARCHAR(64) NULL", "Серийный номер лицензии КриптоПро CSP на этом ПК (замаскирован)"),
			new ColumnDefinition("InstalledCryptoProLicenseValidity", "NVARCHAR(256) NULL", "Срок действия лицензии КриптоПро CSP на этом ПК"),
			new ColumnDefinition("CertificateSource", "NVARCHAR(2000) NULL", "Где найден сертификат при последнем сканировании (файл/хранилище/контейнер)"),
			new ColumnDefinition("ScanMode", "NVARCHAR(32) NULL", "Способ сканирования (Agent/Agentless/Local)")
		};

		/// <summary>
		/// Структура таблицы мест «сертификат — ПК — источник» (на каких ПК и где именно найден сертификат).
		/// </summary>
		public static readonly ColumnDefinition[] LocationColumns =
		{
			new ColumnDefinition("Id", "BIGINT IDENTITY(1,1) NOT NULL", "Идентификатор строки"),
			new ColumnDefinition("SerialNumber", "NVARCHAR(128) NOT NULL", "Серийный номер сертификата"),
			new ColumnDefinition("ComputerName", "NVARCHAR(256) NOT NULL", "ПК, на котором найден сертификат"),
			new ColumnDefinition("Source", "NVARCHAR(1000) NOT NULL", "Где найден: файл, хранилище или контейнер КриптоПро"),
			new ColumnDefinition("SourceHash", "BINARY(32) NOT NULL", "SHA-256 от источника (для уникального индекса)"),
			new ColumnDefinition("FirstSeenAt", "DATETIME2(3) NOT NULL", "Когда найден впервые"),
			new ColumnDefinition("LastSeenAt", "DATETIME2(3) NOT NULL", "Когда найден последний раз"),
			new ColumnDefinition("IsMissing", "BIT NOT NULL", "Не найден при последнем сканировании этого места (1 — пропал)", "0"),
			new ColumnDefinition("MissingSince", "DATETIME2(3) NULL", "С какого сканирования не находится"),
			new ColumnDefinition("ScanMode", "NVARCHAR(32) NULL", "Способ сканирования (Agent/Agentless/Local)")
		};

		private readonly string connectionString;
		private readonly string schemaName;
		private readonly string tableName;
		private readonly string locationsTableName;

		/// <summary>
		/// Создаёт репозиторий для указанной строки подключения и таблицы («схема.таблица» или «таблица»).
		/// Таблица мест получает имя «таблица» + «Locations».
		/// </summary>
		public CertificateRepository(string connectionString, string qualifiedTableName)
		{
			if (string.IsNullOrWhiteSpace(connectionString))
			{
				throw new ArgumentException("Не задана строка подключения к MSSQL", "connectionString");
			}
			this.connectionString = connectionString;
			ParseTableName(qualifiedTableName, out schemaName, out tableName);
			locationsTableName = tableName + LocationsTableSuffix;
		}

		/// <summary>
		/// Полное имя основной таблицы в квадратных скобках: [dbo].[SkziCertificates].
		/// </summary>
		public string QuotedTableName
		{
			get { return "[" + schemaName + "].[" + tableName + "]"; }
		}

		/// <summary>
		/// Полное имя таблицы мест: [dbo].[SkziCertificatesLocations].
		/// </summary>
		public string QuotedLocationsTableName
		{
			get { return "[" + schemaName + "].[" + locationsTableName + "]"; }
		}

		/// <summary>
		/// Разбирает и проверяет имя таблицы (только латиница, цифры и «_» — защита от SQL-инъекций).
		/// </summary>
		public static void ParseTableName(string qualifiedTableName, out string schema, out string table)
		{
			string name = string.IsNullOrWhiteSpace(qualifiedTableName) ? "dbo.SkziCertificates" : qualifiedTableName.Trim();
			name = name.Replace("[", string.Empty).Replace("]", string.Empty);
			string[] parts = name.Split('.');
			if (parts.Length == 1)
			{
				schema = "dbo";
				table = parts[0];
			}
			else if (parts.Length == 2)
			{
				schema = parts[0];
				table = parts[1];
			}
			else
			{
				throw new ArgumentException("Имя таблицы должно иметь вид «схема.таблица»: " + qualifiedTableName);
			}
			if (!IdentifierRegex.IsMatch(schema) || !IdentifierRegex.IsMatch(table))
			{
				throw new ArgumentException("Недопустимое имя таблицы (разрешены латинские буквы, цифры и «_»): " + qualifiedTableName);
			}
			if (table.Length + LocationsTableSuffix.Length > 128)
			{
				throw new ArgumentException("Слишком длинное имя таблицы (не более " + (128 - LocationsTableSuffix.Length) + " символов): " + qualifiedTableName);
			}
		}

		/// <summary>
		/// Проверяет подключение к серверу и возвращает его версию.
		/// </summary>
		public static string TestConnection(string connectionString)
		{
			SqlConnectionStringBuilder builder = new SqlConnectionStringBuilder(connectionString);
			string targetDatabase = builder.InitialCatalog;
			builder.InitialCatalog = "master";
			using (SqlConnection connection = new SqlConnection(builder.ConnectionString))
			{
				connection.Open();
				using (SqlCommand command = new SqlCommand("SELECT @@VERSION, DB_ID(@DatabaseName)", connection))
				{
					command.Parameters.Add("@DatabaseName", SqlDbType.NVarChar, 128).Value = targetDatabase ?? string.Empty;
					using (SqlDataReader reader = command.ExecuteReader())
					{
						reader.Read();
						string version = reader.GetString(0).Split('\n')[0].Trim();
						bool databaseExists = !reader.IsDBNull(1);
						return version + Environment.NewLine + "База данных «" + targetDatabase + "»: " + (databaseExists ? "существует" : "не существует (будет создана)");
					}
				}
			}
		}

		/// <summary>
		/// Создаёт базу данных из строки подключения, если её нет (подключение к master).
		/// </summary>
		public void EnsureDatabaseExists()
		{
			SqlConnectionStringBuilder builder = new SqlConnectionStringBuilder(connectionString);
			string databaseName = builder.InitialCatalog;
			if (string.IsNullOrWhiteSpace(databaseName) || string.Equals(databaseName, "master", StringComparison.OrdinalIgnoreCase))
			{
				return;
			}
			builder.InitialCatalog = "master";
			using (SqlConnection connection = new SqlConnection(builder.ConnectionString))
			{
				connection.Open();
				string sql = "IF DB_ID(@DatabaseName) IS NULL BEGIN DECLARE @CreateSql NVARCHAR(400) = N'CREATE DATABASE ' + QUOTENAME(@DatabaseName); " +
					"EXEC(@CreateSql); SELECT 1; END ELSE SELECT 0;";
				using (SqlCommand command = new SqlCommand(sql, connection))
				{
					command.Parameters.Add("@DatabaseName", SqlDbType.NVarChar, 128).Value = databaseName;
					object created = command.ExecuteScalar();
					if (Convert.ToInt32(created) == 1)
					{
						Logger.Info("Создана база данных " + databaseName);
					}
				}
			}
		}

		/// <summary>
		/// Проверяет существование таблиц: если их нет — создаёт; если есть — добавляет недостающие столбцы
		/// и расширяет столбцы, ставшие шире. Возвращает true, если основная таблица была создана.
		/// </summary>
		public bool EnsureTableExists()
		{
			using (SqlConnection connection = new SqlConnection(connectionString))
			{
				connection.Open();
				bool created = false;
				if (!TableExists(connection, QuotedTableName))
				{
					CreateTable(connection, QuotedTableName, tableName, Columns,
						new[] { "CONSTRAINT [UQ_" + tableName + "_SerialNumber] UNIQUE ([SerialNumber])" }, null);
					Logger.Info("Таблица " + QuotedTableName + " не найдена и была создана");
					created = true;
				}
				else
				{
					AddMissingColumns(connection, QuotedTableName, tableName, Columns);
					WidenColumn(connection, QuotedTableName, "CertificationAuthority", "NVARCHAR(1000) NULL", 2000);
				}

				if (!TableExists(connection, QuotedLocationsTableName))
				{
					CreateTable(connection, QuotedLocationsTableName, locationsTableName, LocationColumns,
						new[] { "CONSTRAINT [UQ_" + locationsTableName + "_Place] UNIQUE ([SerialNumber], [ComputerName], [SourceHash])" },
						"CREATE INDEX [IX_" + locationsTableName + "_Computer] ON " + QuotedLocationsTableName + " ([ComputerName], [IsMissing]);");
					Logger.Info("Таблица мест «сертификат — ПК» " + QuotedLocationsTableName + " не найдена и была создана");
				}
				else
				{
					AddMissingColumns(connection, QuotedLocationsTableName, locationsTableName, LocationColumns);
				}
				return created;
			}
		}

		/// <summary>
		/// Проверяет наличие таблицы в БД.
		/// </summary>
		private static bool TableExists(SqlConnection connection, string quotedName)
		{
			using (SqlCommand command = new SqlCommand("SELECT CASE WHEN OBJECT_ID(@FullName, N'U') IS NULL THEN 0 ELSE 1 END", connection))
			{
				command.Parameters.Add("@FullName", SqlDbType.NVarChar, 300).Value = quotedName;
				return Convert.ToInt32(command.ExecuteScalar()) == 1;
			}
		}

		/// <summary>
		/// Создаёт схему (при необходимости), таблицу с первичным ключом по Id, дополнительными ограничениями,
		/// индексом и русскими описаниями столбцов.
		/// </summary>
		private void CreateTable(SqlConnection connection, string quotedName, string plainName, ColumnDefinition[] columns,
			string[] constraints, string indexSql)
		{
			StringBuilder sql = new StringBuilder();
			sql.AppendLine("IF SCHEMA_ID(N'" + schemaName + "') IS NULL EXEC(N'CREATE SCHEMA [" + schemaName + "]');");
			sql.AppendLine("CREATE TABLE " + quotedName + " (");
			foreach (ColumnDefinition column in columns)
			{
				sql.AppendLine("\t[" + column.Name + "] " + column.SqlType + BuildDefaultClause(plainName, column) + ",");
			}
			sql.Append("\tCONSTRAINT [PK_" + plainName + "] PRIMARY KEY CLUSTERED ([Id])");
			foreach (string constraint in constraints)
			{
				sql.AppendLine(",");
				sql.Append("\t" + constraint);
			}
			sql.AppendLine();
			sql.AppendLine(");");
			if (!string.IsNullOrEmpty(indexSql))
			{
				sql.AppendLine(indexSql);
			}

			using (SqlTransaction transaction = connection.BeginTransaction())
			{
				using (SqlCommand command = new SqlCommand(sql.ToString(), connection, transaction))
				{
					command.ExecuteNonQuery();
				}
				foreach (ColumnDefinition column in columns)
				{
					AddColumnDescription(connection, transaction, plainName, column);
				}
				transaction.Commit();
			}
		}

		/// <summary>
		/// Формирует предложение DEFAULT для столбца со значением по умолчанию.
		/// </summary>
		private static string BuildDefaultClause(string plainTableName, ColumnDefinition column)
		{
			if (string.IsNullOrEmpty(column.DefaultExpression))
			{
				return string.Empty;
			}
			return " CONSTRAINT [DF_" + plainTableName + "_" + column.Name + "] DEFAULT (" + column.DefaultExpression + ")";
		}

		/// <summary>
		/// Добавляет столбцы, которых нет в существующей таблице (например, если таблица создана по старой схеме).
		/// Столбцы со значением по умолчанию добавляются как NOT NULL (существующие строки получают значение по умолчанию).
		/// </summary>
		private void AddMissingColumns(SqlConnection connection, string quotedName, string plainName, ColumnDefinition[] columns)
		{
			HashSet<string> existingColumns = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
			using (SqlCommand command = new SqlCommand("SELECT name FROM sys.columns WHERE object_id = OBJECT_ID(@FullName, N'U')", connection))
			{
				command.Parameters.Add("@FullName", SqlDbType.NVarChar, 300).Value = quotedName;
				using (SqlDataReader reader = command.ExecuteReader())
				{
					while (reader.Read())
					{
						existingColumns.Add(reader.GetString(0));
					}
				}
			}

			foreach (ColumnDefinition column in columns)
			{
				if (existingColumns.Contains(column.Name) || column.SqlType.Contains("IDENTITY"))
				{
					continue;
				}
				string sqlType = string.IsNullOrEmpty(column.DefaultExpression)
					? column.SqlType.Replace("NOT NULL", "NULL")
					: column.SqlType;
				string sql = "ALTER TABLE " + quotedName + " ADD [" + column.Name + "] " + sqlType + BuildDefaultClause(plainName, column);
				using (SqlCommand command = new SqlCommand(sql, connection))
				{
					command.ExecuteNonQuery();
				}
				try
				{
					AddColumnDescription(connection, null, plainName, column);
				}
				catch (SqlException)
				{
					// Описание столбца — справочное; его отсутствие не мешает работе.
				}
				Logger.Info("В таблицу " + quotedName + " добавлен недостающий столбец " + column.Name);
			}
		}

		/// <summary>
		/// Расширяет текстовый столбец существующей таблицы, если он короче нужного (размер в байтах для NVARCHAR — символы × 2).
		/// </summary>
		private static void WidenColumn(SqlConnection connection, string quotedName, string columnName, string newType, int requiredBytes)
		{
			string sql = "IF COL_LENGTH(@FullName, @Column) IS NOT NULL AND COL_LENGTH(@FullName, @Column) BETWEEN 1 AND " + (requiredBytes - 1) +
				" BEGIN ALTER TABLE " + quotedName + " ALTER COLUMN [" + columnName + "] " + newType + "; SELECT 1; END ELSE SELECT 0;";
			using (SqlCommand command = new SqlCommand(sql, connection))
			{
				command.Parameters.Add("@FullName", SqlDbType.NVarChar, 300).Value = quotedName;
				command.Parameters.Add("@Column", SqlDbType.NVarChar, 128).Value = columnName;
				if (Convert.ToInt32(command.ExecuteScalar()) == 1)
				{
					Logger.Info("Столбец " + columnName + " таблицы " + quotedName + " расширен до " + newType);
				}
			}
		}

		/// <summary>
		/// Записывает русское описание столбца в расширенные свойства (MS_Description) — видно в SSMS.
		/// </summary>
		private void AddColumnDescription(SqlConnection connection, SqlTransaction transaction, string plainTableName, ColumnDefinition column)
		{
			const string Sql = "EXEC sys.sp_addextendedproperty @name = N'MS_Description', @value = @Description, " +
				"@level0type = N'SCHEMA', @level0name = @Schema, @level1type = N'TABLE', @level1name = @Table, @level2type = N'COLUMN', @level2name = @Column";
			using (SqlCommand command = new SqlCommand(Sql, connection, transaction))
			{
				command.Parameters.Add("@Description", SqlDbType.NVarChar, 400).Value = column.Description;
				command.Parameters.Add("@Schema", SqlDbType.NVarChar, 128).Value = schemaName;
				command.Parameters.Add("@Table", SqlDbType.NVarChar, 128).Value = plainTableName;
				command.Parameters.Add("@Column", SqlDbType.NVarChar, 128).Value = column.Name;
				command.ExecuteNonQuery();
			}
		}

		/// <summary>
		/// Записывает результат сканирования одного ПК в одной транзакции:
		/// 1) сертификат с уже существующим серийным номером обновляется (UpdatedAt), новый — добавляется (InsertedAt = UpdatedAt);
		///    дубли по серийному номеру невозможны (проверка + уникальный индекс);
		/// 2) для каждого места (ПК + файл/хранилище/контейнер) обновляется или добавляется строка в таблице мест;
		/// 3) места этого ПК, которые входили в область сканирования, но где сертификат больше не найден, помечаются пропавшими;
		///    сертификат помечается пропавшим, если не осталось ни одного места, где он есть.
		/// Время для всех строк одно — время сервера БД в момент записи.
		/// </summary>
		public SaveStatistics SaveScanResult(ScanResult scanResult)
		{
			SaveStatistics statistics = new SaveStatistics();
			if (scanResult == null)
			{
				return statistics;
			}

			string upsertSql = BuildUpsertSql();
			string upsertLocationSql = BuildUpsertLocationSql();
			HashSet<string> savedSerialNumbers = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
			using (SqlConnection connection = new SqlConnection(connectionString))
			{
				connection.Open();
				using (SqlTransaction transaction = connection.BeginTransaction(IsolationLevel.ReadCommitted))
				{
					DateTime now = GetServerTime(connection, transaction);
					foreach (CertificateRecord record in scanResult.Certificates)
					{
						if (string.IsNullOrEmpty(record.SerialNumber) || !savedSerialNumbers.Add(record.SerialNumber))
						{
							continue;
						}
						using (SqlCommand command = new SqlCommand(upsertSql, connection, transaction))
						{
							FillParameters(command, record, scanResult, now);
							bool wasInserted = Convert.ToInt32(command.ExecuteScalar()) == 1;
							if (wasInserted)
							{
								statistics.Inserted = statistics.Inserted + 1;
							}
							else
							{
								statistics.Updated = statistics.Updated + 1;
							}
						}
						if (!string.IsNullOrEmpty(scanResult.ComputerName))
						{
							foreach (string source in record.Sources)
							{
								SaveLocation(connection, transaction, upsertLocationSql, record.SerialNumber, scanResult, source, now);
							}
						}
					}
					if (!string.IsNullOrEmpty(scanResult.ComputerName))
					{
						statistics.MarkedMissing = MarkMissingCertificates(connection, transaction, scanResult, now);
					}
					transaction.Commit();
				}
			}
			Logger.Info("Результат сканирования " + scanResult.ComputerName + " записан в " + QuotedTableName + ": " + statistics);
			return statistics;
		}

		/// <summary>
		/// Возвращает текущее время сервера БД с точностью до миллисекунд — общее для всех строк одного сканирования.
		/// </summary>
		private static DateTime GetServerTime(SqlConnection connection, SqlTransaction transaction)
		{
			using (SqlCommand command = new SqlCommand("SELECT CAST(SYSDATETIME() AS DATETIME2(3))", connection, transaction))
			{
				return (DateTime)command.ExecuteScalar();
			}
		}

		/// <summary>
		/// Формирует SQL «обновить, а если строки нет — вставить» с блокировкой диапазона ключа,
		/// чтобы параллельные записи одного сертификата не создали дубль.
		/// </summary>
		private string BuildUpsertSql()
		{
			StringBuilder sql = new StringBuilder();
			sql.AppendLine("UPDATE " + QuotedTableName + " WITH (UPDLOCK, SERIALIZABLE) SET");
			sql.AppendLine("\t[UpdatedAt] = @Now, [LastSeenAt] = @Now, [IsMissing] = 0, [MissingSince] = NULL,");
			sql.AppendLine("\t[OwnerName] = @OwnerName, [CertificationAuthority] = @CertificationAuthority,");
			sql.AppendLine("\t[CryptoProLicenseVersion] = @CryptoProLicenseVersion, [HasEmbeddedCryptoProLicense] = @HasEmbeddedCryptoProLicense,");
			sql.AppendLine("\t[Thumbprint] = @Thumbprint, [ValidFrom] = @ValidFrom, [ValidTo] = @ValidTo, [OwnerInn] = @OwnerInn,");
			sql.AppendLine("\t[OwnerSnils] = @OwnerSnils, [OwnerOgrn] = @OwnerOgrn, [OwnerOrganization] = @OwnerOrganization, [OwnerTitle] = @OwnerTitle,");
			sql.AppendLine("\t[SubjectDn] = @SubjectDn, [IssuerDn] = @IssuerDn, [SignatureAlgorithm] = @SignatureAlgorithm,");
			sql.AppendLine("\t[CryptoProLicenseDetails] = @CryptoProLicenseDetails, [HasPrivateKey] = @HasPrivateKey, [ComputerName] = @ComputerName,");
			sql.AppendLine("\t[InstalledCryptoProVersion] = @InstalledCryptoProVersion, [InstalledCryptoProLicenseSerial] = @InstalledCryptoProLicenseSerial,");
			sql.AppendLine("\t[InstalledCryptoProLicenseValidity] = @InstalledCryptoProLicenseValidity, [CertificateSource] = @CertificateSource, [ScanMode] = @ScanMode");
			sql.AppendLine("WHERE [SerialNumber] = @SerialNumber;");
			sql.AppendLine("IF @@ROWCOUNT = 0");
			sql.AppendLine("BEGIN");
			sql.AppendLine("\tINSERT INTO " + QuotedTableName + " ([SerialNumber], [InsertedAt], [UpdatedAt], [LastSeenAt], [IsMissing], [OwnerName], [CertificationAuthority],");
			sql.AppendLine("\t\t[CryptoProLicenseVersion], [HasEmbeddedCryptoProLicense], [Thumbprint], [ValidFrom], [ValidTo], [OwnerInn], [OwnerSnils],");
			sql.AppendLine("\t\t[OwnerOgrn], [OwnerOrganization], [OwnerTitle], [SubjectDn], [IssuerDn], [SignatureAlgorithm], [CryptoProLicenseDetails],");
			sql.AppendLine("\t\t[HasPrivateKey], [ComputerName], [InstalledCryptoProVersion], [InstalledCryptoProLicenseSerial], [InstalledCryptoProLicenseValidity],");
			sql.AppendLine("\t\t[CertificateSource], [ScanMode])");
			sql.AppendLine("\tVALUES (@SerialNumber, @Now, @Now, @Now, 0, @OwnerName, @CertificationAuthority,");
			sql.AppendLine("\t\t@CryptoProLicenseVersion, @HasEmbeddedCryptoProLicense, @Thumbprint, @ValidFrom, @ValidTo, @OwnerInn, @OwnerSnils,");
			sql.AppendLine("\t\t@OwnerOgrn, @OwnerOrganization, @OwnerTitle, @SubjectDn, @IssuerDn, @SignatureAlgorithm, @CryptoProLicenseDetails,");
			sql.AppendLine("\t\t@HasPrivateKey, @ComputerName, @InstalledCryptoProVersion, @InstalledCryptoProLicenseSerial, @InstalledCryptoProLicenseValidity,");
			sql.AppendLine("\t\t@CertificateSource, @ScanMode);");
			sql.AppendLine("\tSELECT CAST(1 AS INT);");
			sql.AppendLine("END");
			sql.AppendLine("ELSE SELECT CAST(0 AS INT);");
			return sql.ToString();
		}

		/// <summary>
		/// Формирует SQL «обновить или вставить» для строки таблицы мест (ключ — серийный номер, ПК и хеш источника).
		/// </summary>
		private string BuildUpsertLocationSql()
		{
			StringBuilder sql = new StringBuilder();
			sql.AppendLine("UPDATE " + QuotedLocationsTableName + " WITH (UPDLOCK, SERIALIZABLE) SET");
			sql.AppendLine("\t[LastSeenAt] = @Now, [IsMissing] = 0, [MissingSince] = NULL, [Source] = @Source, [ScanMode] = @ScanMode");
			sql.AppendLine("WHERE [SerialNumber] = @SerialNumber AND [ComputerName] = @ComputerName AND [SourceHash] = @SourceHash;");
			sql.AppendLine("IF @@ROWCOUNT = 0");
			sql.AppendLine("\tINSERT INTO " + QuotedLocationsTableName + " ([SerialNumber], [ComputerName], [Source], [SourceHash], [FirstSeenAt], [LastSeenAt], [IsMissing], [ScanMode])");
			sql.AppendLine("\tVALUES (@SerialNumber, @ComputerName, @Source, @SourceHash, @Now, @Now, 0, @ScanMode);");
			return sql.ToString();
		}

		/// <summary>
		/// Записывает (или обновляет) одно место, где найден сертификат.
		/// </summary>
		private static void SaveLocation(SqlConnection connection, SqlTransaction transaction, string sql, string serialNumber,
			ScanResult scanResult, string source, DateTime now)
		{
			using (SqlCommand command = new SqlCommand(sql, connection, transaction))
			{
				AddText(command, "@SerialNumber", serialNumber, 128);
				AddText(command, "@ComputerName", scanResult.ComputerName, 256);
				AddText(command, "@Source", source, 1000);
				command.Parameters.Add("@SourceHash", SqlDbType.Binary, 32).Value = ComputeSourceHash(source);
				command.Parameters.Add("@Now", SqlDbType.DateTime2).Value = now;
				AddText(command, "@ScanMode", scanResult.ScanMode, 32);
				command.ExecuteNonQuery();
			}
		}

		/// <summary>
		/// SHA-256 от источника без учёта регистра: «C:\Certs\a.cer» и «c:\certs\A.CER» — одно место.
		/// </summary>
		public static byte[] ComputeSourceHash(string source)
		{
			using (SHA256 sha = SHA256.Create())
			{
				return sha.ComputeHash(Encoding.UTF8.GetBytes((source ?? string.Empty).ToUpperInvariant()));
			}
		}

		/// <summary>
		/// Помечает пропавшими места этого ПК, которые входили в область сканирования, но где сертификат не найден;
		/// затем помечает пропавшими сертификаты, у которых не осталось ни одного места. Возвращает число таких сертификатов.
		/// </summary>
		private int MarkMissingCertificates(SqlConnection connection, SqlTransaction transaction, ScanResult scanResult, DateTime now)
		{
			List<long> missingLocationIds = new List<long>();
			HashSet<string> affectedSerialNumbers = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
			string selectSql = "SELECT [Id], [SerialNumber], [Source] FROM " + QuotedLocationsTableName +
				" WHERE [ComputerName] = @ComputerName AND [IsMissing] = 0 AND [LastSeenAt] < @Now";
			using (SqlCommand command = new SqlCommand(selectSql, connection, transaction))
			{
				AddText(command, "@ComputerName", scanResult.ComputerName, 256);
				command.Parameters.Add("@Now", SqlDbType.DateTime2).Value = now;
				using (SqlDataReader reader = command.ExecuteReader())
				{
					while (reader.Read())
					{
						string source = reader.GetString(2);
						if (CertificateSources.IsCoveredByScan(source, scanResult))
						{
							missingLocationIds.Add(reader.GetInt64(0));
							affectedSerialNumbers.Add(reader.GetString(1));
						}
					}
				}
			}

			string markLocationSql = "UPDATE " + QuotedLocationsTableName + " SET [IsMissing] = 1, [MissingSince] = @Now WHERE [Id] = @Id";
			foreach (long locationId in missingLocationIds)
			{
				using (SqlCommand command = new SqlCommand(markLocationSql, connection, transaction))
				{
					command.Parameters.Add("@Id", SqlDbType.BigInt).Value = locationId;
					command.Parameters.Add("@Now", SqlDbType.DateTime2).Value = now;
					command.ExecuteNonQuery();
				}
			}

			int markedCertificates = 0;
			string markCertificateSql = "UPDATE " + QuotedTableName + " SET [IsMissing] = 1, [MissingSince] = @Now " +
				"WHERE [SerialNumber] = @SerialNumber AND [IsMissing] = 0 AND NOT EXISTS (SELECT 1 FROM " + QuotedLocationsTableName +
				" WHERE [SerialNumber] = @SerialNumber AND [IsMissing] = 0)";
			foreach (string serialNumber in affectedSerialNumbers)
			{
				using (SqlCommand command = new SqlCommand(markCertificateSql, connection, transaction))
				{
					AddText(command, "@SerialNumber", serialNumber, 128);
					command.Parameters.Add("@Now", SqlDbType.DateTime2).Value = now;
					markedCertificates = markedCertificates + command.ExecuteNonQuery();
				}
			}
			if (missingLocationIds.Count > 0)
			{
				Logger.Info("На ПК " + scanResult.ComputerName + " не найдены ранее учтённые сертификаты: мест " + missingLocationIds.Count
					+ ", сертификатов помечено пропавшими " + markedCertificates);
			}
			return markedCertificates;
		}

		/// <summary>
		/// Заполняет параметры команды значениями сертификата и сведениями о ПК.
		/// </summary>
		private static void FillParameters(SqlCommand command, CertificateRecord record, ScanResult scanResult, DateTime now)
		{
			command.Parameters.Add("@Now", SqlDbType.DateTime2).Value = now;
			AddText(command, "@SerialNumber", record.SerialNumber, 128);
			AddText(command, "@OwnerName", record.OwnerName, 512);
			AddText(command, "@CertificationAuthority", record.CertificationAuthority, 1000);
			AddText(command, "@CryptoProLicenseVersion", record.HasEmbeddedCryptoProLicense ? record.CryptoProLicenseVersion : null, 64);
			command.Parameters.Add("@HasEmbeddedCryptoProLicense", SqlDbType.Bit).Value = record.HasEmbeddedCryptoProLicense;
			AddText(command, "@Thumbprint", record.Thumbprint, 64);
			command.Parameters.Add("@ValidFrom", SqlDbType.DateTime2).Value = record.ValidFrom;
			command.Parameters.Add("@ValidTo", SqlDbType.DateTime2).Value = record.ValidTo;
			AddText(command, "@OwnerInn", record.OwnerInn, 16);
			AddText(command, "@OwnerSnils", record.OwnerSnils, 16);
			AddText(command, "@OwnerOgrn", record.OwnerOgrn, 16);
			AddText(command, "@OwnerOrganization", record.OwnerOrganization, 512);
			AddText(command, "@OwnerTitle", record.OwnerTitle, 256);
			AddText(command, "@SubjectDn", record.SubjectDn, 2000);
			AddText(command, "@IssuerDn", record.IssuerDn, 2000);
			AddText(command, "@SignatureAlgorithm", record.SignatureAlgorithm, 256);
			AddText(command, "@CryptoProLicenseDetails", record.CryptoProLicenseDetails, 1000);
			command.Parameters.Add("@HasPrivateKey", SqlDbType.Bit).Value = record.HasPrivateKey;
			AddText(command, "@ComputerName", scanResult.ComputerName, 256);
			CryptoProInfo cryptoPro = scanResult.CryptoPro ?? new CryptoProInfo();
			AddText(command, "@InstalledCryptoProVersion", cryptoPro.DisplayText, 256);
			AddText(command, "@InstalledCryptoProLicenseSerial", cryptoPro.IsInstalled ? cryptoPro.LicenseSerialMasked : null, 64);
			AddText(command, "@InstalledCryptoProLicenseValidity", cryptoPro.IsInstalled ? cryptoPro.LicenseValidity : null, 256);
			AddText(command, "@CertificateSource", record.SourcesText, 2000);
			AddText(command, "@ScanMode", scanResult.ScanMode, 32);
		}

		/// <summary>
		/// Добавляет текстовый параметр, обрезая значение до размера столбца; пустые значения записываются как NULL.
		/// </summary>
		private static void AddText(SqlCommand command, string name, string value, int maxLength)
		{
			SqlParameter parameter = command.Parameters.Add(name, SqlDbType.NVarChar, maxLength);
			if (string.IsNullOrEmpty(value))
			{
				parameter.Value = DBNull.Value;
				return;
			}
			parameter.Value = value.Length > maxLength ? value.Substring(0, maxLength) : value;
		}

		/// <summary>
		/// Загружает строки таблицы для просмотра в панели (с фильтром по подстроке и состоянию, с ограничением количества).
		/// Столбец FoundOnComputers — список ПК, где сертификат сейчас есть (по таблице мест).
		/// </summary>
		public DataTable LoadCertificates(string filterText, CertificateStatusFilter statusFilter, int maxRows)
		{
			string sql = "SELECT TOP (@MaxRows) c.[SerialNumber], c.[InsertedAt], c.[UpdatedAt], c.[OwnerName], c.[CertificationAuthority], " +
				"c.[CryptoProLicenseVersion], c.[HasEmbeddedCryptoProLicense], c.[IsMissing], c.[MissingSince], c.[LastSeenAt], c.[ValidFrom], c.[ValidTo], " +
				"c.[OwnerInn], c.[OwnerSnils], c.[OwnerOrganization], " +
				"STUFF((SELECT DISTINCT N', ' + l.[ComputerName] FROM " + QuotedLocationsTableName + " AS l " +
				"WHERE l.[SerialNumber] = c.[SerialNumber] AND l.[IsMissing] = 0 FOR XML PATH(''), TYPE).value('.', 'NVARCHAR(MAX)'), 1, 2, N'') AS [FoundOnComputers], " +
				"c.[ComputerName], c.[InstalledCryptoProVersion], c.[InstalledCryptoProLicenseSerial], c.[InstalledCryptoProLicenseValidity], " +
				"c.[Thumbprint], c.[SignatureAlgorithm], c.[CertificateSource] " +
				"FROM " + QuotedTableName + " AS c " +
				"WHERE (@Filter IS NULL OR c.[SerialNumber] LIKE @Filter OR c.[OwnerName] LIKE @Filter OR c.[CertificationAuthority] LIKE @Filter " +
				"OR c.[ComputerName] LIKE @Filter OR c.[OwnerInn] LIKE @Filter OR c.[OwnerOrganization] LIKE @Filter OR c.[Thumbprint] LIKE @Filter) " +
				BuildStatusCondition(statusFilter) +
				"ORDER BY c.[IsMissing], c.[UpdatedAt] DESC";
			using (SqlConnection connection = new SqlConnection(connectionString))
			using (SqlCommand command = new SqlCommand(sql, connection))
			{
				command.Parameters.Add("@MaxRows", SqlDbType.Int).Value = maxRows > 0 ? maxRows : 10000;
				SqlParameter filterParameter = command.Parameters.Add("@Filter", SqlDbType.NVarChar, 300);
				filterParameter.Value = string.IsNullOrWhiteSpace(filterText) ? (object)DBNull.Value : "%" + EscapeLike(filterText.Trim()) + "%";
				using (SqlDataAdapter adapter = new SqlDataAdapter(command))
				{
					DataTable table = new DataTable("Certificates");
					adapter.Fill(table);
					return table;
				}
			}
		}

		/// <summary>
		/// Загружает строки таблицы без фильтра по состоянию (совместимость с прежним вызовом).
		/// </summary>
		public DataTable LoadCertificates(string filterText, int maxRows)
		{
			return LoadCertificates(filterText, CertificateStatusFilter.All, maxRows);
		}

		/// <summary>
		/// Условие WHERE для фильтра по состоянию сертификата.
		/// </summary>
		private static string BuildStatusCondition(CertificateStatusFilter statusFilter)
		{
			switch (statusFilter)
			{
				case CertificateStatusFilter.Present:
					return "AND c.[IsMissing] = 0 ";
				case CertificateStatusFilter.Missing:
					return "AND c.[IsMissing] = 1 ";
				case CertificateStatusFilter.Expired:
					return "AND c.[ValidTo] < SYSDATETIME() ";
				default:
					return string.Empty;
			}
		}

		/// <summary>
		/// Возвращает все места, где был найден сертификат: ПК, источник, когда найден впервые и последний раз, пропал ли.
		/// </summary>
		public DataTable LoadLocations(string serialNumber)
		{
			string sql = "SELECT [ComputerName], [Source], [FirstSeenAt], [LastSeenAt], [IsMissing], [MissingSince], [ScanMode] FROM " +
				QuotedLocationsTableName + " WHERE [SerialNumber] = @SerialNumber ORDER BY [IsMissing], [ComputerName], [Source]";
			using (SqlConnection connection = new SqlConnection(connectionString))
			using (SqlCommand command = new SqlCommand(sql, connection))
			{
				AddText(command, "@SerialNumber", serialNumber, 128);
				using (SqlDataAdapter adapter = new SqlDataAdapter(command))
				{
					DataTable table = new DataTable("Locations");
					adapter.Fill(table);
					return table;
				}
			}
		}

		/// <summary>
		/// Возвращает общее число строк, число сертификатов со встроенной лицензией, истёкших и пропавших.
		/// </summary>
		public void GetSummary(out int totalCount, out int withLicenseCount, out int expiredCount, out int missingCount)
		{
			string sql = "SELECT COUNT(*), SUM(CASE WHEN [HasEmbeddedCryptoProLicense] = 1 THEN 1 ELSE 0 END), " +
				"SUM(CASE WHEN [ValidTo] < SYSDATETIME() THEN 1 ELSE 0 END), SUM(CASE WHEN [IsMissing] = 1 THEN 1 ELSE 0 END) FROM " + QuotedTableName;
			using (SqlConnection connection = new SqlConnection(connectionString))
			using (SqlCommand command = new SqlCommand(sql, connection))
			{
				connection.Open();
				using (SqlDataReader reader = command.ExecuteReader())
				{
					reader.Read();
					totalCount = reader.GetInt32(0);
					withLicenseCount = reader.IsDBNull(1) ? 0 : reader.GetInt32(1);
					expiredCount = reader.IsDBNull(2) ? 0 : reader.GetInt32(2);
					missingCount = reader.IsDBNull(3) ? 0 : reader.GetInt32(3);
				}
			}
		}

		/// <summary>
		/// Экранирует спецсимволы шаблона LIKE.
		/// </summary>
		private static string EscapeLike(string text)
		{
			return text.Replace("[", "[[]").Replace("%", "[%]").Replace("_", "[_]");
		}
	}
}
