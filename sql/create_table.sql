/*
	Модуль сбора данных о СКЗИ (кейс №03, ФГУП «ГРЧЦ»), команда Red Flag.
	Справочный скрипт: та же структура, которую программа создаёт автоматически,
	если таблиц нет (CertificateRepository.EnsureTableExists). Запускать вручную не обязательно.
	Если таблица уже есть (например, создана по старой схеме), программа сама добавит недостающие столбцы.
*/

IF DB_ID(N'SkziInventory') IS NULL
	CREATE DATABASE [SkziInventory];
GO

USE [SkziInventory];
GO

IF OBJECT_ID(N'[dbo].[SkziCertificates]', N'U') IS NULL
BEGIN
	CREATE TABLE [dbo].[SkziCertificates] (
		-- Обязательные поля по п. 4.1 задания
		[Id]                                BIGINT IDENTITY(1,1) NOT NULL,
		[SerialNumber]                      NVARCHAR(128)  NOT NULL,   -- Серийный номер сертификата
		[InsertedAt]                        DATETIME2(3)   NOT NULL,   -- Дата и время внесения в таблицу
		[UpdatedAt]                         DATETIME2(3)   NOT NULL,   -- Дата и время обновления (= InsertedAt при первой записи)
		[OwnerName]                         NVARCHAR(512)  NULL,       -- Имя владельца (ФИО)
		[CertificationAuthority]            NVARCHAR(1000) NULL,       -- Удостоверяющий центр (полное имя издателя)
		[CryptoProLicenseVersion]           NVARCHAR(64)   NULL,       -- Версия КриптоПро CSP, если в сертификате лицензия
		[HasEmbeddedCryptoProLicense]       BIT            NOT NULL CONSTRAINT [DF_SkziCertificates_HasEmbeddedCryptoProLicense] DEFAULT (0),
		-- Пропавшие сертификаты: строки не удаляются, а помечаются
		[IsMissing]                         BIT            NOT NULL CONSTRAINT [DF_SkziCertificates_IsMissing] DEFAULT (0), -- 1 — больше нигде не найден
		[MissingSince]                      DATETIME2(3)   NULL,       -- С какого сканирования не находится
		[LastSeenAt]                        DATETIME2(3)   NULL,       -- Когда последний раз найден
		-- Расширенные сведения
		[Thumbprint]                        NVARCHAR(64)   NULL,
		[ValidFrom]                         DATETIME2(0)   NULL,
		[ValidTo]                           DATETIME2(0)   NULL,
		[OwnerInn]                          NVARCHAR(16)   NULL,
		[OwnerSnils]                        NVARCHAR(16)   NULL,
		[OwnerOgrn]                         NVARCHAR(16)   NULL,
		[OwnerOrganization]                 NVARCHAR(512)  NULL,
		[OwnerTitle]                        NVARCHAR(256)  NULL,
		[SubjectDn]                         NVARCHAR(2000) NULL,
		[IssuerDn]                          NVARCHAR(2000) NULL,
		[SignatureAlgorithm]                NVARCHAR(256)  NULL,
		[CryptoProLicenseDetails]           NVARCHAR(1000) NULL,
		[HasPrivateKey]                     BIT            NULL,
		[ComputerName]                      NVARCHAR(256)  NULL,       -- ПК, где найден при последнем сканировании
		[InstalledCryptoProVersion]         NVARCHAR(256)  NULL,       -- КриптоПро CSP на этом ПК
		[InstalledCryptoProLicenseSerial]   NVARCHAR(64)   NULL,       -- Серийный номер лицензии CSP на ПК (замаскирован), ответ 5.4
		[InstalledCryptoProLicenseValidity] NVARCHAR(256)  NULL,       -- Срок действия лицензии CSP на ПК, ответ 5.4
		[CertificateSource]                 NVARCHAR(2000) NULL,       -- Файл / хранилище / контейнер
		[ScanMode]                          NVARCHAR(32)   NULL,       -- Agent / Agentless / Local
		CONSTRAINT [PK_SkziCertificates] PRIMARY KEY CLUSTERED ([Id]),
		-- Гарантия отсутствия дублей по серийному номеру (п. 4.2)
		CONSTRAINT [UQ_SkziCertificates_SerialNumber] UNIQUE ([SerialNumber])
	);
END
GO

-- Места «сертификат — ПК — источник»: на каких ПК и где именно найден сертификат
IF OBJECT_ID(N'[dbo].[SkziCertificatesLocations]', N'U') IS NULL
BEGIN
	CREATE TABLE [dbo].[SkziCertificatesLocations] (
		[Id]           BIGINT IDENTITY(1,1) NOT NULL,
		[SerialNumber] NVARCHAR(128)  NOT NULL,   -- Серийный номер сертификата
		[ComputerName] NVARCHAR(256)  NOT NULL,   -- ПК
		[Source]       NVARCHAR(1000) NOT NULL,   -- «Файл: C:\...», «Личное хранилище ...», «Контейнер КриптоПро: ...»
		[SourceHash]   BINARY(32)     NOT NULL,   -- SHA-256 от источника (для уникального индекса)
		[FirstSeenAt]  DATETIME2(3)   NOT NULL,
		[LastSeenAt]   DATETIME2(3)   NOT NULL,
		[IsMissing]    BIT            NOT NULL CONSTRAINT [DF_SkziCertificatesLocations_IsMissing] DEFAULT (0),
		[MissingSince] DATETIME2(3)   NULL,
		[ScanMode]     NVARCHAR(32)   NULL,
		CONSTRAINT [PK_SkziCertificatesLocations] PRIMARY KEY CLUSTERED ([Id]),
		CONSTRAINT [UQ_SkziCertificatesLocations_Place] UNIQUE ([SerialNumber], [ComputerName], [SourceHash])
	);
	CREATE INDEX [IX_SkziCertificatesLocations_Computer] ON [dbo].[SkziCertificatesLocations] ([ComputerName], [IsMissing]);
END
GO

/*
	Как программа записывает результат сканирования одного ПК (одна транзакция, одно время @Now = SYSDATETIME() сервера БД):
	1) для каждого сертификата — «обновить, а если строки нет — вставить» с блокировкой ключа (п. 4.2, без дублей);
	2) для каждого места (ПК + файл/хранилище/контейнер) — то же в таблице мест;
	3) места этого ПК, которые входили в область сканирования (просмотренные папки, хранилища, контейнеры),
	   но где сертификат не найден, помечаются IsMissing = 1; сертификат помечается пропавшим,
	   когда у него не осталось ни одного места с IsMissing = 0. Если сертификат снова найден — отметка снимается.
*/

-- Полезные запросы
-- Сертификаты со встроенной лицензией КриптоПро:
-- SELECT SerialNumber, OwnerName, CertificationAuthority, CryptoProLicenseVersion, ComputerName FROM dbo.SkziCertificates WHERE HasEmbeddedCryptoProLicense = 1;
-- Пропавшие сертификаты:
-- SELECT SerialNumber, OwnerName, MissingSince, ComputerName, CertificateSource FROM dbo.SkziCertificates WHERE IsMissing = 1 ORDER BY MissingSince DESC;
-- На каких ПК есть сертификат:
-- SELECT ComputerName, Source, FirstSeenAt, LastSeenAt FROM dbo.SkziCertificatesLocations WHERE SerialNumber = N'03A14016' AND IsMissing = 0;
-- Истекающие в ближайшие 30 дней:
-- SELECT SerialNumber, OwnerName, ValidTo, ComputerName FROM dbo.SkziCertificates WHERE ValidTo BETWEEN SYSDATETIME() AND DATEADD(DAY, 30, SYSDATETIME()) ORDER BY ValidTo;
-- КриптоПро и лицензии по ПК:
-- SELECT ComputerName, MAX(InstalledCryptoProVersion) AS CryptoPro, MAX(InstalledCryptoProLicenseSerial) AS LicenseSerial,
--        MAX(InstalledCryptoProLicenseValidity) AS LicenseValidity, COUNT(*) AS Certificates FROM dbo.SkziCertificates GROUP BY ComputerName;
