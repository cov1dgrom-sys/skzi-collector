using System;
using System.Collections.Generic;
using System.Data;
using System.Drawing;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using Skzi.Common.Database;
using Skzi.Common.Logging;

namespace Skzi.ControlPanel
{
	/// <summary>
	/// Вкладка «Сертификаты в БД»: просмотр таблицы MSSQL, поиск, экспорт в CSV, создание таблицы.
	/// </summary>
	public sealed partial class MainForm
	{
		private const int MaxDatabaseRows = 10000;

		private static readonly Dictionary<string, string> DatabaseColumnHeaders = new Dictionary<string, string>
		{
			{ "SerialNumber", "Серийный номер" },
			{ "InsertedAt", "Дата и время внесения" },
			{ "UpdatedAt", "Дата и время обновления" },
			{ "OwnerName", "Имя владельца" },
			{ "CertificationAuthority", "Удостоверяющий центр" },
			{ "CryptoProLicenseVersion", "Версия лицензии КриптоПро" },
			{ "HasEmbeddedCryptoProLicense", "Лицензия встроена" },
			{ "IsMissing", "Пропал" },
			{ "MissingSince", "Не находится с" },
			{ "LastSeenAt", "Последний раз найден" },
			{ "FoundOnComputers", "Сейчас есть на ПК" },
			{ "ValidFrom", "Действует с" },
			{ "ValidTo", "Действует до" },
			{ "OwnerInn", "ИНН" },
			{ "OwnerSnils", "СНИЛС" },
			{ "OwnerOrganization", "Организация" },
			{ "ComputerName", "ПК" },
			{ "InstalledCryptoProVersion", "КриптоПро на ПК" },
			{ "InstalledCryptoProLicenseSerial", "Лицензия CSP на ПК (серийный №)" },
			{ "InstalledCryptoProLicenseValidity", "Срок лицензии CSP на ПК" },
			{ "Thumbprint", "Отпечаток" },
			{ "SignatureAlgorithm", "Алгоритм подписи" },
			{ "CertificateSource", "Где найден" }
		};

		private DataGridView databaseGrid;
		private ToolStripTextBox databaseFilterTextBox;
		private ToolStripComboBox databaseStatusComboBox;
		private Label databaseSummaryLabel;
		private bool databaseLoading;

		/// <summary>
		/// Строит вкладку просмотра таблицы БД.
		/// </summary>
		private void BuildDatabaseTab(TabPage page)
		{
			ToolStrip toolStrip = UiStyle.CreateToolStrip();
			toolStrip.Items.Add(UiStyle.CreateToolButton("Обновить", "Перечитать таблицу из БД", delegate { RefreshDatabaseView(); }));
			toolStrip.Items.Add(new ToolStripSeparator());
			toolStrip.Items.Add(new ToolStripLabel("Поиск:"));
			databaseFilterTextBox = new ToolStripTextBox();
			databaseFilterTextBox.AutoSize = false;
			databaseFilterTextBox.Width = 260;
			databaseFilterTextBox.ToolTipText = "Серийный номер, владелец, УЦ, ПК, ИНН, организация или отпечаток";
			databaseFilterTextBox.KeyDown += delegate (object sender, KeyEventArgs eventArgs)
			{
				if (eventArgs.KeyCode == Keys.Enter)
				{
					eventArgs.SuppressKeyPress = true;
					RefreshDatabaseView();
				}
			};
			toolStrip.Items.Add(databaseFilterTextBox);
			toolStrip.Items.Add(UiStyle.CreateToolButton("Найти", "Применить фильтр", delegate { RefreshDatabaseView(); }));
			toolStrip.Items.Add(UiStyle.CreateToolButton("Сбросить", "Показать все строки", delegate
			{
				databaseFilterTextBox.Text = string.Empty;
				databaseStatusComboBox.SelectedIndex = 0;
				RefreshDatabaseView();
			}));
			databaseStatusComboBox = new ToolStripComboBox();
			databaseStatusComboBox.DropDownStyle = ComboBoxStyle.DropDownList;
			databaseStatusComboBox.Items.AddRange(new object[] { "Все сертификаты", "Найденные", "Пропавшие", "Истёкшие" });
			databaseStatusComboBox.SelectedIndex = 0;
			databaseStatusComboBox.ToolTipText = "Показать сертификаты по состоянию";
			databaseStatusComboBox.SelectedIndexChanged += delegate { RefreshDatabaseView(); };
			toolStrip.Items.Add(databaseStatusComboBox);
			toolStrip.Items.Add(new ToolStripSeparator());
			toolStrip.Items.Add(UiStyle.CreateToolButton("Экспорт в CSV…", "Сохранить показанные строки в CSV (открывается в Excel)", OnExportCsvClick));
			toolStrip.Items.Add(UiStyle.CreateToolButton("Создать / проверить таблицу", "Создать БД и таблицу, если их нет, и добавить недостающие столбцы", OnEnsureTableClick));

			// Сводка — отдельной строкой под таблицей, чтобы не уходить в скрытую часть панели инструментов.
			databaseSummaryLabel = new Label();
			databaseSummaryLabel.Dock = DockStyle.Bottom;
			databaseSummaryLabel.Height = 26;
			databaseSummaryLabel.TextAlign = ContentAlignment.MiddleLeft;
			databaseSummaryLabel.Padding = new Padding(6, 0, 0, 0);
			databaseSummaryLabel.ForeColor = UiStyle.MutedText;
			databaseSummaryLabel.Text = "Двойной щелчок по строке — на каких ПК и где найден сертификат.";

			databaseGrid = new DataGridView();
			databaseGrid.Dock = DockStyle.Fill;
			UiStyle.ApplyGridStyle(databaseGrid);
			databaseGrid.AutoGenerateColumns = true;
			databaseGrid.DataBindingComplete += OnDatabaseGridBindingComplete;
			databaseGrid.CellFormatting += OnDatabaseGridCellFormatting;
			databaseGrid.CellDoubleClick += OnDatabaseRowDoubleClick;

			page.Controls.Add(databaseGrid);
			page.Controls.Add(databaseSummaryLabel);
			page.Controls.Add(toolStrip);
		}

		/// <summary>
		/// Загружает строки таблицы из БД в фоне и показывает их.
		/// </summary>
		private async void RefreshDatabaseView()
		{
			if (databaseLoading)
			{
				return;
			}
			databaseLoading = true;
			string filter = databaseFilterTextBox.Text;
			CertificateStatusFilter statusFilter = (CertificateStatusFilter)Math.Max(0, databaseStatusComboBox.SelectedIndex);
			SetStatus("Загрузка данных из БД…");
			Logger.Info("Обновление данных таблицы БД" + (string.IsNullOrWhiteSpace(filter) ? string.Empty : ", фильтр: «" + filter + "»"));
			try
			{
				CertificateRepository repository = coordinator.CreateRepository();
				DataTable table = null;
				int totalCount = 0;
				int withLicenseCount = 0;
				int expiredCount = 0;
				int missingCount = 0;
				await Task.Run(delegate
				{
					coordinator.EnsureDatabaseReady(repository);
					table = repository.LoadCertificates(filter, statusFilter, MaxDatabaseRows);
					repository.GetSummary(out totalCount, out withLicenseCount, out expiredCount, out missingCount);
				});
				databaseGrid.DataSource = table;
				databaseSummaryLabel.Text = "Всего в таблице: " + totalCount + "   ·   со встроенной лицензией: " + withLicenseCount
					+ "   ·   истёкших (красные): " + expiredCount + "   ·   пропавших (серые): " + missingCount + "   ·   показано: " + table.Rows.Count
					+ "   ·   двойной щелчок по строке — где найден сертификат";
				SetStatus("Загружено строк из БД: " + table.Rows.Count);
			}
			catch (Exception exception)
			{
				databaseSummaryLabel.Text = "Нет подключения к БД";
				Logger.Error("Не удалось загрузить данные из БД " + config.Database.Server + "/" + config.Database.DatabaseName, exception);
				SetStatus("Ошибка БД: " + exception.Message);
				if (mainTabs.SelectedTab == databaseTabPage)
				{
					MessageBox.Show(this, "Не удалось загрузить данные из БД:\n\n" + exception.Message + "\n\nПроверьте параметры на вкладке «Настройки».",
						"База данных", MessageBoxButtons.OK, MessageBoxIcon.Warning);
				}
			}
			finally
			{
				databaseLoading = false;
			}
		}

		/// <summary>
		/// После привязки данных задаёт русские заголовки и форматы дат.
		/// </summary>
		private void OnDatabaseGridBindingComplete(object sender, DataGridViewBindingCompleteEventArgs eventArgs)
		{
			foreach (DataGridViewColumn column in databaseGrid.Columns)
			{
				string header;
				if (DatabaseColumnHeaders.TryGetValue(column.DataPropertyName, out header))
				{
					column.HeaderText = header;
				}
				column.Width = 140;
				if (column.DataPropertyName == "InsertedAt" || column.DataPropertyName == "UpdatedAt"
					|| column.DataPropertyName == "MissingSince" || column.DataPropertyName == "LastSeenAt")
				{
					column.DefaultCellStyle.Format = "dd.MM.yyyy HH:mm:ss.fff";
					column.Width = 170;
				}
				else if (column.DataPropertyName == "IsMissing" || column.DataPropertyName == "HasEmbeddedCryptoProLicense")
				{
					column.Width = 80;
				}
				else if (column.DataPropertyName == "ValidFrom" || column.DataPropertyName == "ValidTo")
				{
					column.DefaultCellStyle.Format = "dd.MM.yyyy";
					column.Width = 95;
				}
				else if (column.DataPropertyName == "SerialNumber" || column.DataPropertyName == "Thumbprint")
				{
					column.Width = 240;
				}
				else if (column.DataPropertyName == "CertificateSource")
				{
					column.Width = 400;
				}
				else if (column.DataPropertyName == "OwnerName")
				{
					column.Width = 200;
				}
				else if (column.DataPropertyName == "CertificationAuthority")
				{
					column.Width = 320;
				}
			}
		}

		/// <summary>
		/// Подсвечивает истёкшие сертификаты (красный фон) и пропавшие (серый курсив, «Пропал» — красным).
		/// </summary>
		private void OnDatabaseGridCellFormatting(object sender, DataGridViewCellFormattingEventArgs eventArgs)
		{
			if (eventArgs.RowIndex < 0 || !databaseGrid.Columns.Contains("ValidTo"))
			{
				return;
			}
			DataGridViewRow row = databaseGrid.Rows[eventArgs.RowIndex];
			object validTo = row.Cells["ValidTo"].Value;
			if (validTo is DateTime && (DateTime)validTo < DateTime.Now)
			{
				eventArgs.CellStyle.BackColor = UiStyle.ExpiredRow;
			}
			if (!databaseGrid.Columns.Contains("IsMissing"))
			{
				return;
			}
			object isMissing = row.Cells["IsMissing"].Value;
			if (isMissing is bool && (bool)isMissing)
			{
				eventArgs.CellStyle.ForeColor = UiStyle.MutedText;
				eventArgs.CellStyle.Font = MissingRowFont;
				if (databaseGrid.Columns[eventArgs.ColumnIndex].DataPropertyName == "IsMissing")
				{
					eventArgs.CellStyle.ForeColor = UiStyle.ErrorText;
				}
			}
		}

		private static readonly Font MissingRowFont = new Font(UiStyle.BaseFont, FontStyle.Italic);

		/// <summary>
		/// Двойной щелчок по строке — где найден сертификат: все ПК и места, когда найден впервые и последний раз.
		/// </summary>
		private async void OnDatabaseRowDoubleClick(object sender, DataGridViewCellEventArgs eventArgs)
		{
			if (eventArgs.RowIndex < 0 || !databaseGrid.Columns.Contains("SerialNumber"))
			{
				return;
			}
			string serialNumber = Convert.ToString(databaseGrid.Rows[eventArgs.RowIndex].Cells["SerialNumber"].Value);
			if (string.IsNullOrEmpty(serialNumber))
			{
				return;
			}
			Logger.Info("Открыто окно «Где найден сертификат " + serialNumber + "»");
			try
			{
				CertificateRepository repository = coordinator.CreateRepository();
				DataTable locations = await Task.Run(() => repository.LoadLocations(serialNumber));
				using (TextViewerDialog dialog = new TextViewerDialog("Где найден сертификат " + serialNumber, BuildLocationsText(serialNumber, locations)))
				{
					dialog.ShowDialog(this);
				}
			}
			catch (Exception exception)
			{
				ShowError("Не удалось загрузить места сертификата " + serialNumber, exception);
			}
		}

		/// <summary>
		/// Формирует текст со списком мест сертификата.
		/// </summary>
		private static string BuildLocationsText(string serialNumber, DataTable locations)
		{
			StringBuilder builder = new StringBuilder();
			builder.AppendLine("Сертификат " + serialNumber + " — мест: " + locations.Rows.Count);
			builder.AppendLine();
			if (locations.Rows.Count == 0)
			{
				builder.AppendLine("Сведений о местах нет (сертификат записан до появления учёта мест — просканируйте ПК ещё раз).");
			}
			foreach (DataRow row in locations.Rows)
			{
				bool isMissing = row["IsMissing"] is bool && (bool)row["IsMissing"];
				builder.AppendLine((isMissing ? "[ПРОПАЛ] " : "[есть]   ") + row["ComputerName"] + " — " + row["Source"]);
				builder.AppendLine("          впервые: " + FormatDatabaseDate(row["FirstSeenAt"]) + ", последний раз: " + FormatDatabaseDate(row["LastSeenAt"])
					+ (isMissing ? ", не находится с " + FormatDatabaseDate(row["MissingSince"]) : string.Empty)
					+ (row["ScanMode"] == DBNull.Value ? string.Empty : ", способ: " + row["ScanMode"]));
			}
			return builder.ToString();
		}

		/// <summary>
		/// Форматирует дату из БД с миллисекундами (пустая строка для NULL).
		/// </summary>
		private static string FormatDatabaseDate(object value)
		{
			return value is DateTime ? ((DateTime)value).ToString("dd.MM.yyyy HH:mm:ss.fff") : "—";
		}

		/// <summary>
		/// Создание БД и таблицы по кнопке (если их нет) и добавление недостающих столбцов.
		/// </summary>
		private async void OnEnsureTableClick(object sender, EventArgs eventArgs)
		{
			Logger.Info("Выбран пункт «Создать / проверить таблицу»");
			SetStatus("Проверка таблицы в БД…");
			try
			{
				CertificateRepository repository = coordinator.CreateRepository();
				bool created = false;
				bool createDatabase = config.Database.CreateDatabaseIfMissing;
				await Task.Run(delegate
				{
					if (createDatabase)
					{
						repository.EnsureDatabaseExists();
					}
					created = repository.EnsureTableExists();
				});
				string message = created
					? "Таблица " + repository.QuotedTableName + " создана."
					: "Таблица " + repository.QuotedTableName + " уже существует, структура проверена.";
				SetStatus(message);
				MessageBox.Show(this, message, "База данных", MessageBoxButtons.OK, MessageBoxIcon.Information);
				RefreshDatabaseView();
			}
			catch (Exception exception)
			{
				ShowError("Не удалось создать или проверить таблицу", exception);
			}
		}

		/// <summary>
		/// Экспорт показанных строк в CSV (разделитель «;», UTF-8 с BOM — корректно открывается в Excel).
		/// </summary>
		private void OnExportCsvClick(object sender, EventArgs eventArgs)
		{
			Logger.Info("Выбран пункт «Экспорт в CSV»");
			DataTable table = databaseGrid.DataSource as DataTable;
			if (table == null || table.Rows.Count == 0)
			{
				MessageBox.Show(this, "Нет данных для экспорта. Нажмите «Обновить».", "Экспорт", MessageBoxButtons.OK, MessageBoxIcon.Information);
				return;
			}
			using (SaveFileDialog dialog = new SaveFileDialog())
			{
				dialog.Filter = "CSV (*.csv)|*.csv";
				dialog.FileName = "skzi_certificates_" + DateTime.Now.ToString("yyyyMMdd_HHmm") + ".csv";
				if (dialog.ShowDialog(this) != DialogResult.OK)
				{
					return;
				}
				try
				{
					WriteCsv(table, dialog.FileName);
					Logger.Info("Экспортировано строк в CSV: " + table.Rows.Count + " → " + dialog.FileName);
					SetStatus("Экспортировано строк: " + table.Rows.Count);
				}
				catch (Exception exception)
				{
					ShowError("Не удалось сохранить CSV", exception);
				}
			}
		}

		/// <summary>
		/// Записывает таблицу в CSV-файл с русскими заголовками.
		/// </summary>
		private static void WriteCsv(DataTable table, string filePath)
		{
			StringBuilder builder = new StringBuilder();
			List<string> headers = new List<string>();
			foreach (DataColumn column in table.Columns)
			{
				string header;
				headers.Add(EscapeCsv(DatabaseColumnHeaders.TryGetValue(column.ColumnName, out header) ? header : column.ColumnName));
			}
			builder.AppendLine(string.Join(";", headers));
			foreach (DataRow row in table.Rows)
			{
				List<string> values = new List<string>();
				foreach (DataColumn column in table.Columns)
				{
					object value = row[column];
					string text;
					if (value == DBNull.Value)
					{
						text = string.Empty;
					}
					else if (value is DateTime)
					{
						text = ((DateTime)value).ToString("dd.MM.yyyy HH:mm:ss.fff");
					}
					else if (value is bool)
					{
						text = (bool)value ? "Да" : "Нет";
					}
					else
					{
						text = Convert.ToString(value);
					}
					values.Add(EscapeCsv(text));
				}
				builder.AppendLine(string.Join(";", values));
			}
			File.WriteAllText(filePath, builder.ToString(), new UTF8Encoding(true));
		}

		/// <summary>
		/// Экранирует значение для CSV (кавычки, разделители, переводы строк).
		/// </summary>
		private static string EscapeCsv(string value)
		{
			if (value == null)
			{
				return string.Empty;
			}
			if (value.IndexOfAny(new[] { ';', '"', '\r', '\n' }) >= 0)
			{
				return "\"" + value.Replace("\"", "\"\"") + "\"";
			}
			return value;
		}
	}
}
