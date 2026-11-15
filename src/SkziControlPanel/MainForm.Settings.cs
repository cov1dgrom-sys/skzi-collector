using System;
using System.Collections.Generic;
using System.Drawing;
using System.Security.Cryptography;
using System.Threading.Tasks;
using System.Windows.Forms;
using Skzi.Common.Configuration;
using Skzi.Common.Database;
using Skzi.Common.Logging;

namespace Skzi.ControlPanel
{
	/// <summary>
	/// Вкладка «Настройки»: подключение к MSSQL, параметры агентов, директории и правила сканирования.
	/// </summary>
	public sealed partial class MainForm
	{
		private ComboBox serverComboBox;
		private TextBox databaseNameTextBox;
		private CheckBox windowsAuthenticationCheckBox;
		private TextBox userNameTextBox;
		private TextBox passwordTextBox;
		private TextBox tableNameTextBox;
		private CheckBox createDatabaseCheckBox;
		private CheckBox saveAfterScanCheckBox;
		private NumericUpDown agentPortNumeric;
		private TextBox sharedKeyTextBox;
		private NumericUpDown agentTimeoutNumeric;
		private NumericUpDown parallelScansNumeric;
		private CheckBox sendDirectoriesCheckBox;
		private CheckBox agentsUseOnlyPanelDirectoriesCheckBox;
		private TextBox agentInstallPathTextBox;
		private DataGridView directoriesGrid;
		private TextBox extensionsTextBox;
		private CheckBox scanStoresCheckBox;
		private CheckBox scanContainersCheckBox;
		private NumericUpDown maxFileSizeNumeric;
		private Label pfxPasswordsLabel;
		private List<string> pendingPfxPasswords = new List<string>();
		private TextBox logDirectoryTextBox;
		private NumericUpDown logRetentionNumeric;
		private NumericUpDown logMaxSizeNumeric;

		/// <summary>
		/// Строит вкладку настроек: две колонки групп и кнопки сохранения.
		/// </summary>
		private void BuildSettingsTab(TabPage page)
		{
			page.AutoScroll = true;
			TableLayoutPanel columns = new TableLayoutPanel();
			columns.Dock = DockStyle.Fill;
			columns.ColumnCount = 2;
			columns.RowCount = 2;
			columns.Padding = new Padding(8);
			columns.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50F));
			columns.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50F));
			columns.RowStyles.Add(new RowStyle(SizeType.Percent, 100F));
			columns.RowStyles.Add(new RowStyle(SizeType.Absolute, 48F));

			FlowLayoutPanel leftColumn = new FlowLayoutPanel();
			leftColumn.Dock = DockStyle.Fill;
			leftColumn.FlowDirection = FlowDirection.TopDown;
			leftColumn.WrapContents = false;
			leftColumn.AutoScroll = true;
			leftColumn.Controls.Add(BuildDatabaseGroup());
			leftColumn.Controls.Add(BuildAgentGroup());
			leftColumn.Controls.Add(BuildLogGroup());

			columns.Controls.Add(leftColumn, 0, 0);
			columns.Controls.Add(BuildScanGroup(), 1, 0);

			FlowLayoutPanel buttonPanel = new FlowLayoutPanel();
			buttonPanel.Dock = DockStyle.Fill;
			buttonPanel.FlowDirection = FlowDirection.LeftToRight;
			Button saveButton = new Button();
			saveButton.Text = "Сохранить настройки";
			saveButton.Font = UiStyle.BoldFont;
			saveButton.Size = new Size(190, 32);
			saveButton.Click += OnSaveSettingsClick;
			Button revertButton = new Button();
			revertButton.Text = "Отменить изменения";
			revertButton.Size = new Size(170, 32);
			revertButton.Click += delegate
			{
				LoadSettingsToControls();
				Logger.Info("Изменения настроек отменены");
			};
			Label configPathLabel = new Label();
			configPathLabel.AutoSize = true;
			configPathLabel.ForeColor = UiStyle.MutedText;
			configPathLabel.Padding = new Padding(10, 9, 0, 0);
			configPathLabel.Text = "Файл конфигурации: " + configPath;
			buttonPanel.Controls.Add(saveButton);
			buttonPanel.Controls.Add(revertButton);
			buttonPanel.Controls.Add(configPathLabel);
			columns.Controls.Add(buttonPanel, 0, 1);
			columns.SetColumnSpan(buttonPanel, 2);

			page.Controls.Add(columns);
		}

		/// <summary>
		/// Группа «Подключение к MSSQL».
		/// </summary>
		private GroupBox BuildDatabaseGroup()
		{
			TableLayoutPanel layout = CreateFormLayout();
			serverComboBox = new ComboBox();
			serverComboBox.DropDownStyle = ComboBoxStyle.DropDown;
			serverComboBox.Dock = DockStyle.Fill;
			foreach (string server in SqlServerLocator.FindLocalServers())
			{
				serverComboBox.Items.Add(server);
			}
			AddRow(layout, "Сервер MSSQL:", serverComboBox,
				"В списке — экземпляры SQL Server, найденные на этом ПК. Можно ввести вручную: localhost\\SQLEXPRESS, (localdb)\\MSSQLLocalDB, 10.0.0.5,1433");
			databaseNameTextBox = AddTextRow(layout, "База данных:", "Создаётся автоматически, если её нет (при включённом флажке ниже)");
			windowsAuthenticationCheckBox = AddCheckRow(layout, "Проверка подлинности Windows");
			windowsAuthenticationCheckBox.CheckedChanged += delegate { UpdateAuthenticationControls(); };
			userNameTextBox = AddTextRow(layout, "Логин SQL:", null);
			passwordTextBox = AddTextRow(layout, "Пароль SQL:", "Хранится в конфигурации в зашифрованном виде (DPAPI)");
			passwordTextBox.UseSystemPasswordChar = true;
			tableNameTextBox = AddTextRow(layout, "Таблица:", "Формат: схема.таблица (латиница). Создаётся, если её нет");
			createDatabaseCheckBox = AddCheckRow(layout, "Создавать базу данных, если её нет");
			saveAfterScanCheckBox = AddCheckRow(layout, "Записывать результаты в БД сразу после сканирования");

			FlowLayoutPanel buttons = new FlowLayoutPanel();
			buttons.AutoSize = true;
			buttons.Dock = DockStyle.Fill;
			Button testButton = new Button();
			testButton.Text = "Проверить подключение";
			testButton.AutoSize = true;
			testButton.Click += OnTestConnectionClick;
			buttons.Controls.Add(testButton);
			layout.Controls.Add(buttons, 1, layout.RowCount);
			layout.RowCount = layout.RowCount + 1;

			return WrapInGroup("Подключение к MSSQL", layout, 560);
		}

		/// <summary>
		/// Группа «Агенты на ПК».
		/// </summary>
		private GroupBox BuildAgentGroup()
		{
			TableLayoutPanel layout = CreateFormLayout();
			agentPortNumeric = AddNumericRow(layout, "Порт агентов (TCP):", 1, 65535);
			sharedKeyTextBox = AddTextRow(layout, "Общий ключ:", "Должен совпадать с SharedKey в agent.config.xml на ПК");
			sharedKeyTextBox.UseSystemPasswordChar = true;

			FlowLayoutPanel keyButtons = new FlowLayoutPanel();
			keyButtons.AutoSize = true;
			keyButtons.Dock = DockStyle.Fill;
			CheckBox showKeyCheckBox = new CheckBox();
			showKeyCheckBox.Text = "Показать";
			showKeyCheckBox.AutoSize = true;
			showKeyCheckBox.CheckedChanged += delegate { sharedKeyTextBox.UseSystemPasswordChar = !showKeyCheckBox.Checked; };
			Button generateKeyButton = new Button();
			generateKeyButton.Text = "Сгенерировать новый";
			generateKeyButton.AutoSize = true;
			generateKeyButton.Click += delegate
			{
				sharedKeyTextBox.Text = GenerateSharedKey();
				Logger.Info("Сгенерирован новый общий ключ агентов (не забудьте сохранить и переустановить агенты)");
			};
			keyButtons.Controls.Add(showKeyCheckBox);
			keyButtons.Controls.Add(generateKeyButton);
			layout.Controls.Add(keyButtons, 1, layout.RowCount);
			layout.RowCount = layout.RowCount + 1;

			agentTimeoutNumeric = AddNumericRow(layout, "Таймаут ответа агента, с:", 10, 3600);
			parallelScansNumeric = AddNumericRow(layout, "Сканировать параллельно, ПК:", 1, 64);
			sendDirectoriesCheckBox = AddCheckRow(layout, "Передавать агентам папки для поиска из панели");
			agentsUseOnlyPanelDirectoriesCheckBox = AddCheckRow(layout, "Агенты ищут только в этих папках (без папок из agent.config.xml)");
			sendDirectoriesCheckBox.CheckedChanged += delegate { agentsUseOnlyPanelDirectoriesCheckBox.Enabled = sendDirectoriesCheckBox.Checked; };
			agentInstallPathTextBox = AddTextRow(layout, "Папка установки агента:", "Используется при установке агента из панели (через \\\\ПК\\C$)");
			return WrapInGroup("Агенты на ПК", layout, 560);
		}

		/// <summary>
		/// Группа «Журнал»: папка, срок хранения и размер файлов (ротация).
		/// </summary>
		private GroupBox BuildLogGroup()
		{
			TableLayoutPanel layout = CreateFormLayout();
			logDirectoryTextBox = AddTextRow(layout, "Папка журналов:", "Относительно папки программы или полный путь. Формат строки: «16.09.25 08:43:23.739 - [INFO] текст»");
			logRetentionNumeric = AddNumericRow(layout, "Хранить журналы, суток:", 0, 3650);
			logMaxSizeNumeric = AddNumericRow(layout, "Макс. размер файла, МБ:", 0, 1024);
			Label hintLabel = new Label();
			hintLabel.AutoSize = true;
			hintLabel.ForeColor = UiStyle.MutedText;
			hintLabel.Text = "Новый файл — каждые сутки и при превышении размера; 0 — без ограничения.";
			layout.Controls.Add(hintLabel, 1, layout.RowCount);
			layout.RowCount = layout.RowCount + 1;
			return WrapInGroup("Журнал", layout, 560);
		}

		/// <summary>
		/// Группа «Сканирование»: директории, расширения, хранилища, размер файлов.
		/// </summary>
		private GroupBox BuildScanGroup()
		{
			Label directoriesLabel = new Label();
			directoriesLabel.Text = "Директории для сканирования (маски: C:\\Users\\*\\Desktop; переменные: %USERPROFILE% — только локально и в агенте):";
			directoriesLabel.Dock = DockStyle.Top;
			directoriesLabel.Height = 36;

			directoriesGrid = new DataGridView();
			directoriesGrid.Dock = DockStyle.Fill;
			directoriesGrid.AllowUserToAddRows = true;
			directoriesGrid.AllowUserToDeleteRows = true;
			directoriesGrid.RowHeadersWidth = 28;
			directoriesGrid.BackgroundColor = SystemColors.Window;
			directoriesGrid.ColumnHeadersHeightSizeMode = DataGridViewColumnHeadersHeightSizeMode.AutoSize;
			DataGridViewTextBoxColumn pathColumn = new DataGridViewTextBoxColumn();
			pathColumn.Name = "Path";
			pathColumn.HeaderText = "Путь";
			pathColumn.AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill;
			DataGridViewCheckBoxColumn recursiveColumn = new DataGridViewCheckBoxColumn();
			recursiveColumn.Name = "Recursive";
			recursiveColumn.HeaderText = "С подпапками";
			recursiveColumn.Width = 100;
			directoriesGrid.Columns.Add(pathColumn);
			directoriesGrid.Columns.Add(recursiveColumn);
			directoriesGrid.DefaultValuesNeeded += delegate (object sender, DataGridViewRowEventArgs eventArgs)
			{
				eventArgs.Row.Cells["Recursive"].Value = true;
			};

			FlowLayoutPanel directoryButtons = new FlowLayoutPanel();
			directoryButtons.Dock = DockStyle.Bottom;
			directoryButtons.Height = 36;
			Button browseButton = new Button();
			browseButton.Text = "Добавить папку…";
			browseButton.AutoSize = true;
			browseButton.Click += OnBrowseDirectoryClick;
			Button removeButton = new Button();
			removeButton.Text = "Удалить выбранные";
			removeButton.AutoSize = true;
			removeButton.Click += delegate
			{
				foreach (DataGridViewRow row in directoriesGrid.SelectedRows)
				{
					if (!row.IsNewRow)
					{
						directoriesGrid.Rows.Remove(row);
					}
				}
			};
			directoryButtons.Controls.Add(browseButton);
			directoryButtons.Controls.Add(removeButton);

			TableLayoutPanel optionsLayout = CreateFormLayout();
			optionsLayout.Dock = DockStyle.Bottom;
			extensionsTextBox = AddTextRow(optionsLayout, "Расширения файлов:", "Через «;», например: .cer;.crt;.der;.pem;.p7b;.p12;.pfx");
			maxFileSizeNumeric = AddNumericRow(optionsLayout, "Макс. размер файла, КБ:", 1, 102400);
			scanStoresCheckBox = AddCheckRow(optionsLayout, "Хранилища «Личное» всех пользователей");
			scanContainersCheckBox = AddCheckRow(optionsLayout, "Контейнеры КриптоПро (реестр, флешки, токены)");
			ToolTip scanHints = new ToolTip();
			scanHints.SetToolTip(scanStoresCheckBox, "Хранилища «Личное» всех пользователей ПК (в том числе не вошедших в систему) и хранилище компьютера");
			scanHints.SetToolTip(scanContainersCheckBox, "Сертификаты, записанные в ключевые контейнеры КриптоПро CSP. Проверяются агентом на ПК и в режиме «Этот ПК»; PIN-код не запрашивается");

			FlowLayoutPanel pfxPanel = new FlowLayoutPanel();
			pfxPanel.AutoSize = true;
			pfxPanel.Dock = DockStyle.Fill;
			Button pfxButton = new Button();
			pfxButton.Text = "Пароли для .p12/.pfx…";
			pfxButton.AutoSize = true;
			pfxButton.Click += OnPfxPasswordsClick;
			pfxPasswordsLabel = new Label();
			pfxPasswordsLabel.AutoSize = true;
			pfxPasswordsLabel.ForeColor = UiStyle.MutedText;
			pfxPasswordsLabel.Margin = new Padding(6, 8, 3, 3);
			pfxPanel.Controls.Add(pfxButton);
			pfxPanel.Controls.Add(pfxPasswordsLabel);
			optionsLayout.Controls.Add(pfxPanel, 1, optionsLayout.RowCount);
			optionsLayout.RowCount = optionsLayout.RowCount + 1;

			Panel container = new Panel();
			container.Dock = DockStyle.Fill;
			container.Padding = new Padding(8, 22, 8, 8);
			container.Controls.Add(directoriesGrid);
			container.Controls.Add(directoryButtons);
			container.Controls.Add(optionsLayout);
			container.Controls.Add(directoriesLabel);

			GroupBox group = new GroupBox();
			group.Text = "Сканирование";
			group.Dock = DockStyle.Fill;
			group.Font = UiStyle.BoldFont;
			group.Padding = new Padding(0);
			container.Font = UiStyle.BaseFont;
			group.Controls.Add(container);
			return group;
		}

		/// <summary>
		/// Создаёт таблицу «подпись — поле» для формы настроек.
		/// </summary>
		private static TableLayoutPanel CreateFormLayout()
		{
			TableLayoutPanel layout = new TableLayoutPanel();
			layout.ColumnCount = 2;
			layout.RowCount = 0;
			layout.AutoSize = true;
			layout.AutoSizeMode = AutoSizeMode.GrowAndShrink;
			layout.Dock = DockStyle.Top;
			layout.Padding = new Padding(6, 4, 6, 4);
			layout.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 190F));
			layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100F));
			layout.Font = UiStyle.BaseFont;
			return layout;
		}

		/// <summary>
		/// Помещает таблицу полей в именованную группу заданной ширины.
		/// </summary>
		private static GroupBox WrapInGroup(string title, TableLayoutPanel layout, int width)
		{
			GroupBox group = new GroupBox();
			group.Text = title;
			group.Font = UiStyle.BoldFont;
			group.Width = width;
			group.AutoSize = true;
			group.AutoSizeMode = AutoSizeMode.GrowAndShrink;
			group.Padding = new Padding(6, 6, 6, 6);
			group.Margin = new Padding(0, 0, 0, 10);
			layout.Width = width - 16;
			layout.Dock = DockStyle.Fill;
			group.Controls.Add(layout);
			return group;
		}

		/// <summary>
		/// Добавляет строку с текстовым полем (и подсказкой).
		/// </summary>
		private static TextBox AddTextRow(TableLayoutPanel layout, string labelText, string toolTip)
		{
			TextBox textBox = new TextBox();
			textBox.Dock = DockStyle.Fill;
			AddRow(layout, labelText, textBox, toolTip);
			return textBox;
		}

		/// <summary>
		/// Добавляет строку с числовым полем.
		/// </summary>
		private static NumericUpDown AddNumericRow(TableLayoutPanel layout, string labelText, int minimum, int maximum)
		{
			NumericUpDown numeric = new NumericUpDown();
			numeric.Minimum = minimum;
			numeric.Maximum = maximum;
			numeric.Width = 110;
			AddRow(layout, labelText, numeric, null);
			return numeric;
		}

		/// <summary>
		/// Добавляет строку с флажком (во второй колонке).
		/// </summary>
		private static CheckBox AddCheckRow(TableLayoutPanel layout, string text)
		{
			CheckBox checkBox = new CheckBox();
			checkBox.Text = text;
			checkBox.AutoSize = true;
			checkBox.Margin = new Padding(3, 5, 3, 3);
			layout.Controls.Add(checkBox, 1, layout.RowCount);
			layout.RowCount = layout.RowCount + 1;
			return checkBox;
		}

		/// <summary>
		/// Добавляет строку «подпись — элемент управления» с необязательной всплывающей подсказкой.
		/// </summary>
		private static void AddRow(TableLayoutPanel layout, string labelText, Control control, string toolTip)
		{
			Label label = new Label();
			label.Text = labelText;
			label.AutoSize = true;
			label.Anchor = AnchorStyles.Left;
			label.Margin = new Padding(3, 7, 3, 3);
			layout.Controls.Add(label, 0, layout.RowCount);
			layout.Controls.Add(control, 1, layout.RowCount);
			layout.RowCount = layout.RowCount + 1;
			if (!string.IsNullOrEmpty(toolTip))
			{
				ToolTip hint = new ToolTip();
				hint.SetToolTip(control, toolTip);
				hint.SetToolTip(label, toolTip);
			}
		}

		/// <summary>
		/// Переносит значения конфигурации в элементы управления вкладки.
		/// </summary>
		private void LoadSettingsToControls()
		{
			DatabaseSettings database = config.Database;
			serverComboBox.Text = database.Server;
			databaseNameTextBox.Text = database.DatabaseName;
			windowsAuthenticationCheckBox.Checked = database.UseWindowsAuthentication;
			userNameTextBox.Text = database.UserName;
			passwordTextBox.Text = database.GetPassword();
			tableNameTextBox.Text = database.TableName;
			createDatabaseCheckBox.Checked = database.CreateDatabaseIfMissing;
			saveAfterScanCheckBox.Checked = config.SaveToDatabaseAfterScan;

			agentPortNumeric.Value = Clamp(config.AgentPort, agentPortNumeric);
			sharedKeyTextBox.Text = config.SharedKey;
			agentTimeoutNumeric.Value = Clamp(config.AgentTimeoutSeconds, agentTimeoutNumeric);
			parallelScansNumeric.Value = Clamp(config.MaxParallelScans, parallelScansNumeric);
			sendDirectoriesCheckBox.Checked = config.SendDirectoriesToAgents;
			agentsUseOnlyPanelDirectoriesCheckBox.Checked = config.AgentsUseOnlyPanelDirectories;
			agentsUseOnlyPanelDirectoriesCheckBox.Enabled = config.SendDirectoriesToAgents;
			agentInstallPathTextBox.Text = config.AgentInstallPath;

			ReloadDirectoriesGrid();
			extensionsTextBox.Text = config.CertificateFileExtensions;
			maxFileSizeNumeric.Value = Clamp(config.MaxCertificateFileSizeKb, maxFileSizeNumeric);
			scanStoresCheckBox.Checked = config.ScanCertificateStores;
			scanContainersCheckBox.Checked = config.ScanCryptoProContainers;
			pendingPfxPasswords = config.GetPfxPasswords();
			UpdatePfxPasswordsLabel();

			logDirectoryTextBox.Text = config.LogDirectory;
			logRetentionNumeric.Value = Clamp(config.LogRetentionDays, logRetentionNumeric);
			logMaxSizeNumeric.Value = Clamp(config.LogMaxFileSizeMb, logMaxSizeNumeric);
			UpdateAuthenticationControls();
		}

		/// <summary>
		/// Перезаполняет таблицу директорий на вкладке настроек из конфигурации.
		/// </summary>
		private void ReloadDirectoriesGrid()
		{
			directoriesGrid.Rows.Clear();
			foreach (ScanDirectoryEntry entry in config.ScanDirectories)
			{
				directoriesGrid.Rows.Add(entry.Path, entry.Recursive);
			}
		}

		/// <summary>
		/// Показывает, сколько паролей PKCS#12 задано.
		/// </summary>
		private void UpdatePfxPasswordsLabel()
		{
			pfxPasswordsLabel.Text = pendingPfxPasswords.Count == 0 ? "пароли не заданы" : "задано паролей: " + pendingPfxPasswords.Count;
		}

		/// <summary>
		/// Редактирование списка паролей для файлов .p12/.pfx (применяется кнопкой «Сохранить настройки»).
		/// </summary>
		private void OnPfxPasswordsClick(object sender, EventArgs eventArgs)
		{
			Logger.Info("Открыто окно «Пароли для .p12/.pfx»");
			using (PasswordListDialog dialog = new PasswordListDialog(pendingPfxPasswords))
			{
				if (dialog.ShowDialog(this) == DialogResult.OK)
				{
					pendingPfxPasswords = dialog.Passwords;
					UpdatePfxPasswordsLabel();
					Logger.Info("Список паролей PKCS#12 изменён (паролей: " + pendingPfxPasswords.Count + "), нажмите «Сохранить настройки»");
				}
			}
		}

		/// <summary>
		/// Проверяет введённые значения и переносит их в конфигурацию. Возвращает текст ошибки или null.
		/// </summary>
		private string ApplyControlsToConfig(PanelConfig target)
		{
			string schemaName;
			string tableName;
			try
			{
				CertificateRepository.ParseTableName(tableNameTextBox.Text, out schemaName, out tableName);
			}
			catch (ArgumentException exception)
			{
				return exception.Message;
			}
			if (string.IsNullOrWhiteSpace(serverComboBox.Text) || string.IsNullOrWhiteSpace(databaseNameTextBox.Text))
			{
				return "Укажите сервер MSSQL и имя базы данных.";
			}
			if (string.IsNullOrWhiteSpace(sharedKeyTextBox.Text) || sharedKeyTextBox.Text.Trim().Length < 8)
			{
				return "Общий ключ агентов должен быть не короче 8 символов.";
			}

			if (string.IsNullOrWhiteSpace(logDirectoryTextBox.Text))
			{
				return "Укажите папку журналов.";
			}

			DatabaseSettings database = target.Database;
			database.Server = serverComboBox.Text.Trim();
			database.DatabaseName = databaseNameTextBox.Text.Trim();
			database.UseWindowsAuthentication = windowsAuthenticationCheckBox.Checked;
			database.UserName = userNameTextBox.Text.Trim();
			database.SetPassword(passwordTextBox.Text);
			database.TableName = schemaName + "." + tableName;
			database.CreateDatabaseIfMissing = createDatabaseCheckBox.Checked;
			target.SaveToDatabaseAfterScan = saveAfterScanCheckBox.Checked;

			target.AgentPort = (int)agentPortNumeric.Value;
			target.SharedKey = sharedKeyTextBox.Text.Trim();
			target.AgentTimeoutSeconds = (int)agentTimeoutNumeric.Value;
			target.MaxParallelScans = (int)parallelScansNumeric.Value;
			target.SendDirectoriesToAgents = sendDirectoriesCheckBox.Checked;
			target.AgentsUseOnlyPanelDirectories = agentsUseOnlyPanelDirectoriesCheckBox.Checked;
			target.AgentInstallPath = agentInstallPathTextBox.Text.Trim();
			target.LogDirectory = logDirectoryTextBox.Text.Trim();
			target.LogRetentionDays = (int)logRetentionNumeric.Value;
			target.LogMaxFileSizeMb = (int)logMaxSizeNumeric.Value;

			target.ScanDirectories.Clear();
			foreach (DataGridViewRow row in directoriesGrid.Rows)
			{
				if (row.IsNewRow)
				{
					continue;
				}
				string path = Convert.ToString(row.Cells["Path"].Value);
				if (string.IsNullOrWhiteSpace(path))
				{
					continue;
				}
				bool recursive = row.Cells["Recursive"].Value is bool && (bool)row.Cells["Recursive"].Value;
				target.ScanDirectories.Add(new ScanDirectoryEntry(path.Trim(), recursive));
			}
			target.CertificateFileExtensions = string.Join(";", ScanOptions.ParseExtensions(extensionsTextBox.Text));
			target.MaxCertificateFileSizeKb = (int)maxFileSizeNumeric.Value;
			target.ScanCertificateStores = scanStoresCheckBox.Checked;
			target.ScanCryptoProContainers = scanContainersCheckBox.Checked;
			target.SetPfxPasswords(pendingPfxPasswords);
			return null;
		}

		/// <summary>
		/// Сохранение настроек: проверка, применение, запись файла.
		/// </summary>
		private void OnSaveSettingsClick(object sender, EventArgs eventArgs)
		{
			Logger.Info("Выбран пункт «Сохранить настройки»");
			if (IsScanRunning)
			{
				MessageBox.Show(this, "Дождитесь окончания сканирования, затем сохраните настройки.", "Настройки", MessageBoxButtons.OK, MessageBoxIcon.Information);
				return;
			}
			directoriesGrid.EndEdit();
			string error = ApplyControlsToConfig(config);
			if (error != null)
			{
				Logger.Warning("Настройки не сохранены: " + error);
				MessageBox.Show(this, error, "Проверьте настройки", MessageBoxButtons.OK, MessageBoxIcon.Warning);
				return;
			}
			coordinator.ResetDatabaseInitialization();
			if (SaveConfig())
			{
				Logger.Initialize("SkziControlPanel", config.LogDirectory, false);
				Logger.ConfigureRotation(config.LogRetentionDays, config.LogMaxFileSizeMb);
				UpdateDatabaseStatusLabel();
				UpdateScanFoldersLabel();
				extensionsTextBox.Text = config.CertificateFileExtensions;
				SetStatus("Настройки сохранены");
				MessageBox.Show(this, "Настройки сохранены.", "Настройки", MessageBoxButtons.OK, MessageBoxIcon.Information);
			}
		}

		/// <summary>
		/// Проверка подключения к MSSQL с параметрами из полей формы (без сохранения).
		/// </summary>
		private async void OnTestConnectionClick(object sender, EventArgs eventArgs)
		{
			Logger.Info("Выбран пункт «Проверить подключение к БД»");
			PanelConfig probeConfig = new PanelConfigSnapshot(config).Config;
			directoriesGrid.EndEdit();
			string error = ApplyControlsToConfig(probeConfig);
			if (error != null)
			{
				MessageBox.Show(this, error, "Проверьте настройки", MessageBoxButtons.OK, MessageBoxIcon.Warning);
				return;
			}
			Button button = (Button)sender;
			button.Enabled = false;
			SetStatus("Подключение к " + probeConfig.Database.Server + "…");
			try
			{
				string connectionString = probeConfig.Database.BuildConnectionString();
				string serverInfo = await Task.Run(() => CertificateRepository.TestConnection(connectionString));
				Logger.Info("Подключение к MSSQL успешно: " + serverInfo.Replace(Environment.NewLine, " | "));
				SetStatus("Подключение к MSSQL успешно");
				MessageBox.Show(this, "Подключение успешно.\n\n" + serverInfo, "Подключение к MSSQL", MessageBoxButtons.OK, MessageBoxIcon.Information);
			}
			catch (Exception exception)
			{
				ShowError("Не удалось подключиться к MSSQL " + probeConfig.Database.Server, exception);
			}
			finally
			{
				button.Enabled = true;
			}
		}

		/// <summary>
		/// Выбор папки для сканирования через диалог.
		/// </summary>
		private void OnBrowseDirectoryClick(object sender, EventArgs eventArgs)
		{
			using (FolderBrowserDialog dialog = new FolderBrowserDialog())
			{
				dialog.Description = "Папка для поиска файлов сертификатов";
				if (dialog.ShowDialog(this) == DialogResult.OK)
				{
					directoriesGrid.Rows.Add(dialog.SelectedPath, true);
				}
			}
		}

		/// <summary>
		/// Включает поля логина и пароля только для SQL-аутентификации.
		/// </summary>
		private void UpdateAuthenticationControls()
		{
			bool useSqlLogin = !windowsAuthenticationCheckBox.Checked;
			userNameTextBox.Enabled = useSqlLogin;
			passwordTextBox.Enabled = useSqlLogin;
		}

		/// <summary>
		/// Генерирует случайный общий ключ (32 байта, Base64).
		/// </summary>
		private static string GenerateSharedKey()
		{
			byte[] keyBytes = new byte[32];
			using (RandomNumberGenerator generator = RandomNumberGenerator.Create())
			{
				generator.GetBytes(keyBytes);
			}
			return Convert.ToBase64String(keyBytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
		}

		/// <summary>
		/// Ограничивает значение диапазоном числового поля.
		/// </summary>
		private static decimal Clamp(int value, NumericUpDown numeric)
		{
			return Math.Min(numeric.Maximum, Math.Max(numeric.Minimum, value));
		}
	}
}
