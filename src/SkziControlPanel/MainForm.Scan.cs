using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using Skzi.Common.Certificates;
using Skzi.Common.Database;
using Skzi.Common.Logging;
using Skzi.Common.Network;
using Skzi.Common.Scanning;

namespace Skzi.ControlPanel
{
	/// <summary>
	/// Состояние ПК в списке сканирования.
	/// </summary>
	public sealed class HostState
	{
		public string Address { get; set; }
		public string ComputerName { get; set; }
		public string StatusText { get; set; }
		public Color StatusColor { get; set; }
		public string Message { get; set; }
		public ScanResult LastResult { get; set; }
		public SaveStatistics LastSave { get; set; }
		public DateTime? LastScanAt { get; set; }
		public DataGridViewRow Row { get; set; }

		/// <summary>
		/// Создаёт состояние ПК с адресом из списка.
		/// </summary>
		public HostState(string address)
		{
			Address = address;
			StatusText = "Не сканировался";
			StatusColor = UiStyle.MutedText;
		}
	}

	/// <summary>
	/// Вкладка «Сканирование ПК»: список ПК, запуск сканирования, результаты, развёртывание агента.
	/// </summary>
	public sealed partial class MainForm
	{
		private readonly List<HostState> hosts = new List<HostState>();
		private CancellationTokenSource scanCancellation;
		private DataGridView hostsGrid;
		private DataGridView certificatesGrid;
		private TextBox hostInfoTextBox;
		private TextBox warningsTextBox;
		private Label resultTitleLabel;
		private TabPage warningsTabPage;
		private ToolStripComboBox scanMethodComboBox;
		private ToolStripButton scanSelectedButton;
		private ToolStripButton scanAllButton;
		private ToolStripButton scanLocalButton;
		private ToolStripButton stopScanButton;
		private ToolStripButton chooseFoldersButton;
		private ToolStripLabel scanFoldersLabel;
		private HostState displayedHost;

		/// <summary>
		/// Идёт ли сейчас сканирование.
		/// </summary>
		private bool IsScanRunning
		{
			get { return scanCancellation != null; }
		}

		/// <summary>
		/// Строит вкладку сканирования: панель инструментов, таблица ПК, результаты выбранного ПК.
		/// </summary>
		private void BuildScanTab(TabPage page)
		{
			// Верхняя строка — управление списком ПК и агентами, нижняя — запуск сканирования.
			ToolStrip hostsToolStrip = UiStyle.CreateToolStrip();
			hostsToolStrip.Items.Add(new ToolStripLabel("Список ПК:") { Font = UiStyle.BoldFont });
			hostsToolStrip.Items.Add(UiStyle.CreateToolButton("+ Добавить ПК", "Добавить имена или IP-адреса ПК", OnAddHostsClick));
			hostsToolStrip.Items.Add(UiStyle.CreateToolButton("Импорт из файла…", "Загрузить список ПК из текстового файла", OnImportHostsClick));
			hostsToolStrip.Items.Add(UiStyle.CreateToolButton("Найти агенты в сети…", "Найти ПК с запущенным агентом в диапазоне адресов", OnDiscoverAgentsClick));
			hostsToolStrip.Items.Add(UiStyle.CreateToolButton("Удалить", "Удалить выбранные ПК из списка (Delete)", OnRemoveHostsClick));
			hostsToolStrip.Items.Add(new ToolStripSeparator());

			ToolStrip toolStrip = UiStyle.CreateToolStrip();
			toolStrip.Items.Add(new ToolStripLabel("Способ сканирования:") { Font = UiStyle.BoldFont });
			scanMethodComboBox = new ToolStripComboBox();
			scanMethodComboBox.DropDownStyle = ComboBoxStyle.DropDownList;
			scanMethodComboBox.Items.Add("Через агент (TCP)");
			scanMethodComboBox.Items.Add("Без агента (\\\\ПК\\C$ + удалённый реестр)");
			scanMethodComboBox.AutoSize = false;
			scanMethodComboBox.Width = 270;
			scanMethodComboBox.SelectedIndex = string.Equals(config.DefaultScanMode, "Agentless", StringComparison.OrdinalIgnoreCase) ? 1 : 0;
			scanMethodComboBox.SelectedIndexChanged += delegate
			{
				config.DefaultScanMode = scanMethodComboBox.SelectedIndex == 1 ? "Agentless" : "Agent";
				Logger.Info("Выбран способ сканирования: " + scanMethodComboBox.SelectedItem);
				SaveConfig();
			};
			toolStrip.Items.Add(scanMethodComboBox);

			scanSelectedButton = UiStyle.CreateToolButton("▶ Сканировать выбранные", "Сканировать выделенные в таблице ПК", OnScanSelectedClick);
			scanAllButton = UiStyle.CreateToolButton("▶▶ Сканировать все", "Сканировать все ПК из списка", OnScanAllClick);
			scanLocalButton = UiStyle.CreateToolButton("Этот ПК", "Просканировать компьютер, на котором запущена панель (без агента)", OnScanLocalClick);
			stopScanButton = UiStyle.CreateToolButton("■ Остановить", "Прервать текущее сканирование", delegate { StopScan(); });
			stopScanButton.Enabled = false;
			scanSelectedButton.Font = UiStyle.BoldFont;
			toolStrip.Items.Add(scanSelectedButton);
			toolStrip.Items.Add(scanAllButton);
			toolStrip.Items.Add(scanLocalButton);
			toolStrip.Items.Add(stopScanButton);

			// Третья строка — где искать: папки указывает тот, кто собирает сертификаты.
			ToolStrip foldersToolStrip = UiStyle.CreateToolStrip();
			foldersToolStrip.Items.Add(new ToolStripLabel("Где искать:") { Font = UiStyle.BoldFont });
			chooseFoldersButton = UiStyle.CreateToolButton("Папки для поиска…", "Указать папки, в которых искать файлы сертификатов на сканируемых ПК", OnChooseFoldersClick);
			foldersToolStrip.Items.Add(chooseFoldersButton);
			scanFoldersLabel = new ToolStripLabel();
			scanFoldersLabel.ForeColor = UiStyle.MutedText;
			foldersToolStrip.Items.Add(scanFoldersLabel);
			UpdateScanFoldersLabel();

			ToolStripDropDownButton agentMenu = new ToolStripDropDownButton("Агент на ПК");
			agentMenu.DisplayStyle = ToolStripItemDisplayStyle.Text;
			agentMenu.ToolTipText = "Проверка связи, установка и удаление агента на выбранных ПК";
			agentMenu.DropDownItems.Add("Проверить связь с агентом", null, OnPingAgentsClick);
			agentMenu.DropDownItems.Add("Установить / обновить агент на выбранных ПК", null, OnDeployAgentClick);
			agentMenu.DropDownItems.Add("Удалить агент с выбранных ПК", null, OnRemoveAgentClick);
			agentMenu.DropDownItems.Add(new ToolStripSeparator());
			agentMenu.DropDownItems.Add("Сохранить agent.config.xml для ручной установки…", null, OnExportAgentConfigClick);
			hostsToolStrip.Items.Add(agentMenu);

			hostsGrid = new DataGridView();
			hostsGrid.Dock = DockStyle.Fill;
			UiStyle.ApplyGridStyle(hostsGrid);
			hostsGrid.AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill;
			UiStyle.AddTextColumn(hostsGrid, "Address", "Адрес ПК", 115);
			UiStyle.AddTextColumn(hostsGrid, "ComputerName", "Имя ПК", 105);
			UiStyle.AddTextColumn(hostsGrid, "Status", "Статус", 135);
			UiStyle.AddTextColumn(hostsGrid, "CryptoPro", "КриптоПро CSP", 150);
			UiStyle.AddTextColumn(hostsGrid, "License", "Лицензия CSP на ПК", 130);
			UiStyle.AddTextColumn(hostsGrid, "Certificates", "Сертификатов", 100);
			UiStyle.AddTextColumn(hostsGrid, "WithLicense", "С лицензией", 90);
			UiStyle.AddTextColumn(hostsGrid, "Database", "Запись в БД", 115);
			UiStyle.AddTextColumn(hostsGrid, "LastScan", "Сканирование", 120);
			UiStyle.AddTextColumn(hostsGrid, "Message", "Сообщение", 220);
			hostsGrid.SelectionChanged += OnHostSelectionChanged;
			hostsGrid.CellDoubleClick += delegate (object sender, DataGridViewCellEventArgs eventArgs)
			{
				if (eventArgs.RowIndex >= 0)
				{
					ShowHostDetailsDialog();
				}
			};
			hostsGrid.KeyDown += delegate (object sender, KeyEventArgs eventArgs)
			{
				if (eventArgs.KeyCode == Keys.Delete)
				{
					OnRemoveHostsClick(sender, eventArgs);
				}
			};

			certificatesGrid = new DataGridView();
			certificatesGrid.Dock = DockStyle.Fill;
			UiStyle.ApplyGridStyle(certificatesGrid);
			certificatesGrid.AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill;
			UiStyle.AddTextColumn(certificatesGrid, "SerialNumber", "Серийный номер", 210);
			UiStyle.AddTextColumn(certificatesGrid, "Owner", "Владелец", 175);
			UiStyle.AddTextColumn(certificatesGrid, "Organization", "Организация", 120);
			UiStyle.AddTextColumn(certificatesGrid, "Authority", "Удостоверяющий центр", 150);
			UiStyle.AddTextColumn(certificatesGrid, "ValidTo", "Действует до", 90);
			UiStyle.AddTextColumn(certificatesGrid, "HasLicense", "Лицензия КриптоПро", 85);
			UiStyle.AddTextColumn(certificatesGrid, "LicenseVersion", "Версия лицензии", 85);
			UiStyle.AddTextColumn(certificatesGrid, "PrivateKey", "Закрытый ключ", 70);
			UiStyle.AddTextColumn(certificatesGrid, "Source", "Где найден", 260);
			certificatesGrid.CellDoubleClick += OnCertificateDoubleClick;

			hostInfoTextBox = CreateReadOnlyTextBox();
			warningsTextBox = CreateReadOnlyTextBox();

			TabControl resultTabs = new TabControl();
			resultTabs.Dock = DockStyle.Fill;
			TabPage certificatesTabPage = new TabPage("Сертификаты");
			certificatesTabPage.Controls.Add(certificatesGrid);
			TabPage hostInfoTabPage = new TabPage("Сведения о ПК и КриптоПро");
			hostInfoTabPage.Controls.Add(hostInfoTextBox);
			warningsTabPage = new TabPage("Предупреждения");
			warningsTabPage.Controls.Add(warningsTextBox);
			resultTabs.TabPages.AddRange(new[] { certificatesTabPage, hostInfoTabPage, warningsTabPage });

			resultTitleLabel = new Label();
			resultTitleLabel.Dock = DockStyle.Top;
			resultTitleLabel.Height = 26;
			resultTitleLabel.Font = UiStyle.BoldFont;
			resultTitleLabel.TextAlign = ContentAlignment.MiddleLeft;
			resultTitleLabel.Padding = new Padding(4, 0, 0, 0);
			resultTitleLabel.Text = "Выберите ПК в таблице, чтобы увидеть результат сканирования";

			SplitContainer splitContainer = new SplitContainer();
			splitContainer.Dock = DockStyle.Fill;
			splitContainer.Orientation = Orientation.Horizontal;
			splitContainer.SplitterWidth = 6;
			splitContainer.Panel1.Controls.Add(hostsGrid);
			splitContainer.Panel2.Controls.Add(resultTabs);
			splitContainer.Panel2.Controls.Add(resultTitleLabel);
			page.Controls.Add(splitContainer);
			page.Controls.Add(foldersToolStrip);
			page.Controls.Add(toolStrip);
			page.Controls.Add(hostsToolStrip);
			page.Layout += delegate
			{
				if (splitContainer.Height > 300 && splitContainer.SplitterDistance < 120)
				{
					splitContainer.SplitterDistance = (int)(splitContainer.Height * 0.42);
				}
			};
		}

		/// <summary>
		/// Показывает в строке «Где искать» выбранные папки и источники (хранилища, контейнеры КриптоПро).
		/// </summary>
		private void UpdateScanFoldersLabel()
		{
			List<string> paths = new List<string>();
			List<string> shortPaths = new List<string>();
			foreach (Skzi.Common.Configuration.ScanDirectoryEntry entry in config.ScanDirectories)
			{
				paths.Add(entry.Path);
				shortPaths.Add(CompactPath(entry.Path));
			}
			string foldersText = paths.Count == 0 ? "папки не указаны" : string.Join("; ", shortPaths);
			if (foldersText.Length > 90)
			{
				foldersText = foldersText.Substring(0, 87) + "…";
			}
			List<string> extras = new List<string>();
			if (config.ScanCertificateStores)
			{
				extras.Add("хранилища «Личное»");
			}
			if (config.ScanCryptoProContainers)
			{
				extras.Add("контейнеры КриптоПро");
			}
			scanFoldersLabel.Text = foldersText + (extras.Count == 0 ? string.Empty : "  +  " + string.Join(", ", extras));
			scanFoldersLabel.ToolTipText = paths.Count == 0 ? "Папки для поиска файлов не указаны" : string.Join(Environment.NewLine, paths);
			chooseFoldersButton.Text = "Папки для поиска (" + paths.Count + ")…";
		}

		/// <summary>
		/// Сокращает длинный путь для строки «Где искать»: C:\Users\...\samples\certs → C:\…\samples\certs.
		/// </summary>
		private static string CompactPath(string path)
		{
			if (string.IsNullOrEmpty(path) || path.Length <= 32)
			{
				return path;
			}
			string[] segments = path.TrimEnd('\\').Split('\\');
			if (segments.Length <= 3)
			{
				return path;
			}
			return segments[0] + "\\…\\" + segments[segments.Length - 2] + "\\" + segments[segments.Length - 1];
		}

		/// <summary>
		/// Выбор папок для поиска файлов сертификатов (сохраняется в конфигурацию панели).
		/// </summary>
		private void OnChooseFoldersClick(object sender, EventArgs eventArgs)
		{
			Logger.Info("Открыто окно «Папки для поиска сертификатов»");
			if (IsScanRunning)
			{
				MessageBox.Show(this, "Дождитесь окончания сканирования.", "Папки для поиска", MessageBoxButtons.OK, MessageBoxIcon.Information);
				return;
			}
			using (ScanFoldersDialog dialog = new ScanFoldersDialog(config.ScanDirectories))
			{
				if (dialog.ShowDialog(this) != DialogResult.OK)
				{
					return;
				}
				config.ScanDirectories.Clear();
				config.ScanDirectories.AddRange(dialog.Directories);
			}
			List<string> paths = new List<string>();
			foreach (Skzi.Common.Configuration.ScanDirectoryEntry entry in config.ScanDirectories)
			{
				paths.Add(entry.ToString());
			}
			Logger.Info("Папки для поиска изменены: " + (paths.Count == 0 ? "(не указаны)" : string.Join("; ", paths)));
			SaveConfig();
			ReloadDirectoriesGrid();
			UpdateScanFoldersLabel();
			SetStatus("Папок для поиска: " + paths.Count);
		}

		/// <summary>
		/// Создаёт многострочное поле только для чтения моноширинным шрифтом.
		/// </summary>
		private static TextBox CreateReadOnlyTextBox()
		{
			TextBox textBox = new TextBox();
			textBox.Multiline = true;
			textBox.ReadOnly = true;
			textBox.ScrollBars = ScrollBars.Both;
			textBox.WordWrap = false;
			textBox.Font = UiStyle.MonospaceFont;
			textBox.BackColor = SystemColors.Window;
			textBox.Dock = DockStyle.Fill;
			return textBox;
		}

		/// <summary>
		/// Заполняет таблицу ПК из конфигурации.
		/// </summary>
		private void LoadHostsFromConfig()
		{
			foreach (string address in config.Hosts)
			{
				AddHostRow(address);
			}
		}

		/// <summary>
		/// Добавляет ПК в таблицу (без дублей). Возвращает состояние ПК (новое или существующее).
		/// </summary>
		private HostState AddHostRow(string address)
		{
			HostState existing = FindHost(address);
			if (existing != null)
			{
				return existing;
			}
			HostState host = new HostState(address.Trim());
			int rowIndex = hostsGrid.Rows.Add();
			host.Row = hostsGrid.Rows[rowIndex];
			host.Row.Tag = host;
			hosts.Add(host);
			UpdateHostRow(host);
			return host;
		}

		/// <summary>
		/// Ищет ПК в списке по адресу без учёта регистра.
		/// </summary>
		private HostState FindHost(string address)
		{
			foreach (HostState host in hosts)
			{
				if (string.Equals(host.Address, address.Trim(), StringComparison.OrdinalIgnoreCase))
				{
					return host;
				}
			}
			return null;
		}

		/// <summary>
		/// Синхронизирует список ПК в конфигурации с таблицей и сохраняет файл.
		/// </summary>
		private void SaveHostsToConfig()
		{
			config.Hosts.Clear();
			foreach (HostState host in hosts)
			{
				config.Hosts.Add(host.Address);
			}
			SaveConfig();
		}

		/// <summary>
		/// Добавление ПК вручную (несколько через запятую или с новой строки).
		/// </summary>
		private void OnAddHostsClick(object sender, EventArgs eventArgs)
		{
			Logger.Info("Выбран пункт «Добавить ПК»");
			using (MultiLineInputDialog dialog = new MultiLineInputDialog("Добавить ПК",
				"Введите имена или IP-адреса ПК — по одному в строке или через запятую:", string.Empty))
			{
				if (dialog.ShowDialog(this) != DialogResult.OK)
				{
					return;
				}
				AddHosts(MultiLineInputDialog.SplitItems(dialog.InputText), "вручную");
			}
		}

		/// <summary>
		/// Импорт списка ПК из текстового файла.
		/// </summary>
		private void OnImportHostsClick(object sender, EventArgs eventArgs)
		{
			Logger.Info("Выбран пункт «Импорт списка ПК»");
			using (OpenFileDialog dialog = new OpenFileDialog())
			{
				dialog.Title = "Список ПК (по одному имени или IP в строке)";
				dialog.Filter = "Текстовые файлы (*.txt;*.csv)|*.txt;*.csv|Все файлы (*.*)|*.*";
				if (dialog.ShowDialog(this) != DialogResult.OK)
				{
					return;
				}
				try
				{
					AddHosts(MultiLineInputDialog.SplitItems(File.ReadAllText(dialog.FileName)), "из файла " + dialog.FileName);
				}
				catch (Exception exception)
				{
					ShowError("Не удалось прочитать файл со списком ПК", exception);
				}
			}
		}

		/// <summary>
		/// Открывает окно поиска агентов в подсети и добавляет найденные ПК.
		/// </summary>
		private void OnDiscoverAgentsClick(object sender, EventArgs eventArgs)
		{
			Logger.Info("Открыто окно «Поиск агентов в локальной сети»");
			using (DiscoveryDialog dialog = new DiscoveryDialog(config.AgentPort))
			{
				if (dialog.ShowDialog(this) == DialogResult.OK)
				{
					AddHosts(dialog.SelectedHosts, "поиском агентов");
				}
			}
			Logger.Info("Закрыто окно «Поиск агентов в локальной сети»");
		}

		/// <summary>
		/// Добавляет набор ПК и сохраняет список в конфигурацию.
		/// </summary>
		private void AddHosts(List<string> addresses, string sourceDescription)
		{
			int addedCount = 0;
			foreach (string address in addresses)
			{
				if (FindHost(address) == null)
				{
					AddHostRow(address);
					addedCount = addedCount + 1;
				}
			}
			if (addedCount > 0)
			{
				SaveHostsToConfig();
			}
			Logger.Info("Добавлено ПК " + sourceDescription + ": " + addedCount + " (повторы пропущены: " + (addresses.Count - addedCount) + ")");
			SetStatus("Добавлено ПК: " + addedCount);
		}

		/// <summary>
		/// Удаляет выбранные ПК из списка.
		/// </summary>
		private void OnRemoveHostsClick(object sender, EventArgs eventArgs)
		{
			if (IsScanRunning)
			{
				MessageBox.Show(this, "Дождитесь окончания сканирования.", "Удаление ПК", MessageBoxButtons.OK, MessageBoxIcon.Information);
				return;
			}
			List<HostState> selected = GetSelectedHosts();
			if (selected.Count == 0)
			{
				return;
			}
			if (MessageBox.Show(this, "Удалить из списка ПК: " + selected.Count + "?", "Удаление ПК", MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes)
			{
				return;
			}
			foreach (HostState host in selected)
			{
				hostsGrid.Rows.Remove(host.Row);
				hosts.Remove(host);
				Logger.Info("ПК удалён из списка: " + host.Address);
			}
			SaveHostsToConfig();
		}

		/// <summary>
		/// Возвращает ПК, выделенные в таблице (в порядке таблицы).
		/// </summary>
		private List<HostState> GetSelectedHosts()
		{
			List<HostState> selected = new List<HostState>();
			foreach (DataGridViewRow row in hostsGrid.Rows)
			{
				if (row.Selected && row.Tag is HostState)
				{
					selected.Add((HostState)row.Tag);
				}
			}
			return selected;
		}

		/// <summary>
		/// Текущий способ сканирования из выпадающего списка.
		/// </summary>
		private ScanMethod SelectedScanMethod
		{
			get { return scanMethodComboBox.SelectedIndex == 1 ? ScanMethod.Agentless : ScanMethod.Agent; }
		}

		/// <summary>
		/// Сканирование выделенных ПК.
		/// </summary>
		private void OnScanSelectedClick(object sender, EventArgs eventArgs)
		{
			Logger.Info("Выбран пункт «Сканировать выбранные»");
			List<HostState> selected = GetSelectedHosts();
			if (selected.Count == 0)
			{
				MessageBox.Show(this, "Выделите ПК в таблице (Ctrl/Shift для нескольких) или нажмите «Сканировать все».", "Сканирование",
					MessageBoxButtons.OK, MessageBoxIcon.Information);
				return;
			}
			StartScan(selected, SelectedScanMethod);
		}

		/// <summary>
		/// Сканирование всех ПК из списка.
		/// </summary>
		private void OnScanAllClick(object sender, EventArgs eventArgs)
		{
			Logger.Info("Выбран пункт «Сканировать все»");
			if (hosts.Count == 0)
			{
				MessageBox.Show(this, "Список ПК пуст. Добавьте ПК вручную, из файла или поиском агентов.", "Сканирование",
					MessageBoxButtons.OK, MessageBoxIcon.Information);
				return;
			}
			StartScan(new List<HostState>(hosts), SelectedScanMethod);
		}

		/// <summary>
		/// Сканирование компьютера, на котором запущена панель (без агента).
		/// </summary>
		private void OnScanLocalClick(object sender, EventArgs eventArgs)
		{
			Logger.Info("Выбран пункт «Этот ПК»");
			HostState localHost = FindHost(Environment.MachineName) ?? FindHost("localhost") ?? AddHostRow(Environment.MachineName);
			SaveHostsToConfig();
			hostsGrid.ClearSelection();
			hostsGrid.CurrentCell = localHost.Row.Cells["Address"];
			localHost.Row.Selected = true;
			StartScan(new List<HostState> { localHost }, ScanMethod.Local);
		}

		/// <summary>
		/// Запускает параллельное сканирование ПК (не более MaxParallelScans одновременно).
		/// </summary>
		private async void StartScan(List<HostState> targets, ScanMethod method)
		{
			if (IsScanRunning)
			{
				return;
			}
			scanCancellation = new CancellationTokenSource();
			CancellationToken token = scanCancellation.Token;
			SetScanControlsState(true);
			int completedCount = 0;
			int failedCount = 0;
			SetProgress(0, targets.Count);
			SetStatus("Сканирование ПК: 0 из " + targets.Count + "…");
			Logger.Info("Начато сканирование ПК: " + targets.Count + ", способ: " + method + ", параллельно: " + config.MaxParallelScans);

			foreach (HostState host in targets)
			{
				host.StatusText = "В очереди";
				host.StatusColor = UiStyle.MutedText;
				host.Message = string.Empty;
				UpdateHostRow(host);
			}

			SemaphoreSlim limiter = new SemaphoreSlim(Math.Max(1, config.MaxParallelScans));
			Func<HostState, Task> scanAndCount = async (HostState target) =>
			{
				bool succeeded = await ScanSingleHostAsync(target, method, limiter, token);
				completedCount = completedCount + 1;
				if (!succeeded)
				{
					failedCount = failedCount + 1;
				}
				SetProgress(completedCount, targets.Count);
				SetStatus("Сканирование ПК: " + completedCount + " из " + targets.Count + "…");
			};
			List<Task> scanTasks = new List<Task>();
			foreach (HostState host in targets)
			{
				scanTasks.Add(scanAndCount(host));
			}

			await Task.WhenAll(scanTasks);

			bool wasCancelled = token.IsCancellationRequested;
			scanCancellation.Dispose();
			scanCancellation = null;
			SetScanControlsState(false);
			SetProgress(0, 0);
			string summary = (wasCancelled ? "Сканирование остановлено" : "Сканирование завершено") + ": ПК " + targets.Count
				+ ", успешно " + (completedCount - failedCount) + ", с ошибками " + failedCount;
			SetStatus(summary);
			Logger.Info(summary);
			if (databaseViewLoaded && config.SaveToDatabaseAfterScan)
			{
				RefreshDatabaseView();
			}
		}

		/// <summary>
		/// Сканирует один ПК с учётом ограничения параллельности; возвращает true при успехе.
		/// Все ошибки перехватываются, пишутся в журнал и показываются в строке ПК.
		/// </summary>
		private async Task<bool> ScanSingleHostAsync(HostState host, ScanMethod method, SemaphoreSlim limiter, CancellationToken token)
		{
			try
			{
				await limiter.WaitAsync(token);
			}
			catch (OperationCanceledException)
			{
				host.StatusText = "Отменено";
				host.StatusColor = UiStyle.MutedText;
				UpdateHostRow(host);
				return false;
			}

			try
			{
				host.StatusText = "Сканирование…";
				host.StatusColor = UiStyle.ProgressText;
				UpdateHostRow(host);

				HostScanOutcome outcome = await coordinator.ScanHostAsync(host.Address, method, token);
				host.LastResult = outcome.Result;
				host.LastSave = outcome.DatabaseStatistics;
				host.LastScanAt = DateTime.Now;
				host.ComputerName = outcome.Result.ComputerName;
				host.StatusText = "Готово";
				host.StatusColor = UiStyle.SuccessText;
				host.Message = BuildHostMessage(outcome);
				Logger.Info("ПК " + host.Address + " просканирован: сертификатов " + outcome.Result.Certificates.Count
					+ (outcome.DatabaseStatistics != null ? ", БД: " + outcome.DatabaseStatistics : string.Empty));
				return outcome.DatabaseError == null;
			}
			catch (OperationCanceledException)
			{
				host.StatusText = "Отменено";
				host.StatusColor = UiStyle.MutedText;
				host.Message = "Сканирование прервано пользователем";
				Logger.Warning("Сканирование ПК " + host.Address + " отменено");
				return false;
			}
			catch (Exception exception)
			{
				host.StatusText = "Ошибка";
				host.StatusColor = UiStyle.ErrorText;
				host.Message = ScanCoordinator.DescribeError(exception, config.AgentPort);
				host.LastScanAt = DateTime.Now;
				Logger.Error("Ошибка сканирования ПК " + host.Address + " (" + method + "): " + host.Message, exception);
				return false;
			}
			finally
			{
				limiter.Release();
				UpdateHostRow(host);
				if (host == displayedHost || (hostsGrid.CurrentRow != null && hostsGrid.CurrentRow.Tag == host))
				{
					ShowHostResult(host);
				}
			}
		}

		/// <summary>
		/// Формирует сообщение для строки ПК: предупреждения сканирования и результат записи в БД.
		/// </summary>
		private string BuildHostMessage(HostScanOutcome outcome)
		{
			List<string> parts = new List<string>();
			if (outcome.DatabaseError != null)
			{
				parts.Add("Ошибка записи в БД: " + outcome.DatabaseError);
			}
			if (outcome.Result.Warnings.Count > 0)
			{
				parts.Add("предупреждений: " + outcome.Result.Warnings.Count + " (см. вкладку «Предупреждения»)");
			}
			if (outcome.Result.FilesFailed > 0)
			{
				parts.Add("нераспознанных файлов: " + outcome.Result.FilesFailed);
			}
			return parts.Count == 0 ? "OK" : string.Join("; ", parts);
		}

		/// <summary>
		/// Прерывает текущее сканирование.
		/// </summary>
		private void StopScan()
		{
			if (scanCancellation != null && !scanCancellation.IsCancellationRequested)
			{
				Logger.Info("Выбран пункт «Остановить сканирование»");
				scanCancellation.Cancel();
				SetStatus("Остановка сканирования…");
			}
		}

		/// <summary>
		/// Включает/выключает кнопки на время сканирования.
		/// </summary>
		private void SetScanControlsState(bool scanning)
		{
			scanSelectedButton.Enabled = !scanning;
			scanAllButton.Enabled = !scanning;
			scanLocalButton.Enabled = !scanning;
			scanMethodComboBox.Enabled = !scanning;
			chooseFoldersButton.Enabled = !scanning;
			stopScanButton.Enabled = scanning;
		}

		/// <summary>
		/// Обновляет ячейки строки ПК по его состоянию.
		/// </summary>
		private void UpdateHostRow(HostState host)
		{
			if (host.Row == null || host.Row.DataGridView == null)
			{
				return;
			}
			DataGridViewCellCollection cells = host.Row.Cells;
			cells["Address"].Value = host.Address;
			cells["ComputerName"].Value = host.ComputerName ?? string.Empty;
			cells["Status"].Value = host.StatusText;
			cells["Status"].Style.ForeColor = host.StatusColor;
			cells["Status"].Style.Font = UiStyle.BoldFont;
			cells["Message"].Value = host.Message ?? string.Empty;
			cells["LastScan"].Value = host.LastScanAt.HasValue ? host.LastScanAt.Value.ToString("dd.MM.yyyy HH:mm:ss") : string.Empty;

			ScanResult result = host.LastResult;
			if (result == null)
			{
				return;
			}
			cells["CryptoPro"].Value = result.CryptoPro.DisplayText;
			cells["License"].Value = BuildLicenseCellText(result.CryptoPro);
			cells["Certificates"].Value = result.Certificates.Count;
			int withLicense = 0;
			foreach (CertificateRecord record in result.Certificates)
			{
				if (record.HasEmbeddedCryptoProLicense)
				{
					withLicense = withLicense + 1;
				}
			}
			cells["WithLicense"].Value = withLicense;
			cells["Database"].Value = host.LastSave == null
				? (config.SaveToDatabaseAfterScan ? "не записано" : "автозапись выкл.")
				: "+" + host.LastSave.Inserted + " / обновлено " + host.LastSave.Updated
					+ (host.LastSave.MarkedMissing > 0 ? " / пропало " + host.LastSave.MarkedMissing : string.Empty);
		}

		/// <summary>
		/// Текст ячейки «Лицензия CSP на ПК»: замаскированный серийный номер и срок действия.
		/// </summary>
		private static string BuildLicenseCellText(CryptoProInfo cryptoPro)
		{
			if (!cryptoPro.IsInstalled)
			{
				return string.Empty;
			}
			string serial = string.IsNullOrEmpty(cryptoPro.LicenseSerialMasked) ? "серийный № не найден" : cryptoPro.LicenseSerialMasked;
			return string.IsNullOrEmpty(cryptoPro.LicenseValidity) ? serial : serial + " — " + cryptoPro.LicenseValidity;
		}

		/// <summary>
		/// При выборе ПК показывает его последний результат сканирования.
		/// </summary>
		private void OnHostSelectionChanged(object sender, EventArgs eventArgs)
		{
			if (hostsGrid.CurrentRow == null)
			{
				return;
			}
			HostState host = hostsGrid.CurrentRow.Tag as HostState;
			if (host != null && host != displayedHost)
			{
				ShowHostResult(host);
			}
		}

		/// <summary>
		/// Заполняет нижнюю часть вкладки: сертификаты, сведения о ПК, предупреждения.
		/// </summary>
		private void ShowHostResult(HostState host)
		{
			displayedHost = host;
			certificatesGrid.Rows.Clear();
			ScanResult result = host.LastResult;
			if (result == null)
			{
				resultTitleLabel.Text = "ПК " + host.Address + ": " + (host.StatusText == "Ошибка" ? "ошибка — " + host.Message : "результатов сканирования нет");
				hostInfoTextBox.Text = string.Empty;
				warningsTextBox.Text = host.Message ?? string.Empty;
				warningsTabPage.Text = "Предупреждения";
				return;
			}

			resultTitleLabel.Text = "ПК " + host.Address + (string.Equals(host.Address, result.ComputerName, StringComparison.OrdinalIgnoreCase) ? string.Empty : " (" + result.ComputerName + ")")
				+ " — сертификатов: " + result.Certificates.Count + ", КриптоПро: " + result.CryptoPro.DisplayText
				+ ", сканирование " + result.FinishedAt.ToString("dd.MM.yyyy HH:mm:ss");

			foreach (CertificateRecord record in result.Certificates)
			{
				int rowIndex = certificatesGrid.Rows.Add(
					record.SerialNumber,
					record.OwnerName,
					record.OwnerOrganization,
					record.CertificationAuthority,
					record.ValidTo.ToString("dd.MM.yyyy"),
					record.HasEmbeddedCryptoProLicense ? "Да" : "Нет",
					record.HasEmbeddedCryptoProLicense ? record.CryptoProLicenseVersion : string.Empty,
					record.HasPrivateKey ? "Есть" : string.Empty,
					record.SourcesText);
				DataGridViewRow row = certificatesGrid.Rows[rowIndex];
				row.Tag = record;
				if (record.IsExpired)
				{
					row.DefaultCellStyle.BackColor = UiStyle.ExpiredRow;
					row.Cells["ValidTo"].ToolTipText = "Срок действия истёк";
				}
				else if (record.ValidTo < DateTime.Now.AddDays(30))
				{
					row.DefaultCellStyle.BackColor = UiStyle.ExpiringRow;
					row.Cells["ValidTo"].ToolTipText = "Истекает в ближайшие 30 дней";
				}
				if (record.HasEmbeddedCryptoProLicense)
				{
					row.Cells["HasLicense"].Style.Font = UiStyle.BoldFont;
				}
			}

			hostInfoTextBox.Text = BuildHostInfoText(host);
			StringBuilder warnings = new StringBuilder();
			foreach (string warning in result.Warnings)
			{
				warnings.AppendLine(warning);
			}
			warningsTextBox.Text = warnings.Length == 0 ? "Предупреждений нет." : warnings.ToString();
			warningsTabPage.Text = result.Warnings.Count == 0 ? "Предупреждения" : "Предупреждения (" + result.Warnings.Count + ")";
		}

		/// <summary>
		/// Формирует текст «Сведения о ПК и КриптоПро».
		/// </summary>
		private static string BuildHostInfoText(HostState host)
		{
			ScanResult result = host.LastResult;
			CryptoProInfo cryptoPro = result.CryptoPro;
			StringBuilder builder = new StringBuilder();
			builder.AppendLine("Адрес в списке:           " + host.Address);
			builder.AppendLine("Имя ПК:                   " + result.ComputerName);
			builder.AppendLine("ОС:                       " + (result.OperatingSystem ?? "нет сведений (безагентный режим)"));
			builder.AppendLine("Способ сканирования:      " + result.ScanMode);
			builder.AppendLine("Учётная запись сканера:   " + result.ScannedAs);
			builder.AppendLine("Версия сканера:           " + result.ScannerVersion);
			builder.AppendLine("Начало / окончание:       " + result.StartedAt.ToString("dd.MM.yyyy HH:mm:ss.fff") + " / " + result.FinishedAt.ToString("HH:mm:ss.fff")
				+ " (" + (int)result.Duration.TotalMilliseconds + " мс)");
			builder.AppendLine();
			builder.AppendLine("КриптоПро CSP:            " + (cryptoPro.IsInstalled ? "установлен" : "не установлен"));
			if (cryptoPro.IsInstalled)
			{
				builder.AppendLine("  Продукт:                " + cryptoPro.ProductName);
				builder.AppendLine("  Версия:                 " + cryptoPro.Version);
				builder.AppendLine("  Дата установки:         " + (cryptoPro.InstallDate ?? "нет сведений"));
				builder.AppendLine("  Серийный номер лицензии:" + (string.IsNullOrEmpty(cryptoPro.LicenseSerialMasked) ? " нет сведений" : " " + cryptoPro.LicenseSerialMasked));
				builder.AppendLine("  Срок действия лицензии: " + (cryptoPro.LicenseValidity ?? "не определён"));
				builder.AppendLine("  Версия по лицензии:     " + (cryptoPro.LicenseVersion ?? "—"));
				if (!string.IsNullOrEmpty(cryptoPro.LicenseDetails))
				{
					builder.AppendLine("  Сведения cpconfig:      " + cryptoPro.LicenseDetails);
				}
				builder.AppendLine("  Источник сведений:      " + cryptoPro.DetectionSource);
			}
			if (cryptoPro.OtherProducts.Count > 0)
			{
				builder.AppendLine("Другие продукты КриптоПро:");
				foreach (string product in cryptoPro.OtherProducts)
				{
					builder.AppendLine("  • " + product);
				}
			}
			builder.AppendLine();
			builder.AppendLine("Статистика:");
			builder.AppendLine("  Просмотрено директорий: " + result.DirectoriesScanned);
			builder.AppendLine("  Обработано файлов:      " + result.FilesScanned + " (не распознано: " + result.FilesFailed + ")");
			builder.AppendLine("  Сертификатов из хранилищ Windows: " + result.StoreCertificatesFound);
			builder.AppendLine("  Сертификатов из контейнеров КриптоПро: " + (result.CryptoProContainersScanned ? result.ContainerCertificatesFound.ToString() : "не проверялись"));
			builder.AppendLine("  Уникальных сертификатов: " + result.Certificates.Count);
			builder.AppendLine("  Искались расширения:    " + (result.ScannedFileExtensions ?? "—"));
			builder.AppendLine("  Просмотренные папки:");
			if (result.ScannedDirectories.Count == 0)
			{
				builder.AppendLine("    —");
			}
			foreach (Skzi.Common.Configuration.ScanDirectoryEntry directory in result.ScannedDirectories)
			{
				builder.AppendLine("    • " + directory);
			}
			if (host.LastSave != null)
			{
				builder.AppendLine("  Запись в БД:            " + host.LastSave);
			}
			return builder.ToString();
		}

		/// <summary>
		/// Открывает окно со всеми сведениями о ПК (двойной щелчок по строке ПК).
		/// </summary>
		private void ShowHostDetailsDialog()
		{
			HostState host = hostsGrid.CurrentRow == null ? null : hostsGrid.CurrentRow.Tag as HostState;
			if (host == null || host.LastResult == null)
			{
				return;
			}
			Logger.Info("Открыто окно «Сведения о ПК " + host.Address + "»");
			using (TextViewerDialog dialog = new TextViewerDialog("Сведения о ПК " + host.Address, BuildHostInfoText(host)))
			{
				dialog.ShowDialog(this);
			}
		}

		/// <summary>
		/// Двойной щелчок по сертификату — окно со всеми полями.
		/// </summary>
		private void OnCertificateDoubleClick(object sender, DataGridViewCellEventArgs eventArgs)
		{
			if (eventArgs.RowIndex < 0)
			{
				return;
			}
			CertificateRecord record = certificatesGrid.Rows[eventArgs.RowIndex].Tag as CertificateRecord;
			if (record == null)
			{
				return;
			}
			Logger.Info("Открыто окно сведений о сертификате " + record.SerialNumber);
			using (TextViewerDialog dialog = new TextViewerDialog("Сертификат " + record.SerialNumber, BuildCertificateDetailsText(record)))
			{
				dialog.ShowDialog(this);
			}
		}

		/// <summary>
		/// Формирует текст со всеми полями сертификата.
		/// </summary>
		public static string BuildCertificateDetailsText(CertificateRecord record)
		{
			StringBuilder builder = new StringBuilder();
			builder.AppendLine("Серийный номер:        " + record.SerialNumber);
			builder.AppendLine("Отпечаток (SHA-1):     " + record.Thumbprint);
			builder.AppendLine("Владелец:              " + record.OwnerName);
			builder.AppendLine("Организация:           " + (record.OwnerOrganization ?? "—"));
			builder.AppendLine("Должность:             " + (record.OwnerTitle ?? "—"));
			builder.AppendLine("ИНН:                   " + (record.OwnerInn ?? "—"));
			builder.AppendLine("СНИЛС:                 " + (record.OwnerSnils ?? "—"));
			builder.AppendLine("ОГРН/ОГРНИП:           " + (record.OwnerOgrn ?? "—"));
			builder.AppendLine("E-mail:                " + (record.OwnerEmail ?? "—"));
			builder.AppendLine("Удостоверяющий центр:  " + record.CertificationAuthority);
			builder.AppendLine("Действует:             с " + record.ValidFrom.ToString("dd.MM.yyyy HH:mm") + " по " + record.ValidTo.ToString("dd.MM.yyyy HH:mm")
				+ (record.IsExpired ? "  (ИСТЁК)" : string.Empty));
			builder.AppendLine("Алгоритм подписи:      " + record.SignatureAlgorithm);
			builder.AppendLine("Алгоритм ключа:        " + record.PublicKeyAlgorithm);
			builder.AppendLine("Закрытый ключ:         " + (record.HasPrivateKey ? "есть привязка к контейнеру" : "нет сведений"));
			builder.AppendLine();
			builder.AppendLine("Лицензия КриптоПро CSP встроена: " + (record.HasEmbeddedCryptoProLicense ? "ДА" : "нет"));
			if (record.HasEmbeddedCryptoProLicense)
			{
				builder.AppendLine("Версия лицензии:       " + record.CryptoProLicenseVersion);
				builder.AppendLine("Содержимое расширения: " + record.CryptoProLicenseDetails);
			}
			builder.AppendLine();
			builder.AppendLine("Субъект: " + record.SubjectDn);
			builder.AppendLine("Издатель: " + record.IssuerDn);
			builder.AppendLine();
			builder.AppendLine("Где найден:");
			foreach (string source in record.Sources)
			{
				builder.AppendLine("  • " + source);
			}
			return builder.ToString();
		}

		/// <summary>
		/// Проверка связи с агентами выбранных ПК (команда Ping с проверкой ключа).
		/// </summary>
		private async void OnPingAgentsClick(object sender, EventArgs eventArgs)
		{
			Logger.Info("Выбран пункт «Проверить связь с агентом»");
			List<HostState> selected = GetSelectedHosts();
			if (selected.Count == 0)
			{
				MessageBox.Show(this, "Выделите ПК в таблице.", "Проверка связи", MessageBoxButtons.OK, MessageBoxIcon.Information);
				return;
			}
			SetStatus("Проверка связи с агентами…");
			List<Task> pingTasks = new List<Task>();
			foreach (HostState host in selected)
			{
				pingTasks.Add(PingAgentAsync(host));
			}
			await Task.WhenAll(pingTasks);
			SetStatus("Проверка связи завершена");
		}

		/// <summary>
		/// Отправляет агенту команду Ping и показывает результат в строке ПК.
		/// </summary>
		private async Task PingAgentAsync(HostState host)
		{
			host.StatusText = "Проверка…";
			host.StatusColor = UiStyle.ProgressText;
			UpdateHostRow(host);
			try
			{
				AgentRequest request = new AgentRequest();
				request.Command = AgentRequest.CommandPing;
				request.RequestedBy = CertificateCollector.GetCurrentAccountName() + "@" + Environment.MachineName;
				AgentResponse response = await AgentClient.SendRequestAsync(host.Address, config.AgentPort, config.SharedKey, request, 10000, CancellationToken.None);
				host.ComputerName = response.ComputerName;
				host.StatusText = "Агент доступен";
				host.StatusColor = UiStyle.SuccessText;
				host.Message = "Агент " + response.AgentVersion + " на " + response.ComputerName + ", ключ совпадает";
				Logger.Info("Агент на " + host.Address + " доступен: " + response.AgentVersion);
			}
			catch (Exception exception)
			{
				host.StatusText = "Агент недоступен";
				host.StatusColor = UiStyle.ErrorText;
				host.Message = ScanCoordinator.DescribeError(exception, config.AgentPort);
				Logger.Warning("Агент на " + host.Address + " недоступен: " + host.Message);
			}
			UpdateHostRow(host);
		}

		/// <summary>
		/// Установка (обновление) агента на выбранных ПК.
		/// </summary>
		private void OnDeployAgentClick(object sender, EventArgs eventArgs)
		{
			Logger.Info("Выбран пункт «Установить агент»");
			RunAgentManagement(true);
		}

		/// <summary>
		/// Удаление агента с выбранных ПК.
		/// </summary>
		private void OnRemoveAgentClick(object sender, EventArgs eventArgs)
		{
			Logger.Info("Выбран пункт «Удалить агент»");
			RunAgentManagement(false);
		}

		/// <summary>
		/// Выполняет установку или удаление агента на выбранных ПК последовательно в фоне.
		/// </summary>
		private async void RunAgentManagement(bool install)
		{
			List<HostState> selected = GetSelectedHosts();
			if (selected.Count == 0)
			{
				MessageBox.Show(this, "Выделите ПК в таблице.", "Агент", MessageBoxButtons.OK, MessageBoxIcon.Information);
				return;
			}
			string action = install ? "Установить (обновить) агент" : "Удалить агент";
			string question = action + " на ПК: " + selected.Count + "?\n\nНужны права локального администратора на этих ПК (доступ к \\\\ПК\\C$ и управлению службами)."
				+ (install ? "\nПапка установки: " + config.AgentInstallPath + "\nПорт: " + config.AgentPort : string.Empty);
			if (MessageBox.Show(this, question, action, MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes)
			{
				return;
			}

			SetProgress(0, selected.Count);
			int doneCount = 0;
			foreach (HostState host in selected)
			{
				host.StatusText = install ? "Установка агента…" : "Удаление агента…";
				host.StatusColor = UiStyle.ProgressText;
				UpdateHostRow(host);
				try
				{
					string address = host.Address;
					PanelConfigSnapshot snapshot = new PanelConfigSnapshot(config);
					string message = await Task.Run(() => install ? AgentDeployer.Deploy(address, snapshot.Config) : AgentDeployer.Remove(address, snapshot.Config));
					host.StatusText = install ? "Агент установлен" : "Агент удалён";
					host.StatusColor = UiStyle.SuccessText;
					host.Message = message;
				}
				catch (Exception exception)
				{
					host.StatusText = "Ошибка";
					host.StatusColor = UiStyle.ErrorText;
					host.Message = exception.Message;
					Logger.Error(action + " на " + host.Address + ": ошибка", exception);
				}
				doneCount = doneCount + 1;
				SetProgress(doneCount, selected.Count);
				UpdateHostRow(host);
			}
			SetProgress(0, 0);
			SetStatus(action + ": обработано ПК " + selected.Count);
		}

		/// <summary>
		/// Сохраняет agent.config.xml с текущими настройками панели (для ручной установки агента).
		/// </summary>
		private void OnExportAgentConfigClick(object sender, EventArgs eventArgs)
		{
			Logger.Info("Выбран пункт «Сохранить agent.config.xml»");
			using (SaveFileDialog dialog = new SaveFileDialog())
			{
				dialog.FileName = AgentDeployer.AgentConfigName;
				dialog.Filter = "Конфигурация агента (*.xml)|*.xml";
				if (dialog.ShowDialog(this) != DialogResult.OK)
				{
					return;
				}
				try
				{
					Skzi.Common.Configuration.ConfigFile.Save(dialog.FileName, AgentDeployer.BuildAgentConfig(config));
					Logger.Info("Конфигурация агента сохранена: " + dialog.FileName);
					SetStatus("Конфигурация агента сохранена: " + dialog.FileName);
				}
				catch (Exception exception)
				{
					ShowError("Не удалось сохранить конфигурацию агента", exception);
				}
			}
		}
	}

	/// <summary>
	/// Копия конфигурации для фоновых операций (чтобы изменения в настройках не влияли на идущую операцию).
	/// </summary>
	public sealed class PanelConfigSnapshot
	{
		public Skzi.Common.Configuration.PanelConfig Config { get; private set; }

		/// <summary>
		/// Создаёт независимую копию конфигурации через XML-сериализацию.
		/// </summary>
		public PanelConfigSnapshot(Skzi.Common.Configuration.PanelConfig source)
		{
			string xml = XmlMessageSerializer.Serialize(source);
			Config = XmlMessageSerializer.Deserialize<Skzi.Common.Configuration.PanelConfig>(xml);
		}
	}
}
