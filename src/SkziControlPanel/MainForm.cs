using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Text;
using System.Threading;
using System.Windows.Forms;
using Skzi.Common.Configuration;
using Skzi.Common.Logging;
using Skzi.Common.Scanning;

namespace Skzi.ControlPanel
{
	/// <summary>
	/// Главное окно панели управления: вкладки «Сканирование ПК», «Сертификаты в БД», «Журнал», «Настройки».
	/// Этот файл — каркас окна, строка состояния и вкладка журнала; остальные вкладки — в MainForm.*.cs.
	/// </summary>
	public sealed partial class MainForm : Form
	{
		private const int MaxLogTextLength = 400000;

		private readonly string configPath;
		private PanelConfig config;
		private ScanCoordinator coordinator;

		private TabControl mainTabs;
		private TabPage scanTabPage;
		private TabPage databaseTabPage;
		private TabPage logTabPage;
		private TabPage settingsTabPage;
		private ToolStripStatusLabel statusTextLabel;
		private ToolStripStatusLabel databaseStatusLabel;
		private ToolStripProgressBar statusProgressBar;
		private TextBox logTextBox;
		private bool databaseViewLoaded;

		/// <summary>
		/// Создаёт главное окно с конфигурацией панели.
		/// </summary>
		public MainForm(string configPath, PanelConfig config)
		{
			this.configPath = configPath;
			this.config = config;
			coordinator = new ScanCoordinator(config);

			Text = "Модуль сбора данных о СКЗИ — панель управления";
			UiStyle.EnableDpiScaling(this);
			StartPosition = FormStartPosition.CenterScreen;
			Size = new Size(1280, 800);
			MinimumSize = new Size(980, 600);
			TryLoadIcon();

			BuildLayout();
			LoadHostsFromConfig();
			LoadSettingsToControls();
			UpdateDatabaseStatusLabel();
		}

		/// <summary>
		/// Собирает каркас окна: заголовок, вкладки и строку состояния.
		/// </summary>
		private void BuildLayout()
		{
			SuspendLayout();

			HeaderPanel headerPanel = new HeaderPanel();
			headerPanel.Dock = DockStyle.Top;
			headerPanel.Height = 74;
			headerPanel.Padding = new Padding(24, 0, 20, 0);
			headerPanel.Title = "Модуль сбора данных о СКЗИ";
			headerPanel.Subtitle = "Личные сертификаты и КриптоПро CSP на ПК локальной сети  →  MSSQL   ·   кейс №03   ·   команда Red Flag";
			Image customerLogo = LoadCustomerLogo();
			if (customerLogo != null)
			{
				headerPanel.SetLogo(customerLogo, "ФГУП «Главный радиочастотный центр» — заказчик кейса №03");
			}

			mainTabs = new TabControl();
			mainTabs.Dock = DockStyle.Fill;
			mainTabs.Padding = new Point(16, 6);

			scanTabPage = new TabPage("Сканирование ПК");
			databaseTabPage = new TabPage("Сертификаты в БД");
			logTabPage = new TabPage("Журнал");
			settingsTabPage = new TabPage("Настройки");
			mainTabs.TabPages.AddRange(new[] { scanTabPage, databaseTabPage, logTabPage, settingsTabPage });
			mainTabs.SelectedIndexChanged += OnMainTabChanged;

			BuildScanTab(scanTabPage);
			BuildDatabaseTab(databaseTabPage);
			BuildLogTab(logTabPage);
			BuildSettingsTab(settingsTabPage);

			StatusStrip statusStrip = new StatusStrip();
			statusStrip.Font = UiStyle.BaseFont;
			statusTextLabel = new ToolStripStatusLabel("Готово");
			statusTextLabel.Spring = true;
			statusTextLabel.TextAlign = ContentAlignment.MiddleLeft;
			statusProgressBar = new ToolStripProgressBar();
			statusProgressBar.Size = new Size(200, 16);
			statusProgressBar.Visible = false;
			databaseStatusLabel = new ToolStripStatusLabel();
			databaseStatusLabel.ForeColor = UiStyle.MutedText;
			statusStrip.Items.AddRange(new ToolStripItem[] { statusTextLabel, statusProgressBar, databaseStatusLabel });

			Controls.Add(mainTabs);
			Controls.Add(headerPanel);
			Controls.Add(statusStrip);
			ResumeLayout(true);
		}

		/// <summary>
		/// Загружает встроенный логотип заказчика (белый фирменный знак «грчц.») из ресурсов exe.
		/// Если ресурса нет, возвращает null и заголовок рисуется без логотипа.
		/// </summary>
		private static Image LoadCustomerLogo()
		{
			try
			{
				using (Stream stream = typeof(MainForm).Assembly.GetManifestResourceStream("Skzi.ControlPanel.GrfcLogo.png"))
				{
					if (stream == null)
					{
						return null;
					}
					using (Image loaded = Image.FromStream(stream))
					{
						return new Bitmap(loaded);
					}
				}
			}
			catch (Exception exception)
			{
				Logger.Warning("Не удалось загрузить логотип: " + exception.Message);
				return null;
			}
		}

		/// <summary>
		/// Строит вкладку журнала: последние строки файла журнала и новые записи в реальном времени.
		/// </summary>
		private void BuildLogTab(TabPage page)
		{
			ToolStrip toolStrip = UiStyle.CreateToolStrip();
			toolStrip.Items.Add(UiStyle.CreateToolButton("Открыть папку журналов", "Открыть папку с файлами журнала в проводнике", OnOpenLogFolderClick));
			toolStrip.Items.Add(UiStyle.CreateToolButton("Открыть файл журнала", "Открыть сегодняшний файл журнала в Блокноте", OnOpenLogFileClick));
			toolStrip.Items.Add(new ToolStripSeparator());
			toolStrip.Items.Add(UiStyle.CreateToolButton("Очистить окно", "Очистить окно (файл журнала не изменяется)", delegate { logTextBox.Clear(); }));

			logTextBox = new TextBox();
			logTextBox.Multiline = true;
			logTextBox.ReadOnly = true;
			logTextBox.ScrollBars = ScrollBars.Both;
			logTextBox.WordWrap = false;
			logTextBox.Font = UiStyle.MonospaceFont;
			logTextBox.BackColor = Color.FromArgb(250, 250, 250);
			logTextBox.Dock = DockStyle.Fill;

			page.Controls.Add(logTextBox);
			page.Controls.Add(toolStrip);
		}

		/// <summary>
		/// После показа окна загружает хвост журнала и подписывается на новые записи.
		/// </summary>
		protected override void OnShown(EventArgs eventArgs)
		{
			base.OnShown(eventArgs);
			LoadLogTail();
			Logger.LineWritten += OnLogLineWritten;
			Logger.Info("Открыто главное окно панели управления. Конфигурация: " + configPath);
		}

		/// <summary>
		/// Загружает последние строки сегодняшнего файла журнала в окно журнала.
		/// </summary>
		private void LoadLogTail()
		{
			try
			{
				string logPath = Logger.CurrentLogFilePath;
				if (!File.Exists(logPath))
				{
					return;
				}
				string[] lines;
				using (FileStream stream = new FileStream(logPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
				using (StreamReader reader = new StreamReader(stream, Encoding.UTF8))
				{
					lines = reader.ReadToEnd().Split(new[] { "\r\n", "\n" }, StringSplitOptions.None);
				}
				int startIndex = Math.Max(0, lines.Length - 300);
				StringBuilder builder = new StringBuilder();
				for (int index = startIndex; index < lines.Length; index++)
				{
					if (lines[index].Length > 0)
					{
						builder.AppendLine(lines[index]);
					}
				}
				logTextBox.Text = builder.ToString();
				ScrollLogToEnd();
			}
			catch (Exception exception)
			{
				Logger.Error("Не удалось загрузить журнал в окно", exception);
			}
		}

		/// <summary>
		/// Добавляет новую строку журнала в окно (из любого потока).
		/// </summary>
		private void OnLogLineWritten(object sender, LogLineEventArgs eventArgs)
		{
			if (IsDisposed || !IsHandleCreated)
			{
				return;
			}
			if (InvokeRequired)
			{
				try
				{
					BeginInvoke(new EventHandler<LogLineEventArgs>(OnLogLineWritten), sender, eventArgs);
				}
				catch (InvalidOperationException)
				{
					// Окно закрывается.
				}
				return;
			}
			if (logTextBox.TextLength > MaxLogTextLength)
			{
				logTextBox.Text = logTextBox.Text.Substring(logTextBox.TextLength / 2);
			}
			logTextBox.AppendText(eventArgs.Line + Environment.NewLine);
			if (eventArgs.Level == LogLevel.Error)
			{
				SetStatus(eventArgs.Line.Length > 160 ? eventArgs.Line.Substring(0, 160) + "…" : eventArgs.Line.Split('\n')[0]);
			}
		}

		/// <summary>
		/// Прокручивает журнал к последней строке.
		/// </summary>
		private void ScrollLogToEnd()
		{
			logTextBox.SelectionStart = logTextBox.TextLength;
			logTextBox.ScrollToCaret();
		}

		/// <summary>
		/// Открывает папку журналов в проводнике.
		/// </summary>
		private void OnOpenLogFolderClick(object sender, EventArgs eventArgs)
		{
			Logger.Info("Выбран пункт «Открыть папку журналов»");
			try
			{
				Directory.CreateDirectory(Logger.LogDirectory);
				Process.Start("explorer.exe", "\"" + Logger.LogDirectory + "\"");
			}
			catch (Exception exception)
			{
				ShowError("Не удалось открыть папку журналов", exception);
			}
		}

		/// <summary>
		/// Открывает сегодняшний файл журнала в Блокноте.
		/// </summary>
		private void OnOpenLogFileClick(object sender, EventArgs eventArgs)
		{
			Logger.Info("Выбран пункт «Открыть файл журнала»");
			try
			{
				Process.Start("notepad.exe", "\"" + Logger.CurrentLogFilePath + "\"");
			}
			catch (Exception exception)
			{
				ShowError("Не удалось открыть файл журнала", exception);
			}
		}

		/// <summary>
		/// Фиксирует переключение вкладок в журнале и при первом открытии загружает данные БД.
		/// </summary>
		private void OnMainTabChanged(object sender, EventArgs eventArgs)
		{
			TabPage selected = mainTabs.SelectedTab;
			if (selected == null)
			{
				return;
			}
			Logger.Info("Активирована вкладка «" + selected.Text + "»");
			if (selected == databaseTabPage && !databaseViewLoaded)
			{
				databaseViewLoaded = true;
				RefreshDatabaseView();
			}
		}

		/// <summary>
		/// Показывает текст в строке состояния.
		/// </summary>
		private void SetStatus(string text)
		{
			statusTextLabel.Text = text;
		}

		/// <summary>
		/// Показывает/скрывает индикатор прогресса в строке состояния.
		/// </summary>
		private void SetProgress(int value, int maximum)
		{
			if (maximum <= 0)
			{
				statusProgressBar.Visible = false;
				return;
			}
			statusProgressBar.Visible = true;
			statusProgressBar.Maximum = maximum;
			statusProgressBar.Value = Math.Min(Math.Max(0, value), maximum);
		}

		/// <summary>
		/// Обновляет подпись о подключении к БД в строке состояния.
		/// </summary>
		private void UpdateDatabaseStatusLabel()
		{
			databaseStatusLabel.Text = "БД: " + config.Database.Server + " / " + config.Database.DatabaseName + " / " + config.Database.TableName
				+ (config.SaveToDatabaseAfterScan ? string.Empty : " (автозапись выключена)");
		}

		/// <summary>
		/// Записывает ошибку в журнал и показывает её пользователю.
		/// </summary>
		private void ShowError(string message, Exception exception)
		{
			Logger.Error(message, exception);
			string details = exception == null ? string.Empty : Environment.NewLine + Environment.NewLine + exception.Message;
			MessageBox.Show(this, message + details, "Ошибка", MessageBoxButtons.OK, MessageBoxIcon.Error);
		}

		/// <summary>
		/// Сохраняет конфигурацию панели в файл; ошибки показываются пользователю.
		/// </summary>
		private bool SaveConfig()
		{
			try
			{
				ConfigFile.Save(configPath, config);
				Logger.Info("Конфигурация панели сохранена: " + configPath);
				return true;
			}
			catch (Exception exception)
			{
				ShowError("Не удалось сохранить конфигурацию " + configPath, exception);
				return false;
			}
		}

		/// <summary>
		/// При закрытии окна: подтверждение, если идёт сканирование; отписка от журнала.
		/// </summary>
		protected override void OnFormClosing(FormClosingEventArgs eventArgs)
		{
			if (IsScanRunning)
			{
				DialogResult answer = MessageBox.Show(this, "Идёт сканирование. Прервать его и выйти?", "Выход",
					MessageBoxButtons.YesNo, MessageBoxIcon.Question);
				if (answer != DialogResult.Yes)
				{
					eventArgs.Cancel = true;
					return;
				}
				StopScan();
			}
			Logger.LineWritten -= OnLogLineWritten;
			Logger.Info("Закрыто главное окно панели управления");
			base.OnFormClosing(eventArgs);
		}

		/// <summary>
		/// Устанавливает значок окна из ресурсов исполняемого файла.
		/// </summary>
		private void TryLoadIcon()
		{
			try
			{
				Icon = Icon.ExtractAssociatedIcon(Application.ExecutablePath);
			}
			catch (Exception)
			{
				// Значок не критичен.
			}
		}
	}
}
