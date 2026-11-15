using System;
using System.Collections.Generic;
using System.Drawing;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using Skzi.Common.Configuration;
using Skzi.Common.Logging;
using Skzi.Common.Network;

namespace Skzi.ControlPanel
{
	/// <summary>
	/// Диалог ввода нескольких строк (например, списка ПК).
	/// </summary>
	public sealed class MultiLineInputDialog : Form
	{
		private readonly TextBox inputTextBox;

		/// <summary>
		/// Введённый текст.
		/// </summary>
		public string InputText
		{
			get { return inputTextBox.Text; }
		}

		/// <summary>
		/// Создаёт диалог с заголовком, поясняющей надписью и начальным текстом.
		/// </summary>
		public MultiLineInputDialog(string title, string prompt, string initialText)
		{
			Text = title;
			UiStyle.EnableDpiScaling(this);
			StartPosition = FormStartPosition.CenterParent;
			FormBorderStyle = FormBorderStyle.FixedDialog;
			MinimizeBox = false;
			MaximizeBox = false;
			ShowInTaskbar = false;
			ClientSize = new Size(460, 300);

			Label promptLabel = new Label();
			promptLabel.Text = prompt;
			promptLabel.AutoSize = false;
			promptLabel.SetBounds(12, 10, 436, 36);

			inputTextBox = new TextBox();
			inputTextBox.Multiline = true;
			inputTextBox.ScrollBars = ScrollBars.Vertical;
			inputTextBox.AcceptsReturn = true;
			inputTextBox.Font = UiStyle.MonospaceFont;
			inputTextBox.Text = initialText ?? string.Empty;
			inputTextBox.SetBounds(12, 50, 436, 200);

			Button okButton = new Button();
			okButton.Text = "Добавить";
			okButton.DialogResult = DialogResult.OK;
			okButton.SetBounds(262, 260, 90, 28);

			Button cancelButton = new Button();
			cancelButton.Text = "Отмена";
			cancelButton.DialogResult = DialogResult.Cancel;
			cancelButton.SetBounds(358, 260, 90, 28);

			Controls.AddRange(new Control[] { promptLabel, inputTextBox, okButton, cancelButton });
			AcceptButton = okButton;
			CancelButton = cancelButton;
		}

		/// <summary>
		/// Разбивает текст на элементы по строкам, запятым, точкам с запятой и пробелам; пропускает комментарии «#».
		/// </summary>
		public static List<string> SplitItems(string text)
		{
			List<string> items = new List<string>();
			if (string.IsNullOrWhiteSpace(text))
			{
				return items;
			}
			foreach (string rawLine in text.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
			{
				string line = rawLine;
				int commentIndex = line.IndexOf('#');
				if (commentIndex >= 0)
				{
					line = line.Substring(0, commentIndex);
				}
				foreach (string part in line.Split(new[] { ',', ';', ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries))
				{
					string item = part.Trim().TrimStart('\\');
					if (item.Length > 0)
					{
						items.Add(item);
					}
				}
			}
			return items;
		}
	}

	/// <summary>
	/// Окно просмотра текста (сведения о сертификате, о ПК) с кнопкой копирования.
	/// </summary>
	public sealed class TextViewerDialog : Form
	{
		/// <summary>
		/// Создаёт окно с заголовком и текстом.
		/// </summary>
		public TextViewerDialog(string title, string content)
		{
			Text = title;
			UiStyle.EnableDpiScaling(this);
			StartPosition = FormStartPosition.CenterParent;
			ShowInTaskbar = false;
			MinimizeBox = false;
			ClientSize = new Size(760, 520);

			TextBox contentTextBox = new TextBox();
			contentTextBox.Multiline = true;
			contentTextBox.ReadOnly = true;
			contentTextBox.ScrollBars = ScrollBars.Both;
			contentTextBox.WordWrap = false;
			contentTextBox.Font = UiStyle.MonospaceFont;
			contentTextBox.BackColor = SystemColors.Window;
			contentTextBox.Text = content;
			contentTextBox.Dock = DockStyle.Fill;

			FlowLayoutPanel buttonPanel = new FlowLayoutPanel();
			buttonPanel.Dock = DockStyle.Bottom;
			buttonPanel.FlowDirection = FlowDirection.RightToLeft;
			buttonPanel.Height = 42;
			buttonPanel.Padding = new Padding(6);

			Button closeButton = new Button();
			closeButton.Text = "Закрыть";
			closeButton.Width = 100;
			closeButton.DialogResult = DialogResult.Cancel;

			Button copyButton = new Button();
			copyButton.Text = "Копировать";
			copyButton.Width = 110;
			copyButton.Click += delegate
			{
				Clipboard.SetText(content);
				Logger.Info("Сведения скопированы в буфер обмена: " + title);
			};

			buttonPanel.Controls.Add(closeButton);
			buttonPanel.Controls.Add(copyButton);
			Controls.Add(contentTextBox);
			Controls.Add(buttonPanel);
			CancelButton = closeButton;
		}
	}

	/// <summary>
	/// Выбор папок, в которых искать файлы сертификатов на сканируемых ПК (папки указывает тот, кто собирает сертификаты).
	/// </summary>
	public sealed class ScanFoldersDialog : Form
	{
		private readonly DataGridView foldersGrid;

		/// <summary>
		/// Выбранные папки (заполняется при нажатии «Сохранить»).
		/// </summary>
		public List<ScanDirectoryEntry> Directories { get; private set; }

		/// <summary>
		/// Создаёт диалог с текущим списком папок.
		/// </summary>
		public ScanFoldersDialog(IEnumerable<ScanDirectoryEntry> currentDirectories)
		{
			Text = "Папки для поиска сертификатов";
			UiStyle.EnableDpiScaling(this);
			StartPosition = FormStartPosition.CenterParent;
			ShowInTaskbar = false;
			MinimizeBox = false;
			ClientSize = new Size(720, 420);
			MinimumSize = new Size(560, 320);
			Directories = new List<ScanDirectoryEntry>();

			Label hintLabel = new Label();
			hintLabel.Dock = DockStyle.Top;
			hintLabel.Height = 58;
			hintLabel.Padding = new Padding(8, 8, 8, 0);
			hintLabel.Text = "Пути указываются так, как они выглядят на сканируемом ПК (C:\\Certs). Можно вписать путь вручную в пустую строку таблицы. "
				+ "Маски: C:\\Users\\*\\Desktop. Эти папки используются при сканировании «Этот ПК», без агента и передаются агентам.";

			foldersGrid = new DataGridView();
			foldersGrid.Dock = DockStyle.Fill;
			foldersGrid.AllowUserToAddRows = true;
			foldersGrid.AllowUserToDeleteRows = true;
			foldersGrid.RowHeadersWidth = 28;
			foldersGrid.BackgroundColor = SystemColors.Window;
			foldersGrid.ColumnHeadersHeightSizeMode = DataGridViewColumnHeadersHeightSizeMode.AutoSize;
			DataGridViewTextBoxColumn pathColumn = new DataGridViewTextBoxColumn();
			pathColumn.Name = "Path";
			pathColumn.HeaderText = "Папка";
			pathColumn.AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill;
			DataGridViewCheckBoxColumn recursiveColumn = new DataGridViewCheckBoxColumn();
			recursiveColumn.Name = "Recursive";
			recursiveColumn.HeaderText = "С подпапками";
			recursiveColumn.Width = 110;
			foldersGrid.Columns.Add(pathColumn);
			foldersGrid.Columns.Add(recursiveColumn);
			foldersGrid.DefaultValuesNeeded += delegate (object sender, DataGridViewRowEventArgs eventArgs)
			{
				eventArgs.Row.Cells["Recursive"].Value = true;
			};
			foreach (ScanDirectoryEntry entry in currentDirectories)
			{
				foldersGrid.Rows.Add(entry.Path, entry.Recursive);
			}

			FlowLayoutPanel buttonPanel = new FlowLayoutPanel();
			buttonPanel.Dock = DockStyle.Bottom;
			buttonPanel.Height = 44;
			buttonPanel.Padding = new Padding(6);

			Button browseButton = new Button();
			browseButton.Text = "Добавить папку…";
			browseButton.AutoSize = true;
			browseButton.Click += OnBrowseClick;

			Button removeButton = new Button();
			removeButton.Text = "Удалить выбранные";
			removeButton.AutoSize = true;
			removeButton.Click += delegate
			{
				foreach (DataGridViewRow row in foldersGrid.SelectedRows)
				{
					if (!row.IsNewRow)
					{
						foldersGrid.Rows.Remove(row);
					}
				}
			};

			Button saveButton = new Button();
			saveButton.Text = "Сохранить";
			saveButton.Font = UiStyle.BoldFont;
			saveButton.AutoSize = true;
			saveButton.Click += OnSaveClick;

			Button cancelButton = new Button();
			cancelButton.Text = "Отмена";
			cancelButton.AutoSize = true;
			cancelButton.DialogResult = DialogResult.Cancel;

			buttonPanel.Controls.Add(browseButton);
			buttonPanel.Controls.Add(removeButton);
			buttonPanel.Controls.Add(saveButton);
			buttonPanel.Controls.Add(cancelButton);

			Controls.Add(foldersGrid);
			Controls.Add(hintLabel);
			Controls.Add(buttonPanel);
			CancelButton = cancelButton;
		}

		/// <summary>
		/// Добавляет папку через стандартный диалог выбора.
		/// </summary>
		private void OnBrowseClick(object sender, EventArgs eventArgs)
		{
			using (FolderBrowserDialog dialog = new FolderBrowserDialog())
			{
				dialog.Description = "Папка для поиска файлов сертификатов";
				if (dialog.ShowDialog(this) == DialogResult.OK)
				{
					foldersGrid.Rows.Add(dialog.SelectedPath, true);
				}
			}
		}

		/// <summary>
		/// Собирает список папок из таблицы (без пустых строк и повторов) и закрывает диалог.
		/// </summary>
		private void OnSaveClick(object sender, EventArgs eventArgs)
		{
			foldersGrid.EndEdit();
			List<ScanDirectoryEntry> directories = new List<ScanDirectoryEntry>();
			HashSet<string> seenPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
			foreach (DataGridViewRow row in foldersGrid.Rows)
			{
				if (row.IsNewRow)
				{
					continue;
				}
				string path = Convert.ToString(row.Cells["Path"].Value);
				if (string.IsNullOrWhiteSpace(path) || !seenPaths.Add(path.Trim().TrimEnd('\\')))
				{
					continue;
				}
				bool recursive = row.Cells["Recursive"].Value is bool && (bool)row.Cells["Recursive"].Value;
				directories.Add(new ScanDirectoryEntry(path.Trim(), recursive));
			}
			if (directories.Count == 0)
			{
				DialogResult answer = MessageBox.Show(this, "Папки не указаны: файлы сертификатов искаться не будут, проверятся только хранилища Windows и контейнеры КриптоПро. Продолжить?",
					Text, MessageBoxButtons.YesNo, MessageBoxIcon.Question);
				if (answer != DialogResult.Yes)
				{
					return;
				}
			}
			Directories = directories;
			DialogResult = DialogResult.OK;
			Close();
		}
	}

	/// <summary>
	/// Список паролей для файлов PKCS#12 (.p12/.pfx). Пароли не показываются на экране.
	/// </summary>
	public sealed class PasswordListDialog : Form
	{
		private readonly List<string> passwords;
		private readonly ListBox passwordsListBox;
		private readonly TextBox newPasswordTextBox;

		/// <summary>
		/// Итоговый список паролей.
		/// </summary>
		public List<string> Passwords
		{
			get { return new List<string>(passwords); }
		}

		/// <summary>
		/// Создаёт диалог с текущим списком паролей.
		/// </summary>
		public PasswordListDialog(IEnumerable<string> currentPasswords)
		{
			Text = "Пароли для файлов .p12/.pfx";
			UiStyle.EnableDpiScaling(this);
			StartPosition = FormStartPosition.CenterParent;
			FormBorderStyle = FormBorderStyle.FixedDialog;
			MinimizeBox = false;
			MaximizeBox = false;
			ShowInTaskbar = false;
			ClientSize = new Size(480, 330);
			passwords = new List<string>(currentPasswords);

			Label hintLabel = new Label();
			hintLabel.AutoSize = false;
			hintLabel.SetBounds(12, 10, 456, 48);
			hintLabel.Text = "Файлы PKCS#12 содержат закрытый ключ и обычно закрыты паролем. Программа пробует эти пароли по очереди, "
				+ "чтобы прочитать открытую часть сертификата. Пароли хранятся зашифрованными (DPAPI) и агентам не передаются.";

			newPasswordTextBox = new TextBox();
			newPasswordTextBox.UseSystemPasswordChar = true;
			newPasswordTextBox.SetBounds(12, 66, 340, 24);

			Button addButton = new Button();
			addButton.Text = "Добавить";
			addButton.SetBounds(358, 64, 110, 28);
			addButton.Click += delegate
			{
				if (newPasswordTextBox.Text.Length > 0 && !passwords.Contains(newPasswordTextBox.Text))
				{
					passwords.Add(newPasswordTextBox.Text);
					RefreshList();
				}
				newPasswordTextBox.Clear();
				newPasswordTextBox.Focus();
			};

			passwordsListBox = new ListBox();
			passwordsListBox.SetBounds(12, 100, 340, 180);

			Button removeButton = new Button();
			removeButton.Text = "Удалить";
			removeButton.SetBounds(358, 100, 110, 28);
			removeButton.Click += delegate
			{
				int index = passwordsListBox.SelectedIndex;
				if (index >= 0 && index < passwords.Count)
				{
					passwords.RemoveAt(index);
					RefreshList();
				}
			};

			Button okButton = new Button();
			okButton.Text = "Сохранить";
			okButton.DialogResult = DialogResult.OK;
			okButton.SetBounds(262, 292, 100, 28);

			Button cancelButton = new Button();
			cancelButton.Text = "Отмена";
			cancelButton.DialogResult = DialogResult.Cancel;
			cancelButton.SetBounds(368, 292, 100, 28);

			Controls.AddRange(new Control[] { hintLabel, newPasswordTextBox, addButton, passwordsListBox, removeButton, okButton, cancelButton });
			AcceptButton = addButton;
			CancelButton = cancelButton;
			RefreshList();
		}

		/// <summary>
		/// Показывает пароли в списке в скрытом виде (только номер и длина).
		/// </summary>
		private void RefreshList()
		{
			passwordsListBox.Items.Clear();
			for (int index = 0; index < passwords.Count; index++)
			{
				passwordsListBox.Items.Add("Пароль " + (index + 1) + ": " + new string('•', Math.Min(passwords[index].Length, 12)));
			}
		}
	}

	/// <summary>
	/// Поиск агентов в подсети: перебор адресов диапазона и проверка приветствия агента на заданном порту.
	/// </summary>
	public sealed class DiscoveryDialog : Form
	{
		private const int ProbeTimeoutMilliseconds = 800;
		private const int MaxParallelProbes = 64;
		private const int MaxAddressesPerSearch = 65536;

		private readonly int agentPort;
		private readonly TextBox rangeTextBox;
		private readonly Button searchButton;
		private readonly Button addButton;
		private readonly ProgressBar progressBar;
		private readonly Label statusLabel;
		private readonly ListView resultsListView;
		private CancellationTokenSource searchCancellation;

		/// <summary>
		/// Адреса, отмеченные пользователем для добавления в список ПК.
		/// </summary>
		public List<string> SelectedHosts { get; private set; }

		/// <summary>
		/// Создаёт окно поиска агентов на указанном порту.
		/// </summary>
		public DiscoveryDialog(int agentPort)
		{
			this.agentPort = agentPort;
			SelectedHosts = new List<string>();
			Text = "Поиск агентов в локальной сети";
			UiStyle.EnableDpiScaling(this);
			StartPosition = FormStartPosition.CenterParent;
			ShowInTaskbar = false;
			MinimizeBox = false;
			ClientSize = new Size(640, 470);
			MinimumSize = new Size(560, 400);

			Label rangeLabel = new Label();
			rangeLabel.Text = "Диапазон адресов (192.168.1.1-254, 10.0.0.0/24, через запятую):";
			rangeLabel.AutoSize = true;
			rangeLabel.Location = new Point(12, 12);

			rangeTextBox = new TextBox();
			rangeTextBox.SetBounds(12, 34, 470, 24);
			rangeTextBox.Anchor = AnchorStyles.Left | AnchorStyles.Top | AnchorStyles.Right;
			rangeTextBox.Text = GuessLocalRange();

			searchButton = new Button();
			searchButton.Text = "Найти";
			searchButton.SetBounds(492, 32, 136, 28);
			searchButton.Anchor = AnchorStyles.Top | AnchorStyles.Right;
			searchButton.Click += OnSearchButtonClick;

			progressBar = new ProgressBar();
			progressBar.SetBounds(12, 68, 616, 14);
			progressBar.Anchor = AnchorStyles.Left | AnchorStyles.Top | AnchorStyles.Right;

			statusLabel = new Label();
			statusLabel.AutoSize = false;
			statusLabel.SetBounds(12, 86, 616, 20);
			statusLabel.Anchor = AnchorStyles.Left | AnchorStyles.Top | AnchorStyles.Right;
			statusLabel.ForeColor = UiStyle.MutedText;
			statusLabel.Text = "Порт агентов: " + agentPort + ". Найденные агенты появятся в списке.";

			resultsListView = new ListView();
			resultsListView.View = View.Details;
			resultsListView.CheckBoxes = true;
			resultsListView.FullRowSelect = true;
			resultsListView.GridLines = true;
			resultsListView.SetBounds(12, 110, 616, 306);
			resultsListView.Anchor = AnchorStyles.Left | AnchorStyles.Top | AnchorStyles.Right | AnchorStyles.Bottom;
			resultsListView.Columns.Add("IP-адрес", 140);
			resultsListView.Columns.Add("Имя ПК (от агента)", 220);
			resultsListView.Columns.Add("Версия агента", 230);

			addButton = new Button();
			addButton.Text = "Добавить отмеченные";
			addButton.SetBounds(352, 428, 170, 30);
			addButton.Anchor = AnchorStyles.Right | AnchorStyles.Bottom;
			addButton.Click += OnAddButtonClick;

			Button closeButton = new Button();
			closeButton.Text = "Закрыть";
			closeButton.SetBounds(528, 428, 100, 30);
			closeButton.Anchor = AnchorStyles.Right | AnchorStyles.Bottom;
			closeButton.DialogResult = DialogResult.Cancel;

			Controls.AddRange(new Control[] { rangeLabel, rangeTextBox, searchButton, progressBar, statusLabel, resultsListView, addButton, closeButton });
			CancelButton = closeButton;
			FormClosing += delegate
			{
				if (searchCancellation != null)
				{
					searchCancellation.Cancel();
				}
			};
		}

		/// <summary>
		/// Запускает или останавливает поиск агентов.
		/// </summary>
		private async void OnSearchButtonClick(object sender, EventArgs eventArgs)
		{
			if (searchCancellation != null)
			{
				searchCancellation.Cancel();
				return;
			}

			List<IPAddress> addresses;
			try
			{
				addresses = ParseAddressRanges(rangeTextBox.Text);
			}
			catch (Exception exception)
			{
				MessageBox.Show(this, exception.Message, "Неверный диапазон", MessageBoxButtons.OK, MessageBoxIcon.Warning);
				return;
			}
			if (addresses.Count == 0)
			{
				MessageBox.Show(this, "Укажите хотя бы один адрес.", "Поиск агентов", MessageBoxButtons.OK, MessageBoxIcon.Information);
				return;
			}

			Logger.Info("Поиск агентов в диапазоне «" + rangeTextBox.Text + "» (" + addresses.Count + " адресов, порт " + agentPort + ")");
			resultsListView.Items.Clear();
			searchCancellation = new CancellationTokenSource();
			searchButton.Text = "Остановить";
			progressBar.Maximum = addresses.Count;
			progressBar.Value = 0;
			int foundCount = 0;
			int checkedCount = 0;

			SemaphoreSlim limiter = new SemaphoreSlim(MaxParallelProbes);
			List<Task> probeTasks = new List<Task>();
			CancellationToken token = searchCancellation.Token;
			try
			{
				foreach (IPAddress address in addresses)
				{
					await limiter.WaitAsync(token);
					string host = address.ToString();
					Task<AgentHello> probeTask = AgentClient.ProbeAsync(host, agentPort, ProbeTimeoutMilliseconds, token);
					probeTasks.Add(probeTask.ContinueWith(delegate (Task<AgentHello> completed)
					{
						limiter.Release();
						AgentHello hello = completed.Status == TaskStatus.RanToCompletion ? completed.Result : null;
						if (IsDisposed || Disposing || !IsHandleCreated)
						{
							return;
						}
						BeginInvokeSafe(delegate
						{
							checkedCount = checkedCount + 1;
							progressBar.Value = Math.Min(progressBar.Maximum, checkedCount);
							if (hello != null)
							{
								foundCount = foundCount + 1;
								ListViewItem item = new ListViewItem(new[] { host, hello.ComputerName, hello.AgentVersion });
								item.Checked = true;
								resultsListView.Items.Add(item);
							}
							statusLabel.Text = "Проверено " + checkedCount + " из " + addresses.Count + ", найдено агентов: " + foundCount;
						});
					}, TaskScheduler.Default));
				}
				await Task.WhenAll(probeTasks);
			}
			catch (OperationCanceledException)
			{
				statusLabel.Text = "Поиск остановлен. Найдено агентов: " + foundCount;
			}
			finally
			{
				searchCancellation.Dispose();
				searchCancellation = null;
				searchButton.Text = "Найти";
			}
			Logger.Info("Поиск агентов завершён, найдено: " + foundCount);
		}

		/// <summary>
		/// Выполняет действие в потоке интерфейса, если окно ещё открыто.
		/// </summary>
		private void BeginInvokeSafe(Action action)
		{
			try
			{
				BeginInvoke(action);
			}
			catch (InvalidOperationException)
			{
				// Окно уже закрыто.
			}
		}

		/// <summary>
		/// Сохраняет отмеченные адреса и закрывает окно.
		/// </summary>
		private void OnAddButtonClick(object sender, EventArgs eventArgs)
		{
			SelectedHosts.Clear();
			foreach (ListViewItem item in resultsListView.Items)
			{
				if (item.Checked)
				{
					SelectedHosts.Add(item.Text);
				}
			}
			DialogResult = DialogResult.OK;
			Close();
		}

		/// <summary>
		/// Разбирает список диапазонов: одиночный IP, «a.b.c.d-e», «a.b.c.d-a.b.c.e», CIDR «a.b.c.d/nn».
		/// </summary>
		public static List<IPAddress> ParseAddressRanges(string text)
		{
			List<IPAddress> addresses = new List<IPAddress>();
			foreach (string rawPart in text.Split(new[] { ',', ';', ' ' }, StringSplitOptions.RemoveEmptyEntries))
			{
				string part = rawPart.Trim();
				uint first;
				uint last;
				if (part.Contains("/"))
				{
					string[] cidrParts = part.Split('/');
					int prefixLength;
					if (!int.TryParse(cidrParts[1], out prefixLength) || prefixLength < 16 || prefixLength > 32)
					{
						throw new FormatException("Длина префикса должна быть от 16 до 32: " + part);
					}
					uint network = ToUInt32(ParseIPv4(cidrParts[0]));
					uint mask = prefixLength == 32 ? uint.MaxValue : ~(uint.MaxValue >> prefixLength);
					first = network & mask;
					last = first | ~mask;
					if (prefixLength < 31)
					{
						first = first + 1;
						last = last - 1;
					}
				}
				else if (part.Contains("-"))
				{
					string[] rangeParts = part.Split('-');
					first = ToUInt32(ParseIPv4(rangeParts[0]));
					if (rangeParts[1].Contains("."))
					{
						last = ToUInt32(ParseIPv4(rangeParts[1]));
					}
					else
					{
						byte lastOctet;
						if (!byte.TryParse(rangeParts[1], out lastOctet))
						{
							throw new FormatException("Неверный конец диапазона: " + part);
						}
						last = (first & 0xFFFFFF00u) | lastOctet;
					}
				}
				else
				{
					first = ToUInt32(ParseIPv4(part));
					last = first;
				}
				if (last < first)
				{
					throw new FormatException("Конец диапазона меньше начала: " + part);
				}
				for (uint value = first; value <= last; value++)
				{
					addresses.Add(FromUInt32(value));
					if (addresses.Count > MaxAddressesPerSearch)
					{
						throw new FormatException("Слишком большой диапазон (больше " + MaxAddressesPerSearch + " адресов)");
					}
					if (value == uint.MaxValue)
					{
						break;
					}
				}
			}
			return addresses;
		}

		/// <summary>
		/// Предлагает диапазон /24 по первому активному IPv4-адресу этого ПК.
		/// </summary>
		private static string GuessLocalRange()
		{
			try
			{
				foreach (NetworkInterface networkInterface in NetworkInterface.GetAllNetworkInterfaces())
				{
					if (networkInterface.OperationalStatus != OperationalStatus.Up || networkInterface.NetworkInterfaceType == NetworkInterfaceType.Loopback)
					{
						continue;
					}
					foreach (UnicastIPAddressInformation unicast in networkInterface.GetIPProperties().UnicastAddresses)
					{
						if (unicast.Address.AddressFamily != AddressFamily.InterNetwork)
						{
							continue;
						}
						byte[] bytes = unicast.Address.GetAddressBytes();
						if (bytes[0] == 169 && bytes[1] == 254)
						{
							continue;
						}
						return bytes[0] + "." + bytes[1] + "." + bytes[2] + ".1-254";
					}
				}
			}
			catch (NetworkInformationException)
			{
				// Нет сведений об интерфейсах — пусть пользователь введёт диапазон сам.
			}
			return "192.168.1.1-254";
		}

		/// <summary>
		/// Разбирает IPv4-адрес; бросает FormatException для некорректных или IPv6-адресов.
		/// </summary>
		private static IPAddress ParseIPv4(string text)
		{
			IPAddress address;
			if (!IPAddress.TryParse(text.Trim(), out address) || address.AddressFamily != AddressFamily.InterNetwork)
			{
				throw new FormatException("Неверный IPv4-адрес: " + text);
			}
			return address;
		}

		/// <summary>
		/// Преобразует IPv4-адрес в число (старший октет — старшие биты).
		/// </summary>
		private static uint ToUInt32(IPAddress address)
		{
			byte[] bytes = address.GetAddressBytes();
			return ((uint)bytes[0] << 24) | ((uint)bytes[1] << 16) | ((uint)bytes[2] << 8) | bytes[3];
		}

		/// <summary>
		/// Преобразует число в IPv4-адрес.
		/// </summary>
		private static IPAddress FromUInt32(uint value)
		{
			return new IPAddress(new[] { (byte)(value >> 24), (byte)(value >> 16), (byte)(value >> 8), (byte)value });
		}
	}
}
