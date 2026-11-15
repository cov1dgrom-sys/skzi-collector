using System;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Windows.Forms;

namespace Skzi.ControlPanel
{
	/// <summary>
	/// Общие цвета, шрифты и настройки элементов интерфейса панели (фирменный стиль ГРЧЦ: тёмно-синий + акцент).
	/// </summary>
	public static class UiStyle
	{
		// Фирменная палитра: тёмно-синий логотипа ГРЧЦ и производные тона.
		public static readonly Color HeaderBackground = Color.FromArgb(20, 41, 77);
		public static readonly Color HeaderBackgroundDark = Color.FromArgb(13, 27, 54);
		public static readonly Color HeaderHairline = Color.FromArgb(62, 86, 134);
		public static readonly Color AccentBlue = Color.FromArgb(37, 99, 235);
		public static readonly Color AccentRed = Color.FromArgb(200, 32, 44);
		public static readonly Color PageBackground = Color.FromArgb(243, 245, 249);
		public static readonly Color CardBackground = Color.White;
		public static readonly Color CardBorder = Color.FromArgb(222, 226, 233);
		public static readonly Color ToolStripBackground = Color.FromArgb(248, 249, 251);
		public static readonly Color ToolButtonHover = Color.FromArgb(224, 232, 247);
		public static readonly Color ToolButtonPressed = Color.FromArgb(205, 219, 244);
		public static readonly Color ExpiredRow = Color.FromArgb(253, 226, 226);
		public static readonly Color ExpiringRow = Color.FromArgb(255, 244, 214);
		public static readonly Color SuccessText = Color.FromArgb(22, 128, 61);
		public static readonly Color ErrorText = Color.FromArgb(185, 28, 28);
		public static readonly Color ProgressText = Color.FromArgb(29, 78, 216);
		public static readonly Color MutedText = Color.FromArgb(100, 100, 110);
		public static readonly Color HeaderSubtitle = Color.FromArgb(176, 192, 222);

		public static readonly Font BaseFont = new Font("Segoe UI", 9F, FontStyle.Regular, GraphicsUnit.Point);
		public static readonly Font BoldFont = new Font("Segoe UI", 9F, FontStyle.Bold, GraphicsUnit.Point);
		public static readonly Font TitleFont = new Font("Segoe UI Semibold", 15F, FontStyle.Regular, GraphicsUnit.Point);
		public static readonly Font SubtitleFont = new Font("Segoe UI", 8.5F, FontStyle.Regular, GraphicsUnit.Point);
		public static readonly Font SectionFont = new Font("Segoe UI Semibold", 9.5F, FontStyle.Regular, GraphicsUnit.Point);
		public static readonly Font MonospaceFont = new Font("Consolas", 9F, FontStyle.Regular, GraphicsUnit.Point);

		/// <summary>
		/// Включает масштабирование окна по DPI: размеры в коде задаются для 96 DPI и пересчитываются для текущего монитора.
		/// </summary>
		public static void EnableDpiScaling(Form form)
		{
			form.Font = BaseFont;
			form.AutoScaleDimensions = new SizeF(96F, 96F);
			form.AutoScaleMode = AutoScaleMode.Dpi;
		}

		/// <summary>
		/// Применяет единый стиль к таблице: только чтение, выделение строк, чередование цветов.
		/// </summary>
		public static void ApplyGridStyle(DataGridView grid)
		{
			grid.AllowUserToAddRows = false;
			grid.AllowUserToDeleteRows = false;
			grid.AllowUserToResizeRows = false;
			grid.ReadOnly = true;
			grid.SelectionMode = DataGridViewSelectionMode.FullRowSelect;
			grid.MultiSelect = true;
			grid.RowHeadersVisible = false;
			grid.BackgroundColor = SystemColors.Window;
			grid.BorderStyle = BorderStyle.None;
			grid.CellBorderStyle = DataGridViewCellBorderStyle.SingleHorizontal;
			grid.ColumnHeadersDefaultCellStyle.Font = BoldFont;
			grid.ColumnHeadersHeightSizeMode = DataGridViewColumnHeadersHeightSizeMode.AutoSize;
			grid.EnableHeadersVisualStyles = true;
			grid.AlternatingRowsDefaultCellStyle.BackColor = Color.FromArgb(247, 248, 250);
			grid.DefaultCellStyle.SelectionBackColor = Color.FromArgb(204, 224, 255);
			grid.DefaultCellStyle.SelectionForeColor = Color.Black;
			grid.AutoSizeRowsMode = DataGridViewAutoSizeRowsMode.None;
			grid.RowTemplate.Height = 24;
			typeof(DataGridView).InvokeMember("DoubleBuffered",
				System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.SetProperty,
				null, grid, new object[] { true });
		}

		/// <summary>
		/// Добавляет в таблицу текстовый столбец с заголовком и шириной.
		/// </summary>
		public static DataGridViewTextBoxColumn AddTextColumn(DataGridView grid, string name, string header, int width)
		{
			DataGridViewTextBoxColumn column = new DataGridViewTextBoxColumn();
			column.Name = name;
			column.HeaderText = header;
			column.Width = width;
			column.FillWeight = width;
			column.MinimumWidth = Math.Min(width, 60);
			column.SortMode = DataGridViewColumnSortMode.Automatic;
			grid.Columns.Add(column);
			return column;
		}

		/// <summary>
		/// Создаёт кнопку панели инструментов с текстом и подсказкой.
		/// </summary>
		public static ToolStripButton CreateToolButton(string text, string toolTip, EventHandler onClick)
		{
			ToolStripButton button = new ToolStripButton(text);
			button.DisplayStyle = ToolStripItemDisplayStyle.Text;
			button.ToolTipText = toolTip;
			button.Click += onClick;
			button.Margin = new Padding(2, 1, 2, 1);
			button.Padding = new Padding(8, 4, 8, 4);
			return button;
		}

		/// <summary>
		/// Создаёт панель инструментов с единым плоским оформлением (подсветка кнопок при наведении).
		/// </summary>
		public static ToolStrip CreateToolStrip()
		{
			ToolStrip toolStrip = new ToolStrip();
			toolStrip.GripStyle = ToolStripGripStyle.Hidden;
			toolStrip.Padding = new Padding(8, 5, 8, 5);
			toolStrip.Font = BaseFont;
			toolStrip.Renderer = new FlatToolStripRenderer();
			toolStrip.BackColor = ToolStripBackground;
			return toolStrip;
		}

		/// <summary>
		/// Создаёт подпись-заголовок раздела (например, «Где искать:») в едином стиле.
		/// </summary>
		public static Label CreateSectionLabel(string text)
		{
			Label label = new Label();
			label.Text = text;
			label.Font = SectionFont;
			label.ForeColor = Color.FromArgb(55, 65, 81);
			label.AutoSize = true;
			return label;
		}

		/// <summary>
		/// Оборачивает содержимое в «карточку»: белый фон, тонкая рамка, внутренние отступы.
		/// </summary>
		public static Panel CreateCard(Control content)
		{
			Panel card = new Panel();
			card.BackColor = CardBackground;
			card.Padding = new Padding(1);
			card.Paint += delegate (object sender, PaintEventArgs e)
			{
				Rectangle bounds = new Rectangle(0, 0, card.Width - 1, card.Height - 1);
				using (Pen pen = new Pen(CardBorder))
				{
					e.Graphics.DrawRectangle(pen, bounds);
				}
			};
			if (content != null)
			{
				content.Dock = DockStyle.Fill;
				card.Controls.Add(content);
			}
			return card;
		}
	}

	/// <summary>
	/// Плоский рисовальщик панели инструментов: без объёмных градиентов, с мягкой подсветкой кнопок.
	/// </summary>
	public sealed class FlatToolStripRenderer : ToolStripProfessionalRenderer
	{
		/// <summary>
		/// Создаёт рисовальщик с фирменной цветовой таблицей.
		/// </summary>
		public FlatToolStripRenderer() : base(new FlatColorTable())
		{
			RoundedEdges = false;
		}

		/// <summary>
		/// Убирает рамку панели инструментов.
		/// </summary>
		protected override void OnRenderToolStripBorder(ToolStripRenderEventArgs e)
		{
			// Нижняя тонкая линия-разделитель вместо объёмной рамки.
			using (Pen pen = new Pen(UiStyle.CardBorder))
			{
				e.Graphics.DrawLine(pen, 0, e.ToolStrip.Height - 1, e.ToolStrip.Width, e.ToolStrip.Height - 1);
			}
		}

		/// <summary>
		/// Рисует фон кнопки: подсветка при наведении и нажатии, скруглённые углы.
		/// </summary>
		protected override void OnRenderButtonBackground(ToolStripItemRenderEventArgs e)
		{
			ToolStripButton button = e.Item as ToolStripButton;
			bool highlight = e.Item.Selected || e.Item.Pressed || (button != null && button.Checked);
			if (!highlight)
			{
				return;
			}
			Color fill = e.Item.Pressed || (button != null && button.Checked) ? UiStyle.ToolButtonPressed : UiStyle.ToolButtonHover;
			Rectangle bounds = new Rectangle(1, 1, e.Item.Width - 3, e.Item.Height - 3);
			using (SolidBrush brush = new SolidBrush(fill))
			{
				e.Graphics.SmoothingMode = SmoothingMode.AntiAlias;
				e.Graphics.FillRectangle(brush, bounds);
			}
		}
	}

	/// <summary>
	/// Цветовая таблица для плоских панелей инструментов.
	/// </summary>
	public sealed class FlatColorTable : ProfessionalColorTable
	{
		public override Color ToolStripGradientBegin { get { return UiStyle.ToolStripBackground; } }
		public override Color ToolStripGradientMiddle { get { return UiStyle.ToolStripBackground; } }
		public override Color ToolStripGradientEnd { get { return UiStyle.ToolStripBackground; } }
		public override Color SeparatorDark { get { return UiStyle.CardBorder; } }
		public override Color SeparatorLight { get { return UiStyle.CardBorder; } }
	}

	/// <summary>
	/// Панель заголовка окна: горизонтальный градиент фирменного синего, название модуля, подпись,
	/// логотип заказчика справа и тонкая акцентная линия снизу. Всё рисуется напрямую, без дочерних
	/// элементов, чтобы не было проблем с прозрачностью поверх градиента.
	/// </summary>
	public sealed class HeaderPanel : Panel
	{
		private string titleText = string.Empty;
		private string subtitleText = string.Empty;
		private Image logoImage;
		private string logoToolTip;
		private readonly ToolTip toolTip = new ToolTip();

		/// <summary>
		/// Включает двойную буферизацию, чтобы градиент не мерцал.
		/// </summary>
		public HeaderPanel()
		{
			DoubleBuffered = true;
			ResizeRedraw = true;
		}

		/// <summary>
		/// Название модуля (крупная строка слева).
		/// </summary>
		public string Title
		{
			get { return titleText; }
			set { titleText = value ?? string.Empty; Invalidate(); }
		}

		/// <summary>
		/// Подпись под названием.
		/// </summary>
		public string Subtitle
		{
			get { return subtitleText; }
			set { subtitleText = value ?? string.Empty; Invalidate(); }
		}

		/// <summary>
		/// Логотип заказчика (рисуется справа с сохранением пропорций) и подсказка к нему.
		/// </summary>
		public void SetLogo(Image image, string toolTipText)
		{
			logoImage = image;
			logoToolTip = toolTipText;
			Invalidate();
		}

		/// <summary>
		/// Рисует фон-градиент, тексты, логотип и нижнюю акцентную линию.
		/// </summary>
		protected override void OnPaint(PaintEventArgs e)
		{
			base.OnPaint(e);
			Graphics graphics = e.Graphics;
			Rectangle area = new Rectangle(0, 0, Width, Height);
			using (LinearGradientBrush brush = new LinearGradientBrush(area, UiStyle.HeaderBackground, UiStyle.HeaderBackgroundDark, LinearGradientMode.Horizontal))
			{
				graphics.FillRectangle(brush, area);
			}

			int logoRight = Width - 20;
			if (logoImage != null && logoImage.Width > 0 && logoImage.Height > 0)
			{
				int maxHeight = 34;
				int logoHeight = Math.Min(maxHeight, Height - 34);
				int logoWidth = (int)Math.Round(logoImage.Width * (logoHeight / (double)logoImage.Height));
				int logoX = Width - 20 - logoWidth;
				int logoY = (Height - 2 - logoHeight) / 2;
				graphics.InterpolationMode = InterpolationMode.HighQualityBicubic;
				graphics.PixelOffsetMode = PixelOffsetMode.Half;
				Rectangle logoRect = new Rectangle(logoX, logoY, logoWidth, logoHeight);
				graphics.DrawImage(logoImage, logoRect);
				logoRight = logoX - 16;
				UpdateLogoToolTip(logoRect);
			}

			int textLeft = Padding.Left;
			int available = Math.Max(120, logoRight - textLeft);
			if (titleText.Length > 0)
			{
				TextRenderer.DrawText(graphics, titleText, UiStyle.TitleFont, new Rectangle(textLeft, 11, available, 30),
					Color.White, TextFormatFlags.NoPrefix | TextFormatFlags.EndEllipsis | TextFormatFlags.Left);
			}
			if (subtitleText.Length > 0)
			{
				TextRenderer.DrawText(graphics, subtitleText, UiStyle.SubtitleFont, new Rectangle(textLeft + 1, 45, available, 20),
					UiStyle.HeaderSubtitle, TextFormatFlags.NoPrefix | TextFormatFlags.EndEllipsis | TextFormatFlags.Left);
			}

			using (Pen hairline = new Pen(UiStyle.HeaderHairline))
			{
				graphics.DrawLine(hairline, 0, Height - 3, Width, Height - 3);
			}
			using (SolidBrush accent = new SolidBrush(UiStyle.AccentRed))
			{
				graphics.FillRectangle(accent, 0, Height - 2, Width, 2);
			}
		}

		/// <summary>
		/// Привязывает подсказку логотипа к занимаемой им области (через невидимую метку поверх).
		/// </summary>
		private Label logoHotspot;
		private void UpdateLogoToolTip(Rectangle logoRect)
		{
			if (string.IsNullOrEmpty(logoToolTip))
			{
				return;
			}
			if (logoHotspot == null)
			{
				logoHotspot = new Label();
				logoHotspot.BackColor = Color.Transparent;
				logoHotspot.Cursor = Cursors.Hand;
				Controls.Add(logoHotspot);
			}
			logoHotspot.Bounds = logoRect;
			toolTip.SetToolTip(logoHotspot, logoToolTip);
		}
	}
}
