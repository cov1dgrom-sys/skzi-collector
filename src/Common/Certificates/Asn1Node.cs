using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;

namespace Skzi.Common.Certificates
{
	/// <summary>
	/// Узел дерева ASN.1 (DER): тег, признак составного типа, содержимое и дочерние узлы.
	/// </summary>
	public sealed class Asn1Node
	{
		public const int TagBoolean = 1;
		public const int TagInteger = 2;
		public const int TagBitString = 3;
		public const int TagOctetString = 4;
		public const int TagNull = 5;
		public const int TagObjectIdentifier = 6;
		public const int TagUtf8String = 12;
		public const int TagSequence = 16;
		public const int TagSet = 17;
		public const int TagNumericString = 18;
		public const int TagPrintableString = 19;
		public const int TagTeletexString = 20;
		public const int TagIa5String = 22;
		public const int TagUtcTime = 23;
		public const int TagGeneralizedTime = 24;
		public const int TagVisibleString = 26;
		public const int TagUniversalString = 28;
		public const int TagBmpString = 30;

		/// <summary>Класс тега: 0 — universal, 1 — application, 2 — context-specific, 3 — private.</summary>
		public int TagClass { get; private set; }

		/// <summary>Номер тега внутри класса.</summary>
		public int TagNumber { get; private set; }

		/// <summary>Признак составного (constructed) значения.</summary>
		public bool IsConstructed { get; private set; }

		/// <summary>Байты содержимого (без тега и длины).</summary>
		public byte[] Content { get; private set; }

		/// <summary>Дочерние узлы (для составных значений).</summary>
		public List<Asn1Node> Children { get; private set; }

		/// <summary>
		/// Создаёт узел ASN.1 из разобранных тега и содержимого.
		/// </summary>
		private Asn1Node(int tagClass, int tagNumber, bool isConstructed, byte[] content)
		{
			TagClass = tagClass;
			TagNumber = tagNumber;
			IsConstructed = isConstructed;
			Content = content;
			Children = new List<Asn1Node>();
		}

		/// <summary>
		/// Признак универсального типа с указанным номером тега.
		/// </summary>
		public bool IsUniversal(int tagNumber)
		{
			return TagClass == 0 && TagNumber == tagNumber;
		}

		/// <summary>
		/// Разбирает один DER-элемент из массива байт. Бросает FormatException при некорректной кодировке.
		/// </summary>
		public static Asn1Node Parse(byte[] data)
		{
			if (data == null || data.Length == 0)
			{
				throw new FormatException("Пустые данные ASN.1");
			}
			int offset = 0;
			Asn1Node node = ReadNode(data, ref offset, data.Length, 0);
			return node;
		}

		/// <summary>
		/// Пытается разобрать байты как DER-элемент, занимающий весь массив. Возвращает null при неудаче.
		/// </summary>
		public static Asn1Node TryParseExact(byte[] data)
		{
			if (data == null || data.Length < 2)
			{
				return null;
			}
			try
			{
				int offset = 0;
				Asn1Node node = ReadNode(data, ref offset, data.Length, 0);
				return offset == data.Length ? node : null;
			}
			catch (FormatException)
			{
				return null;
			}
		}

		/// <summary>
		/// Рекурсивно читает узел ASN.1 начиная с позиции offset, не выходя за границу limit.
		/// </summary>
		private static Asn1Node ReadNode(byte[] data, ref int offset, int limit, int depth)
		{
			if (depth > 64)
			{
				throw new FormatException("Слишком глубокая вложенность ASN.1");
			}
			if (offset >= limit)
			{
				throw new FormatException("Неожиданный конец данных ASN.1");
			}

			byte firstTagByte = data[offset];
			offset = offset + 1;
			int tagClass = firstTagByte >> 6;
			bool isConstructed = (firstTagByte & 0x20) != 0;
			int tagNumber = firstTagByte & 0x1F;
			if (tagNumber == 0x1F)
			{
				tagNumber = 0;
				byte tagByte;
				int guard = 0;
				do
				{
					if (offset >= limit || guard > 4)
					{
						throw new FormatException("Некорректный длинный тег ASN.1");
					}
					tagByte = data[offset];
					offset = offset + 1;
					tagNumber = (tagNumber << 7) | (tagByte & 0x7F);
					guard = guard + 1;
				}
				while ((tagByte & 0x80) != 0);
			}

			int contentLength = ReadLength(data, ref offset, limit);
			if (contentLength > limit - offset)
			{
				throw new FormatException("Длина ASN.1 выходит за границы данных");
			}

			byte[] content = new byte[contentLength];
			Buffer.BlockCopy(data, offset, content, 0, contentLength);
			Asn1Node node = new Asn1Node(tagClass, tagNumber, isConstructed, content);

			if (isConstructed)
			{
				int childOffset = offset;
				int childLimit = offset + contentLength;
				while (childOffset < childLimit)
				{
					node.Children.Add(ReadNode(data, ref childOffset, childLimit, depth + 1));
				}
			}

			offset = offset + contentLength;
			return node;
		}

		/// <summary>
		/// Читает длину DER (короткая и длинная формы; неопределённая длина запрещена в DER).
		/// </summary>
		private static int ReadLength(byte[] data, ref int offset, int limit)
		{
			if (offset >= limit)
			{
				throw new FormatException("Нет байта длины ASN.1");
			}
			int firstLengthByte = data[offset];
			offset = offset + 1;
			if (firstLengthByte < 0x80)
			{
				return firstLengthByte;
			}
			int lengthByteCount = firstLengthByte & 0x7F;
			if (lengthByteCount == 0 || lengthByteCount > 4)
			{
				throw new FormatException("Неподдерживаемая форма длины ASN.1");
			}
			long length = 0;
			for (int index = 0; index < lengthByteCount; index++)
			{
				if (offset >= limit)
				{
					throw new FormatException("Обрезанная длина ASN.1");
				}
				length = (length << 8) | data[offset];
				offset = offset + 1;
			}
			if (length > int.MaxValue)
			{
				throw new FormatException("Слишком большая длина ASN.1");
			}
			return (int)length;
		}

		/// <summary>
		/// Декодирует содержимое узла OBJECT IDENTIFIER в точечную запись (например, 1.2.643.100.3).
		/// </summary>
		public string ReadObjectIdentifier()
		{
			if (!IsUniversal(TagObjectIdentifier) || Content.Length == 0)
			{
				return null;
			}
			StringBuilder builder = new StringBuilder();
			long value = 0;
			bool isFirstArc = true;
			for (int index = 0; index < Content.Length; index++)
			{
				value = value * 128 + (Content[index] & 0x7F);
				if ((Content[index] & 0x80) == 0)
				{
					if (isFirstArc)
					{
						long firstArc = value < 80 ? value / 40 : 2;
						long secondArc = value - firstArc * 40;
						builder.Append(firstArc.ToString(CultureInfo.InvariantCulture)).Append('.')
							.Append(secondArc.ToString(CultureInfo.InvariantCulture));
						isFirstArc = false;
					}
					else
					{
						builder.Append('.').Append(value.ToString(CultureInfo.InvariantCulture));
					}
					value = 0;
				}
			}
			return builder.ToString();
		}

		/// <summary>
		/// Признак того, что узел является одним из строковых типов ASN.1.
		/// </summary>
		public bool IsStringType()
		{
			if (TagClass != 0)
			{
				return false;
			}
			switch (TagNumber)
			{
				case TagUtf8String:
				case TagNumericString:
				case TagPrintableString:
				case TagTeletexString:
				case TagIa5String:
				case TagVisibleString:
				case TagUniversalString:
				case TagBmpString:
					return true;
				default:
					return false;
			}
		}

		/// <summary>
		/// Декодирует строковое значение узла с учётом его типа (UTF8, BMP, Printable и т.д.).
		/// Для нестроковых типов возвращает null.
		/// </summary>
		public string ReadString()
		{
			if (!IsStringType())
			{
				return null;
			}
			switch (TagNumber)
			{
				case TagBmpString:
					return Encoding.BigEndianUnicode.GetString(Content);
				case TagUniversalString:
					return new UTF32Encoding(true, false).GetString(Content);
				case TagUtf8String:
					return Encoding.UTF8.GetString(Content);
				case TagTeletexString:
					return DecodeTeletex(Content);
				default:
					return Encoding.ASCII.GetString(Content);
			}
		}

		/// <summary>
		/// Декодирует TeletexString: многие УЦ кладут туда UTF-8, поэтому сначала пробуем UTF-8, затем Latin-1.
		/// </summary>
		private static string DecodeTeletex(byte[] content)
		{
			try
			{
				return new UTF8Encoding(false, true).GetString(content);
			}
			catch (ArgumentException)
			{
				return Encoding.GetEncoding(28591).GetString(content);
			}
		}

		/// <summary>
		/// Рекурсивно собирает все строковые значения из поддерева, в том числе вложенные в OCTET STRING / BIT STRING.
		/// </summary>
		public void CollectStrings(List<string> target, int depth)
		{
			if (depth > 32)
			{
				return;
			}
			string text = ReadString();
			if (text != null)
			{
				target.Add(text);
				return;
			}
			if (IsConstructed)
			{
				foreach (Asn1Node child in Children)
				{
					child.CollectStrings(target, depth + 1);
				}
				return;
			}
			if (IsUniversal(TagOctetString) || IsUniversal(TagBitString))
			{
				byte[] encapsulated = Content;
				if (IsUniversal(TagBitString) && encapsulated.Length > 0)
				{
					// Первый байт BIT STRING — количество неиспользуемых бит.
					encapsulated = new byte[Content.Length - 1];
					Buffer.BlockCopy(Content, 1, encapsulated, 0, encapsulated.Length);
				}
				Asn1Node nested = TryParseExact(encapsulated);
				if (nested != null)
				{
					nested.CollectStrings(target, depth + 1);
				}
				else if (LooksLikeText(encapsulated))
				{
					target.Add(Encoding.UTF8.GetString(encapsulated));
				}
			}
		}

		/// <summary>
		/// Проверяет, похожи ли байты на печатный текст (для «сырых» строк внутри OCTET STRING).
		/// </summary>
		public static bool LooksLikeText(byte[] bytes)
		{
			if (bytes == null || bytes.Length < 3)
			{
				return false;
			}
			int printableCount = 0;
			foreach (byte currentByte in bytes)
			{
				if ((currentByte >= 0x20 && currentByte < 0x7F) || currentByte >= 0xC0 || (currentByte >= 0x80 && currentByte < 0xC0))
				{
					printableCount = printableCount + 1;
				}
			}
			return printableCount * 100 / bytes.Length >= 90;
		}
	}
}
