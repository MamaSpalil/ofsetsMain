#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
unpack_main.py — Скрипт для полной распаковки main.exe и удаления ASProtect

Описание:
    Этот скрипт удаляет защиту ASProtect из файла main.exe (MU Online Game Client).
    ASProtect добавляет 5 секций в PE-файл:
        .zero     — пустая секция-заполнитель (2 штуки)
        .as_0001  — код распаковщика ASProtect
        .as_0002  — дополнительный код защиты
        .LibHook  — точка входа с проверкой main.dll

    Скрипт выполняет:
        1. Восстановление украденных байтов в точке входа (OEP)
        2. Исправление AddressOfEntryPoint на оригинальную точку входа
        3. Удаление 5 секций ASProtect из заголовков PE
        4. Обрезку файла (удаление данных ASProtect)
        5. Пересчёт SizeOfImage и NumberOfSections
        6. Очистку указателей на ASProtect в секции .data

Использование:
    python3 unpack_main.py [input_file] [output_file]

    По умолчанию:
        input_file  = main.exe
        output_file = main_unpacked.exe
"""

import struct
import sys
import os


# ============================================================================
#  Константы
# ============================================================================

IMAGE_BASE = 0x00400000

# Оригинальная точка входа (OEP) — WinMainCRTStartup (MSVC 6.0 CRT)
# VA: 0x00794510, RVA: 0x00394510
OEP_RVA = 0x00394510
OEP_VA = IMAGE_BASE + OEP_RVA

# Украденные байты OEP (6 байтов, обнулённые ASProtect)
# Оригинальный пролог:
#   55       PUSH EBP
#   8B EC    MOV EBP, ESP
#   83 EC 68 SUB ESP, 0x68   (104 байта для локальных переменных)
STOLEN_BYTES = bytes([0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x68])
STOLEN_BYTES_FILE_OFFSET = 0x00393910  # File offset OEP в .text

# Секции ASProtect (индексы 5-9 в таблице секций)
ASPROTECT_SECTION_NAMES = ['.zero', '.as_0001', '.as_0002', '.LibHook']
ASPROTECT_SECTION_COUNT = 5  # .zero, .as_0001, .zero, .as_0002, .LibHook
ORIGINAL_SECTION_COUNT = 5   # .text, .data, (unnamed), .rsrc, .idata

# Смещения в PE-заголовках
PE_SIGNATURE_OFFSET_LOCATION = 0x3C  # e_lfanew в DOS Header
COFF_HEADER_OFFSET = 4               # Смещение COFF Header после PE Signature

# Указатель в .data на ASProtect (нужно очистить)
ASPROTECT_DATA_POINTER_FILE_OFFSET = 0x003CB2C0  # .data pointer to 0x091684CE

# Конец полезных данных файла (после .idata секции)
CLEAN_FILE_END = 0x003F5000  # Конец .idata raw data


# ============================================================================
#  Вспомогательные функции
# ============================================================================

def read_uint16(data, offset):
    """Прочитать 16-битное целое (little-endian)."""
    return struct.unpack_from('<H', data, offset)[0]


def read_uint32(data, offset):
    """Прочитать 32-битное целое (little-endian)."""
    return struct.unpack_from('<I', data, offset)[0]


def write_uint16(data, offset, value):
    """Записать 16-битное целое (little-endian)."""
    struct.pack_into('<H', data, offset, value)


def write_uint32(data, offset, value):
    """Записать 32-битное целое (little-endian)."""
    struct.pack_into('<I', data, offset, value)


def get_section_name(data, section_offset):
    """Получить имя секции из заголовка секции."""
    raw = data[section_offset:section_offset + 8]
    return raw.split(b'\x00')[0].decode('ascii', errors='replace')


# ============================================================================
#  Основная логика распаковки
# ============================================================================

def unpack(input_path, output_path):
    """Распаковать main.exe: удалить ASProtect и восстановить OEP."""

    print(f"[*] Чтение файла: {input_path}")
    with open(input_path, 'rb') as f:
        raw_data = f.read()

    original_size = len(raw_data)
    print(f"[*] Размер оригинала: {original_size} байт (0x{original_size:08X})")

    # Работаем с изменяемым буфером
    data = bytearray(raw_data)

    # -----------------------------------------------------------------------
    # 1. Проверка PE-сигнатуры
    # -----------------------------------------------------------------------
    if data[0:2] != b'MZ':
        print("[!] Ошибка: файл не является PE-файлом (нет MZ-сигнатуры)")
        return False

    pe_offset = read_uint32(data, 0x3C)  # e_lfanew
    if data[pe_offset:pe_offset + 4] != b'PE\x00\x00':
        print("[!] Ошибка: не найдена PE-сигнатура")
        return False

    print(f"[*] PE-заголовок: смещение 0x{pe_offset:08X}")

    coff_offset = pe_offset + 4
    optional_offset = coff_offset + 20  # COFF Header = 20 байт

    # Текущие значения заголовков
    num_sections = read_uint16(data, coff_offset + 2)
    entry_point_rva = read_uint32(data, optional_offset + 16)
    size_of_image = read_uint32(data, optional_offset + 56)
    size_of_headers = read_uint32(data, optional_offset + 60)

    print(f"[*] NumberOfSections: {num_sections}")
    print(f"[*] Текущий EntryPoint (RVA): 0x{entry_point_rva:08X} "
          f"(VA: 0x{IMAGE_BASE + entry_point_rva:08X})")
    print(f"[*] SizeOfImage: 0x{size_of_image:08X}")

    if num_sections != 10:
        print(f"[!] Предупреждение: ожидалось 10 секций, найдено {num_sections}")

    # -----------------------------------------------------------------------
    # 2. Анализ таблицы секций
    # -----------------------------------------------------------------------
    # Optional Header Size
    opt_header_size = read_uint16(data, coff_offset + 16)
    sections_offset = optional_offset + opt_header_size

    print(f"\n[*] Таблица секций (смещение 0x{sections_offset:08X}):")
    for i in range(num_sections):
        sec_off = sections_offset + i * 40
        name = get_section_name(data, sec_off)
        virt_size = read_uint32(data, sec_off + 8)
        virt_addr = read_uint32(data, sec_off + 12)
        raw_size = read_uint32(data, sec_off + 16)
        raw_ptr = read_uint32(data, sec_off + 20)
        chars = read_uint32(data, sec_off + 36)
        va = IMAGE_BASE + virt_addr
        is_asprotect = (i >= ORIGINAL_SECTION_COUNT)
        marker = " [ASProtect]" if is_asprotect else ""
        print(f"    [{i}] '{name}' VA=0x{va:08X} VSize=0x{virt_size:08X} "
              f"Raw=0x{raw_ptr:08X}+0x{raw_size:08X} Chars=0x{chars:08X}{marker}")

    # -----------------------------------------------------------------------
    # 3. Восстановление украденных байтов OEP
    # -----------------------------------------------------------------------
    print(f"\n[*] Восстановление украденных байтов OEP")
    print(f"    Адрес: VA 0x{OEP_VA:08X}, File offset 0x{STOLEN_BYTES_FILE_OFFSET:08X}")

    # Проверяем что текущие байты действительно обнулены
    current_oep_bytes = data[STOLEN_BYTES_FILE_OFFSET:STOLEN_BYTES_FILE_OFFSET + 6]
    print(f"    Текущие байты: {' '.join(f'{b:02X}' for b in current_oep_bytes)}")

    if current_oep_bytes != b'\x00\x00\x00\x00\x00\x00':
        print(f"[!] Предупреждение: OEP байты не обнулены!")
        print(f"    Ожидалось: 00 00 00 00 00 00")

    data[STOLEN_BYTES_FILE_OFFSET:STOLEN_BYTES_FILE_OFFSET + 6] = STOLEN_BYTES
    print(f"    Восстановлено: {' '.join(f'{b:02X}' for b in STOLEN_BYTES)}")
    print(f"    55 = PUSH EBP")
    print(f"    8B EC = MOV EBP, ESP")
    print(f"    83 EC 68 = SUB ESP, 0x68")

    # -----------------------------------------------------------------------
    # 4. Исправление AddressOfEntryPoint
    # -----------------------------------------------------------------------
    print(f"\n[*] Исправление точки входа")
    print(f"    Старая: RVA 0x{entry_point_rva:08X} (VA 0x{IMAGE_BASE + entry_point_rva:08X}) "
          f"[в .LibHook]")

    write_uint32(data, optional_offset + 16, OEP_RVA)
    print(f"    Новая:  RVA 0x{OEP_RVA:08X} (VA 0x{OEP_VA:08X}) "
          f"[WinMainCRTStartup в .text]")

    # -----------------------------------------------------------------------
    # 5. Обновление NumberOfSections
    # -----------------------------------------------------------------------
    print(f"\n[*] Обновление количества секций: {num_sections} -> {ORIGINAL_SECTION_COUNT}")
    write_uint16(data, coff_offset + 2, ORIGINAL_SECTION_COUNT)

    # -----------------------------------------------------------------------
    # 6. Пересчёт SizeOfImage
    # -----------------------------------------------------------------------
    # Последняя оставшаяся секция — .idata (секция 4)
    last_sec_off = sections_offset + (ORIGINAL_SECTION_COUNT - 1) * 40
    last_virt_addr = read_uint32(data, last_sec_off + 12)
    last_virt_size = read_uint32(data, last_sec_off + 8)

    section_alignment = read_uint32(data, optional_offset + 32)
    new_image_end = last_virt_addr + last_virt_size
    # Выравнивание по SectionAlignment
    if new_image_end % section_alignment != 0:
        new_image_end = ((new_image_end // section_alignment) + 1) * section_alignment

    print(f"\n[*] Пересчёт SizeOfImage")
    print(f"    Старый: 0x{size_of_image:08X}")
    print(f"    Новый:  0x{new_image_end:08X}")
    write_uint32(data, optional_offset + 56, new_image_end)

    # -----------------------------------------------------------------------
    # 7. Очистка заголовков ASProtect-секций (обнуление)
    # -----------------------------------------------------------------------
    print(f"\n[*] Очистка заголовков ASProtect-секций")
    for i in range(ORIGINAL_SECTION_COUNT, num_sections):
        sec_off = sections_offset + i * 40
        name = get_section_name(data, sec_off)
        print(f"    Очистка секции [{i}] '{name}' (заголовок +0x{sec_off:X})")
        data[sec_off:sec_off + 40] = b'\x00' * 40

    # -----------------------------------------------------------------------
    # 8. Очистка указателя на ASProtect в .data
    # -----------------------------------------------------------------------
    if ASPROTECT_DATA_POINTER_FILE_OFFSET < len(data):
        old_ptr = read_uint32(data, ASPROTECT_DATA_POINTER_FILE_OFFSET)
        if 0x09110000 <= old_ptr < 0x0917D000:
            print(f"\n[*] Очистка указателя на ASProtect в .data")
            print(f"    Адрес: File 0x{ASPROTECT_DATA_POINTER_FILE_OFFSET:08X}")
            print(f"    Старое значение: 0x{old_ptr:08X}")
            write_uint32(data, ASPROTECT_DATA_POINTER_FILE_OFFSET, 0x00000000)
            print(f"    Новое значение: 0x00000000")

    # -----------------------------------------------------------------------
    # 9. Обрезка файла (удаление данных ASProtect)
    # -----------------------------------------------------------------------
    print(f"\n[*] Обрезка файла")
    print(f"    Старый размер: {len(data)} байт (0x{len(data):08X})")

    data = data[:CLEAN_FILE_END]
    print(f"    Новый размер:  {len(data)} байт (0x{len(data):08X})")
    print(f"    Удалено:       {original_size - len(data)} байт")

    # -----------------------------------------------------------------------
    # 10. Сохранение результата
    # -----------------------------------------------------------------------
    print(f"\n[*] Сохранение: {output_path}")
    with open(output_path, 'wb') as f:
        f.write(data)

    print(f"[+] Готово! Файл распакован успешно.")

    # -----------------------------------------------------------------------
    # 11. Верификация
    # -----------------------------------------------------------------------
    print(f"\n[*] Верификация распакованного файла...")
    verify(output_path)

    return True


def verify(path):
    """Проверить корректность распакованного PE-файла."""
    with open(path, 'rb') as f:
        data = f.read()

    # Проверка MZ
    assert data[0:2] == b'MZ', "Нет MZ-сигнатуры"

    pe_offset = struct.unpack_from('<I', data, 0x3C)[0]
    assert data[pe_offset:pe_offset + 4] == b'PE\x00\x00', "Нет PE-сигнатуры"

    coff_offset = pe_offset + 4
    optional_offset = coff_offset + 20

    num_sections = struct.unpack_from('<H', data, coff_offset + 2)[0]
    entry_rva = struct.unpack_from('<I', data, optional_offset + 16)[0]
    size_of_image = struct.unpack_from('<I', data, optional_offset + 56)[0]

    print(f"    NumberOfSections: {num_sections}")
    assert num_sections == ORIGINAL_SECTION_COUNT, \
        f"Ожидалось {ORIGINAL_SECTION_COUNT} секций, найдено {num_sections}"

    print(f"    EntryPoint (RVA): 0x{entry_rva:08X}")
    assert entry_rva == OEP_RVA, \
        f"EntryPoint не совпадает: 0x{entry_rva:08X} != 0x{OEP_RVA:08X}"

    print(f"    SizeOfImage: 0x{size_of_image:08X}")

    # Проверка восстановленных байтов OEP
    oep_bytes = data[STOLEN_BYTES_FILE_OFFSET:STOLEN_BYTES_FILE_OFFSET + 6]
    print(f"    OEP байты: {' '.join(f'{b:02X}' for b in oep_bytes)}")
    assert oep_bytes == STOLEN_BYTES, "OEP байты не восстановлены"

    # Проверка отсутствия ASProtect-секций
    opt_header_size = struct.unpack_from('<H', data, coff_offset + 16)[0]
    sections_start = optional_offset + opt_header_size
    for i in range(num_sections):
        sec_off = sections_start + i * 40
        name_raw = data[sec_off:sec_off + 8]
        name = name_raw.split(b'\x00')[0].decode('ascii', errors='replace')
        assert name not in ASPROTECT_SECTION_NAMES, \
            f"ASProtect секция '{name}' всё ещё присутствует"

    # Проверка что область заголовков ASProtect-секций чистая
    for i in range(ORIGINAL_SECTION_COUNT, 10):
        sec_off = sections_start + i * 40
        if sec_off + 40 <= len(data):
            sec_data = data[sec_off:sec_off + 40]
            assert sec_data == b'\x00' * 40, \
                f"Заголовок секции [{i}] не очищен"

    print(f"    [+] Все проверки пройдены!")


# ============================================================================
#  Точка входа
# ============================================================================

def main():
    input_file = sys.argv[1] if len(sys.argv) > 1 else 'main.exe'
    output_file = sys.argv[2] if len(sys.argv) > 2 else 'main_unpacked.exe'

    if not os.path.exists(input_file):
        print(f"[!] Файл не найден: {input_file}")
        sys.exit(1)

    success = unpack(input_file, output_file)
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
