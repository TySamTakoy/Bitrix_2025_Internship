import numpy as np
from scipy.io import wavfile
from scipy.signal import spectrogram
import matplotlib.pyplot as plt

# DTMF частоты для каждой кнопки
DTMF_TABLE = {
    (697, 1209): '1', (697, 1336): '2', (697, 1477): '3', (697, 1633): 'A',
    (770, 1209): '4', (770, 1336): '5', (770, 1477): '6', (770, 1633): 'B',
    (852, 1209): '7', (852, 1336): '8', (852, 1477): '9', (852, 1633): 'C',
    (941, 1209): '*', (941, 1336): '0', (941, 1477): '#', (941, 1633): 'D',
}

LOW_FREQS = [697, 770, 852, 941]
HIGH_FREQS = [1209, 1336, 1477, 1633]


def plot_spectrogram(data, sample_rate):
    """Визуализирует спектрограмму"""
    plt.figure(figsize=(15, 8))

    # Спектрограмма
    f, t, Sxx = spectrogram(data, sample_rate, nperseg=512)
    plt.subplot(2, 1, 1)
    plt.pcolormesh(t, f, 10 * np.log10(Sxx + 1e-10), shading='gouraud', cmap='viridis')
    plt.ylabel('Частота (Hz)')
    plt.xlabel('Время (сек)')
    plt.title('Спектрограмма')
    plt.colorbar(label='Амплитуда (dB)')
    plt.ylim([0, 2000])

    # Добавляем линии DTMF частот
    for freq in LOW_FREQS + HIGH_FREQS:
        plt.axhline(y=freq, color='r', linestyle='--', alpha=0.3, linewidth=0.5)

    # Waveform
    plt.subplot(2, 1, 2)
    time = np.arange(len(data)) / sample_rate
    plt.plot(time, data)
    plt.ylabel('Амплитуда')
    plt.xlabel('Время (сек)')
    plt.title('Форма волны')
    plt.grid(True, alpha=0.3)

    plt.tight_layout()
    plt.savefig('spectrogram.png', dpi=150)
    print("Спектрограмма сохранена в spectrogram.png")
    plt.show()


def goertzel(samples, target_freq, sample_rate):
    """Алгоритм Гёрцеля для обнаружения конкретной частоты"""
    n = len(samples)
    k = int(0.5 + (n * target_freq / sample_rate))
    omega = (2.0 * np.pi * k) / n

    coeff = 2.0 * np.cos(omega)
    q1, q2 = 0.0, 0.0

    for sample in samples:
        q0 = coeff * q1 - q2 + sample
        q2 = q1
        q1 = q0

    magnitude = np.sqrt(q1 ** 2 + q2 ** 2 - q1 * q2 * coeff)
    return magnitude


def detect_dtmf_goertzel(data, sample_rate, window_size=400):
    """Использует алгоритм Гёрцеля для поиска DTMF"""
    print("\nИспользую алгоритм Гёрцеля...")

    hop_size = window_size // 4
    decoded = []
    last_symbol = None
    silence_counter = 0

    for i in range(0, len(data) - window_size, hop_size):
        chunk = data[i:i + window_size]

        # Проверяем энергию сигнала
        energy = np.sum(chunk ** 2)
        if energy < np.max(data ** 2) * 0.001:
            silence_counter += 1
            if silence_counter > 3:
                last_symbol = None
            continue

        silence_counter = 0

        # Вычисляем магнитуды для всех DTMF частот
        low_mags = {freq: goertzel(chunk, freq, sample_rate) for freq in LOW_FREQS}
        high_mags = {freq: goertzel(chunk, freq, sample_rate) for freq in HIGH_FREQS}

        # Находим максимумы
        best_low = max(low_mags, key=low_mags.get)
        best_high = max(high_mags, key=high_mags.get)

        # Проверяем, что пики достаточно сильные
        threshold = 0.3 * max(max(low_mags.values()), max(high_mags.values()))

        if low_mags[best_low] > threshold and high_mags[best_high] > threshold:
            symbol = DTMF_TABLE.get((best_low, best_high))
            if symbol and symbol != last_symbol:
                decoded.append(symbol)
                print(f"Время {i / sample_rate:.2f}с: {best_low} Hz + {best_high} Hz = '{symbol}'")
                last_symbol = symbol

    return ''.join(decoded)


def analyze_frequencies(data, sample_rate):
    """Анализирует частотный состав всего файла"""
    print("\nОбщий частотный анализ:")

    # FFT всего сигнала
    fft = np.fft.fft(data)
    freqs = np.fft.fftfreq(len(data), 1 / sample_rate)
    magnitude = np.abs(fft)

    # Только положительные частоты до 2000 Hz
    mask = (freqs > 0) & (freqs < 2000)
    freqs_pos = freqs[mask]
    mag_pos = magnitude[mask]

    # Находим топ-10 частот
    top_indices = np.argsort(mag_pos)[-10:][::-1]
    print("\nТоп-10 частот в сигнале:")
    for idx in top_indices:
        print(f"  {freqs_pos[idx]:.1f} Hz - амплитуда: {mag_pos[idx]:.0f}")


def decode_dtmf_from_wav(filename):
    """Главная функция декодирования"""
    print(f"Анализ файла: {filename}")

    # Читаем файл
    sample_rate, data = wavfile.read(filename)

    if len(data.shape) > 1:
        data = data[:, 0]

    # Нормализуем
    data = data.astype(np.float32)
    if np.max(np.abs(data)) > 0:
        data = data / np.max(np.abs(data))

    print(f"Sample rate: {sample_rate} Hz")
    print(f"Длительность: {len(data) / sample_rate:.2f} секунд")
    print(f"Макс. амплитуда: {np.max(np.abs(data)):.3f}")

    # Анализ частот
    analyze_frequencies(data, sample_rate)

    # Визуализация
    plot_spectrogram(data, sample_rate)

    # Декодирование с разными размерами окна
    for window_ms in [50, 100, 200]:
        window_size = int(sample_rate * window_ms / 1000)
        print(f"\n{'=' * 60}")
        print(f"Попытка декодирования с окном {window_ms} мс ({window_size} отсчетов):")
        print('=' * 60)
        result = detect_dtmf_goertzel(data, sample_rate, window_size)

        if result:
            print(f"\n>>> РЕЗУЛЬТАТ: {result}")
            try_decode_as_text(result)
            return result

    print("\n⚠️ DTMF тоны не обнаружены!")
    return ""


def try_decode_as_text(symbols):
    """Интерпретация результата"""
    print("\n" + "=" * 60)
    print("ВОЗМОЖНЫЕ ИНТЕРПРЕТАЦИИ:")
    print("=" * 60)

    print(f"1. Прямой вывод: {symbols}")

    # Только цифры
    numbers = ''.join(c for c in symbols if c.isdigit())
    if numbers:
        print(f"2. Только цифры: {numbers}")

        # ASCII из пар
        if len(numbers) % 2 == 0:
            try:
                ascii_text = ''.join(chr(int(numbers[i:i + 2]))
                                     for i in range(0, len(numbers), 2)
                                     if 32 <= int(numbers[i:i + 2]) <= 126)
                if ascii_text:
                    print(f"3. ASCII (пары цифр): {ascii_text}")
            except:
                pass

        # ASCII из троек
        if len(numbers) % 3 == 0:
            try:
                ascii_text = ''.join(chr(int(numbers[i:i + 3]))
                                     for i in range(0, len(numbers), 3)
                                     if 32 <= int(numbers[i:i + 3]) <= 126)
                if ascii_text:
                    print(f"4. ASCII (тройки цифр): {ascii_text}")
            except:
                pass

    # Hex
    try:
        if all(c in '0123456789ABCDEF' for c in symbols):
            hex_text = bytes.fromhex(symbols).decode('ascii')
            print(f"5. HEX декодирование: {hex_text}")
    except:
        pass


if __name__ == "__main__":
    result = decode_dtmf_from_wav("sound.wav")