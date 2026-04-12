export function formatBytes(input: number, fractionDigits = 1) {
  if (!Number.isFinite(input) || input < 0) {
    return '0 B';
  }

  if (input < 1024) {
    return `${input.toFixed(0)} B`;
  }

  const units = ['KB', 'MB', 'GB', 'TB', 'PB'];
  let value = input;
  let index = -1;

  do {
    value /= 1024;
    index += 1;
  } while (value >= 1024 && index < units.length - 1);

  return `${value.toFixed(fractionDigits)} ${units[index]}`;
}

export function formatRate(input: number) {
  return `${formatBytes(input)}/s`;
}

export function formatTime(timestamp: number) {
  return new Intl.DateTimeFormat('zh-CN', {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  }).format(timestamp);
}

export function toLabel(value: string) {
  return value
    .replace(/([a-z])([A-Z])/g, '$1 $2')
    .replace(/[_-]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
    .replace(/^./, (letter) => letter.toUpperCase());
}

export function formatCellValue(value: unknown) {
  if (typeof value === 'boolean') {
    return value ? 'True' : 'False';
  }

  if (value == null || value === '') {
    return '-';
  }

  return String(value);
}
