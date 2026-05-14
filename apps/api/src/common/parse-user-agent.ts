// Vienkāršs user-agent parsētājs — bez npm pakotnēm
export function parseUserAgent(ua?: string | null): { browser: string; os: string; short: string } {
  if (!ua) return { browser: 'Nezināms', os: 'Nezināms', short: 'Nezināms' };

  let browser = 'Nezināms';
  if (/Edg\/(\d+)/.test(ua)) browser = `Edge ${RegExp.$1}`;
  else if (/OPR\/(\d+)/.test(ua)) browser = `Opera ${RegExp.$1}`;
  else if (/Chrome\/(\d+)/.test(ua)) browser = `Chrome ${RegExp.$1}`;
  else if (/Firefox\/(\d+)/.test(ua)) browser = `Firefox ${RegExp.$1}`;
  else if (/Safari\/(\d+)/.test(ua) && /Version\/(\d+)/.test(ua)) browser = `Safari ${RegExp.$1}`;

  let os = 'Nezināms';
  if (/Windows NT 10/.test(ua)) os = 'Windows 10/11';
  else if (/Windows NT/.test(ua)) os = 'Windows';
  else if (/Mac OS X/.test(ua)) os = 'macOS';
  else if (/Linux/.test(ua)) os = 'Linux';
  else if (/Android/.test(ua)) os = 'Android';
  else if (/iPhone|iPad/.test(ua)) os = 'iOS';

  return { browser, os, short: `${browser} / ${os}` };
}
