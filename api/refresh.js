import fetch from 'node-fetch';

async function getCsrfToken(cookie) {
  const sessionHeaders = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.9',
    'Accept-Encoding': 'gzip, deflate',
    'Referer': 'https://www.roblox.com/',
    'Origin': 'https://www.roblox.com',
    'Sec-Fetch-Dest': 'document',
    'Sec-Fetch-Mode': 'navigate',
    'Sec-Fetch-Site': 'same-origin',
    'Sec-Fetch-User': '?1',
    'Cache-Control': 'max-age=0',
    'Upgrade-Insecure-Requests': '1',
    'Cookie': `.ROBLOSECURITY=${cookie}`
  };

  const res = await fetch('https://auth.roblox.com/v2/logout', { method: 'POST', headers: sessionHeaders });
  let csrf = res.headers.get('x-csrf-token');
  if (!csrf) {
    const text = await res.text();
    const match = /"XCSRF-TOKEN" value="([^"]+)"/.exec(text);
    if (match) csrf = match[1];
  }
  if (!csrf) throw new Error(`CSRF fail: ${res.status}`);
  return csrf;
}

async function refreshCookie(cookie) {
  const csrf = await getCsrfToken(cookie);
  const headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36',
    'Accept': 'application/json, text/plain, */*',
    'Accept-Language': 'en-US,en;q=0.9',
    'Accept-Encoding': 'gzip, deflate',
    'Content-Type': 'application/json',
    'Referer': 'https://www.roblox.com/home',
    'Origin': 'https://www.roblox.com',
    'Sec-Fetch-Dest': 'empty',
    'Sec-Fetch-Mode': 'cors',
    'Sec-Fetch-Site': 'same-origin',
    'X-CSRF-TOKEN': csrf,
    'X-Requested-With': 'XMLHttpRequest',
    'Cookie': `.ROBLOSECURITY=${cookie}`
  };

  const res = await fetch('https://auth.roblox.com/v2/logoutfromallsessionsandreauthenticate', {
    method: 'POST',
    headers,
    body: JSON.stringify({})
  });

  if (res.status !== 200) {
    const text = await res.text();
    throw new Error(`Refresh failed: ${res.status} - ${text.substring(0, 300)}`);
  }

  const setCookie = res.headers.get('set-cookie') || '';
  const match = /\.ROBLOSECURITY=(.+?); domain=\.roblox\.com/.exec(setCookie);
  if (match) return match[1];
  throw new Error('No new cookie');
}

export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });
  const { cookie } = req.body;
  if (!cookie) return res.status(400).json({ error: 'No cookie provided' });
  try {
    const newCookie = await refreshCookie(cookie);
    res.json({ new_cookie: newCookie });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
}