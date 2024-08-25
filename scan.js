const readline = require('readline');

function generateIpRange(startIp, endIp) {
  const start = startIp.split('.').map(Number);
  const end = endIp.split('.').map(Number);
  const range = [];
  for (let i = start[0]; i <= end[0]; i++) {
    for (let j = (i === start[0] ? start[1] : 0); j <= (i === end[0] ? end[1] : 255); j++) {
      for (let k = (i === start[0] && j === start[1] ? start[2] : 0); k <= (i === end[0] && j === end[1] ? end[2] : 255); k++) {
        for (let l = (i === start[0] && j === start[1] && k === start[2] ? start[3] : 0); l <= (i === end[0] && j === end[1] && k === end[2] ? end[3] : 255); l++) {
          range.push(`${i}.${j}.${k}.${l}`);
        }
      }
    }
  }
  return range;
}

function ipToInt(ip) {
  return ip.split('.').reduce((acc, octet) => (acc << 8) + Number(octet), 0);
}

function intToIp(int) {
  return [
    (int >>> 24) & 255,
    (int >>> 16) & 255,
    (int >>> 8) & 255,
    int & 255
  ].join('.');
}

function generateCidrRange(cidr) {
  const [baseIp, prefixLength] = cidr.split('/');
  const base = ipToInt(baseIp);
  const mask = 0xFFFFFFFF << (32 - parseInt(prefixLength, 10));
  const start = base & mask;
  const end = start | ~mask;
  const range = [];
  for (let ip = start; ip <= end; ip++) {
    range.push(intToIp(ip));
  }
  return range;
}

function isValidIp(ip) {
  const octets = ip.split('.');
  if (octets.length !== 4) return false;
  return octets.every(octet => {
    const num = Number(octet);
    return num >= 0 && num <= 255;
  });
}

function isValidCidr(cidr) {
  const [ip, prefixLength] = cidr.split('/');
  if (!isValidIp(ip)) return false;
  const prefix = Number(prefixLength);
  return prefix >= 0 && prefix <= 32;
}

function isValidIpRange(startIp, endIp) {
  return isValidIp(startIp) && isValidIp(endIp) && ipToInt(startIp) <= ipToInt(endIp);
}

async function checkProxy(proxy) {
  try {
    const response = await fetch(`https://pyip.bexnxx.us.kg/api?ip=${proxy}`);
    const data = await response.json();
    if (data.proxyStatus !== 'ACTIVE') {
      const msg = `${proxy} (${data.isp}) (${data.countryCode}) (${data.delay})`;
      console.log('\x1b[31m%s\x1b[0m', 'DEAD PROXY: ' + proxy);
    } 
    if (data.proxyStatus === 'ACTIVE') {
      const msg = `${proxy} (${data.isp}) (${data.countryCode}) (${data.delay})`;
      console.log('\x1b[32m%s\x1b[0m', 'ACTIVE PROXY: ' + msg);
    }
  } catch (error) {
  }
}

async function scanProxies(ranges) {
  for (const rangeStr of ranges) {
    let proxies;
    const isCidr = rangeStr.includes('/');
    if (isCidr) {
      proxies = generateCidrRange(rangeStr);
    } else {
      const [startIp, endIp] = rangeStr.split('-');
      proxies = generateIpRange(startIp, endIp);
    }
    for (const proxy of proxies) {
      await checkProxy(proxy);
    }
  }
}

async function main() {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
  });

  async function askForInput() {
    return new Promise((resolve) => {
      rl.question('Masukkan IP CIDR atau rentang IP: ', (answer) => {
        resolve(answer);
      });
    });
  }
  let isValidInput = false;
  let ranges;
  while (!isValidInput) {
    const answer = await askForInput();
    ranges = answer.split(' ').map(range => range.trim());
    isValidInput = ranges.every(range => {
      if (range.includes('/')) {
        return isValidCidr(range);
      } else if (range.includes('-')) {
        const [startIp, endIp] = range.split('-');
        return isValidIpRange(startIp, endIp);
      }
      return false;
    });
    if (!isValidInput) {
      console.log('Invalid IP CIDR atau rentang IP');
    }
  }
  await scanProxies(ranges);
  console.log('Selesai');
  rl.close();
}

main();
