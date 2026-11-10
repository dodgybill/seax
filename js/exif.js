/**
 * Copy evidence metadata out of a file. The original bytes are stored separately
 * and are not rewritten, so this never strips the source.
 * No face detection, templates, or other biometric processing.
 */

const TYPE_SIZE = { 1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 7: 1, 9: 4, 10: 8 };

const IFD0_NAMES = {
  270: 'ImageDescription',
  271: 'Make',
  272: 'Model',
  274: 'Orientation',
  282: 'XResolution',
  283: 'YResolution',
  305: 'Software',
  306: 'DateTime',
  315: 'Artist',
  33432: 'Copyright',
};

const EXIF_NAMES = {
  33434: 'ExposureTime',
  33437: 'FNumber',
  34855: 'ISO',
  36867: 'DateTimeOriginal',
  36868: 'DateTimeDigitized',
  37386: 'FocalLength',
  42036: 'LensModel',
  41989: 'FocalLengthIn35mm',
  37510: 'UserComment',
};

const GPS_NAMES = {
  1: 'GPSLatitudeRef',
  2: 'GPSLatitude',
  3: 'GPSLongitudeRef',
  4: 'GPSLongitude',
  5: 'GPSAltitudeRef',
  6: 'GPSAltitude',
  7: 'GPSTimeStamp',
  16: 'GPSImgDirectionRef',
  17: 'GPSImgDirection',
  29: 'GPSDateStamp',
  31: 'GPSHPositioningError',
};

function u32be(bytes, o) {
  return ((bytes[o] << 24) | (bytes[o + 1] << 16) | (bytes[o + 2] << 8) | bytes[o + 3]) >>> 0;
}

function latin1(bytes, off, len) {
  let s = '';
  const end = Math.min(bytes.length, off + len);
  for (let i = off; i < end; i++) s += String.fromCharCode(bytes[i]);
  return s;
}

function ascii(bytes, off, len) {
  return latin1(bytes, off, len);
}

export function parseTiff(tiff) {
  const fields = {};
  if (!tiff || tiff.length < 8) return fields;
  const le = tiff[0] === 0x49 && tiff[1] === 0x49;
  const be = tiff[0] === 0x4d && tiff[1] === 0x4d;
  if (!le && !be) return fields;
  const u16 = (o) => {
    if (o + 2 > tiff.length) return 0;
    return le ? tiff[o] | (tiff[o + 1] << 8) : (tiff[o] << 8) | tiff[o + 1];
  };
  const u32 = (o) => {
    if (o + 4 > tiff.length) return 0;
    return le
      ? (tiff[o] | (tiff[o + 1] << 8) | (tiff[o + 2] << 16) | (tiff[o + 3] << 24)) >>> 0
      : ((tiff[o] << 24) | (tiff[o + 1] << 16) | (tiff[o + 2] << 8) | tiff[o + 3]) >>> 0;
  };
  if (u16(2) !== 42) return fields;

  const readValue = (type, num, offset) => {
    const sz = (TYPE_SIZE[type] || 1) * num;
    if (offset < 0 || offset + sz > tiff.length) return null;
    if (type === 2) {
      let s = '';
      for (let i = 0; i < num; i++) {
        const c = tiff[offset + i];
        if (c === 0) break;
        s += String.fromCharCode(c);
      }
      return s;
    }
    if (type === 1 || type === 7) {
      if (type === 7 && num > 64) return `undefined:${num}`;
      const arr = [];
      for (let i = 0; i < num; i++) arr.push(tiff[offset + i]);
      return num === 1 ? arr[0] : arr;
    }
    if (type === 3) {
      const arr = [];
      for (let i = 0; i < num; i++) arr.push(u16(offset + i * 2));
      return num === 1 ? arr[0] : arr;
    }
    if (type === 4 || type === 9) {
      const arr = [];
      for (let i = 0; i < num; i++) arr.push(u32(offset + i * 4));
      return num === 1 ? arr[0] : arr;
    }
    if (type === 5 || type === 10) {
      const arr = [];
      for (let i = 0; i < num; i++) {
        const n = u32(offset + i * 8);
        const d = u32(offset + i * 8 + 4) || 1;
        arr.push(Math.round((n / d) * 1e6) / 1e6);
      }
      return num === 1 ? arr[0] : arr;
    }
    const slice = tiff.subarray(offset, Math.min(tiff.length, offset + Math.min(sz, 32)));
    return [...slice].map((b) => b.toString(16).padStart(2, '0')).join('');
  };

  const seen = new Set();
  function readIfd(offset, prefix, depth) {
    if (depth > 6 || seen.has(prefix + ':' + offset) || offset + 2 > tiff.length) return;
    seen.add(prefix + ':' + offset);
    const count = u16(offset);
    const entries = [];
    for (let i = 0; i < count; i++) {
      const e = offset + 2 + i * 12;
      if (e + 12 > tiff.length) break;
      entries.push({
        tag: u16(e),
        type: u16(e + 2),
        num: u32(e + 4),
        entry: e,
      });
    }
    const names = prefix === 'GPS' ? GPS_NAMES : prefix === 'Exif' ? EXIF_NAMES : IFD0_NAMES;
    for (const ent of entries) {
      const size = (TYPE_SIZE[ent.type] || 1) * ent.num;
      const dataOff = size <= 4 ? ent.entry + 8 : u32(ent.entry + 8);
      if (prefix === 'IFD0' && ent.tag === 34665) {
        readIfd(u32(ent.entry + 8), 'Exif', depth + 1);
        continue;
      }
      if (prefix === 'IFD0' && ent.tag === 34853) {
        readIfd(u32(ent.entry + 8), 'GPS', depth + 1);
        continue;
      }
      const value = readValue(ent.type, ent.num, dataOff);
      if (value == null || value === '') continue;
      const name = names[ent.tag] || `${prefix}.tag_${ent.tag}`;
      fields[name] = value;
    }
  }

  readIfd(u32(4), 'IFD0', 0);
  if (Array.isArray(fields.GPSLatitude)) {
    const dec = dmsToDec(fields.GPSLatitude, fields.GPSLatitudeRef);
    if (dec != null) fields.GPSLatitudeDecimal = dec;
  }
  if (Array.isArray(fields.GPSLongitude)) {
    const dec = dmsToDec(fields.GPSLongitude, fields.GPSLongitudeRef);
    if (dec != null) fields.GPSLongitudeDecimal = dec;
  }
  return fields;
}

function dmsToDec(parts, ref) {
  if (!Array.isArray(parts) || parts.length < 3) return null;
  let dec = Number(parts[0]) + Number(parts[1]) / 60 + Number(parts[2]) / 3600;
  if (ref === 'S' || ref === 'W') dec = -dec;
  if (!Number.isFinite(dec)) return null;
  return Math.round(dec * 1e6) / 1e6;
}

export function parseJpeg(bytes) {
  const fields = {};
  const comments = [];
  let xmp = '';
  if (bytes.length < 4 || bytes[0] !== 0xff || bytes[1] !== 0xd8) return { fields, comments, xmp };
  let off = 2;
  while (off + 4 < bytes.length) {
    if (bytes[off] !== 0xff) {
      off += 1;
      continue;
    }
    const marker = bytes[off + 1];
    if (marker === 0xd8) {
      off += 2;
      continue;
    }
    if (marker === 0xd9 || marker === 0xda) break;
    const len = (bytes[off + 2] << 8) | bytes[off + 3];
    if (len < 2 || off + 2 + len > bytes.length) break;
    const start = off + 4;
    const dataLen = len - 2;
    if (marker === 0xfe) comments.push(latin1(bytes, start, dataLen));
    if (marker === 0xe1 && dataLen >= 6) {
      const sig = latin1(bytes, start, 6);
      if (sig === 'Exif\u0000\u0000') {
        Object.assign(fields, parseTiff(bytes.subarray(start + 6, start + dataLen)));
      } else if (latin1(bytes, start, 29) === 'http://ns.adobe.com/xap/1.0/\u0000') {
        xmp = latin1(bytes, start + 29, dataLen - 29);
      }
    }
    off += 2 + len;
  }
  return { fields, comments, xmp };
}

function parsePng(bytes) {
  const fields = {};
  const textChunks = {};
  let off = 8;
  while (off + 12 <= bytes.length) {
    const len = u32be(bytes, off);
    const type = ascii(bytes, off + 4, 4);
    const data = off + 8;
    if (data + len + 4 > bytes.length) break;
    if (type === 'eXIf') Object.assign(fields, parseTiff(bytes.subarray(data, data + len)));
    if (type === 'tEXt' || type === 'iTXt') {
      const raw = latin1(bytes, data, Math.min(len, 8000));
      const nul = raw.indexOf('\u0000');
      if (nul > 0) textChunks[raw.slice(0, nul)] = type === 'tEXt' ? raw.slice(nul + 1) : raw.slice(nul + 1);
    }
    if (type === 'IEND') break;
    off = data + len + 4;
  }
  return { fields, textChunks };
}

function scanQuickTimeLocation(bytes) {
  const hits = [];
  const regions = [
    [0, Math.min(bytes.length, 4 * 1024 * 1024)],
    [Math.max(0, bytes.length - 4 * 1024 * 1024), bytes.length],
  ];
  for (const [start, end] of regions) {
    for (let i = start; i + 8 < end; i++) {
      if (bytes[i] !== 0xa9 || bytes[i + 1] !== 0x78 || bytes[i + 2] !== 0x79 || bytes[i + 3] !== 0x7a) continue;
      const window = latin1(bytes, i, Math.min(96, end - i));
      const m = window.match(/[+-]\d+(?:\.\d+)?[+-]\d+(?:\.\d+)?(?:[+-]\d+(?:\.\d+)?)?/);
      if (m) hits.push(m[0]);
      if (hits.length >= 8) return hits;
    }
  }
  return hits;
}

function retainedNote() {
  return 'Original file retained encrypted. Metadata was copied out and was not removed from the file.';
}

export function extractMetadata(bytes, mime) {
  const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  const base = {
    retained: true,
    note: retainedNote(),
    mime: mime || '',
    bytes: u8.length,
  };
  if (u8.length >= 3 && u8[0] === 0xff && u8[1] === 0xd8 && u8[2] === 0xff) {
    const parsed = parseJpeg(u8);
    return { ...base, parser: 'jpeg', fields: parsed.fields, comments: parsed.comments, xmp: parsed.xmp || undefined };
  }
  if (u8.length >= 8 && u8[0] === 0x89 && u8[1] === 0x50 && u8[2] === 0x4e && u8[3] === 0x47) {
    const parsed = parsePng(u8);
    return { ...base, parser: 'png', fields: parsed.fields, text: parsed.textChunks };
  }
  const locations = scanQuickTimeLocation(u8);
  if (locations.length) {
    return { ...base, parser: 'quicktime-scan', fields: { QuickTimeLocation: locations } };
  }
  return {
    ...base,
    parser: 'unparsed',
    fields: {},
    unparsed: true,
  };
}
