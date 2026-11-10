/** Synthetic JPEG/EXIF bytes for tests. Not a photograph of a person. */

function u16(n) {
  const b = Buffer.alloc(2);
  b.writeUInt16LE(n, 0);
  return b;
}

function entry(tag, type, count, value) {
  const b = Buffer.alloc(12);
  b.writeUInt16LE(tag, 0);
  b.writeUInt16LE(type, 2);
  b.writeUInt32LE(count, 4);
  if (Buffer.isBuffer(value)) value.copy(b, 8);
  else b.writeUInt32LE(value >>> 0, 8);
  return b;
}

export function buildTiff({
  make = 'TestCamSEAX',
  model = 'Synthetic',
  dateTime = '2026:01:01 00:00:00',
} = {}) {
  const makeBytes = Buffer.from(`${make}\0`, 'latin1');
  const modelBytes = Buffer.from(`${model}\0`, 'latin1');
  const dateBytes = Buffer.from(`${dateTime}\0`, 'latin1');
  const dataAt = 8 + 2 + 12 * 3 + 4;
  const modelAt = dataAt + makeBytes.length;
  const dateAt = modelAt + modelBytes.length;
  const hdr = Buffer.alloc(8);
  hdr.write('II', 0, 'latin1');
  hdr.writeUInt16LE(42, 2);
  hdr.writeUInt32LE(8, 4);
  const count = u16(3);
  const next = Buffer.alloc(4);
  return Buffer.concat([
    hdr,
    count,
    entry(271, 2, makeBytes.length, dataAt),
    entry(272, 2, modelBytes.length, modelAt),
    entry(306, 2, dateBytes.length, dateAt),
    next,
    makeBytes,
    modelBytes,
    dateBytes,
  ]);
}

export function insertExif(jpegBytes, options = {}) {
  const buf = Buffer.from(jpegBytes);
  if (buf.length < 2 || buf[0] !== 0xff || buf[1] !== 0xd8) throw new Error('Not a JPEG');
  const tiff = buildTiff(options);
  const payload = Buffer.concat([Buffer.from('Exif\0\0', 'latin1'), tiff]);
  const app1Len = payload.length + 2;
  const app1 = Buffer.concat([
    Buffer.from([0xff, 0xe1, (app1Len >> 8) & 255, app1Len & 255]),
    payload,
  ]);
  const comment = Buffer.from(options.comment || 'UNIQUEPLAINTEXTMARKER', 'latin1');
  const comLen = comment.length + 2;
  const com = Buffer.concat([
    Buffer.from([0xff, 0xfe, (comLen >> 8) & 255, comLen & 255]),
    comment,
  ]);
  return Buffer.concat([buf.subarray(0, 2), app1, com, buf.subarray(2)]);
}

export function buildMarkedJpeg(options) {
  return insertExif(Buffer.from([0xff, 0xd8, 0xff, 0xd9]), options);
}
