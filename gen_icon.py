import struct, zlib

w = h = 256

# Create a simple blue square icon (RGBA)
rows = []
for y in range(h):
    row = b'\x00'  # filter byte
    for x in range(w):
        # Blue shield-like gradient
        row += bytes([30, 64, 175, 255])  # RGBA blue
    rows.append(row)

pixels = b''.join(rows)
compressed = zlib.compress(pixels)

def make_chunk(chunk_type, data):
    crc = zlib.crc32(chunk_type + data) & 0xFFFFFFFF
    return struct.pack('>I', len(data)) + chunk_type + data + struct.pack('>I', crc)

ihdr_data = struct.pack('>IIBBBBB', w, h, 8, 6, 0, 0, 0)

png = b'\x89PNG\r\n\x1a\n'
png += make_chunk(b'IHDR', ihdr_data)
png += make_chunk(b'IDAT', compressed)
png += make_chunk(b'IEND', b'')

with open('assets/icon.png', 'wb') as f:
    f.write(png)

print(f"Generated icon.png: {len(png)} bytes, {w}x{h}")
