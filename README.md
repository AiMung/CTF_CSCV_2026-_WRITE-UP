# CTF_CSCV_2026-_WRITE-UP
Tổng hợp bài giải (write-ups) các thử thách trong giải CTF CSCV 2026
CSCV 2026 – MISC02 Write-up
# CSCV 2026 – MISC02 Write-up

* **Category:** Miscellaneous
* **Team:** ITDLU
* **Flag:** `CSCV2026{WaKe_Up_4nD_sM31l_7H3_c0fFe3}`

---

## 1. Đề bài

Challenge gửi đến một đoạn văn bản trông bề ngoài như hướng dẫn pha cà phê, kèm theo một `"SYSTEM DIRECTIVE OVERRIDE"` lạ mắt ở đầu – nhưng đây thực ra là mồi nhử (red herring) để che giấu dữ liệu ẩn thực sự.

**Nội dung hiển thị:**
```text
☕ BREWING INSTRUCTIONS ☕
...
Enjoy your coffee! ☕
```

* **Flag format:** `CSCV2026{[A-Za-z0-9_]+}`

---

## 2. Nhận diện kỹ thuật ẩn

### 2.1 Phát hiện ký tự invisible
Bước đầu tiên: kiểm tra tất cả code point trong văn bản.

```python
for i, ch in enumerate(text):
    cp = ord(ch)
    if cp > 0x7F:
        print(f"pos {i}: U+{cp:06X}")
```

**Kết quả:** Rải rác trong văn bản (chủ yếu sau các emoji) có rất nhiều ký tự thuộc dải `U+E0100` – `U+E01EF`.

### 2.2 Unicode Variation Selectors Supplement
Unicode dành dải `U+E0100` – `U+E01EF` (256 code point) làm variation selectors. Về mặt hiển thị, chúng hoàn toàn vô hình (zero-width, không render ra màn hình). Đây là kỹ thuật steganography cực kỳ hiệu quả để nhúng dữ liệu vào văn bản mà mắt thường không thể phát hiện.

---

## 3. Giải mã từng bước

* **Bước 1: Trích xuất variation selectors**
  ```python
  hidden = [ord(ch) for ch in text if 0xE0100 <= ord(ch) <= 0xE01EF]
  ```
* **Bước 2: Trừ base offset ra giá trị ASCII**  
  Mỗi variation selector mang offset so với `0xE0100`:
  ```python
  ascii_vals = [cp - 0xE0100 for cp in hidden]
  # ''.join(chr(v) for v in ascii_vals)
  # => chuỗi bị mã hóa Caesar, chưa đọc được
  ```
* **Bước 3: Giải mã Caesar shift -16**  
  Chuỗi thu được ở bước 2 vẫn chưa đọc được. Áp dụng Caesar cipher với shift -16 trên tập 94 ký tự printable ASCII:
  ```python
  def caesar_decode(vals, shift=16):
      result = []
      for v in vals:
          if 33 <= v <= 126:
              decoded = ((v - 33 - shift) % 94) + 33
              result.append(chr(decoded))
          else:
              result.append(chr(v))
      return ''.join(result)
  ```

### Script giải mã hoàn chỉnh (`solve.py`)

```python
def solve(text):
    hidden = [ord(ch) for ch in text if 0xE0100 <= ord(ch) <= 0xE01EF]
    ascii_vals = [cp - 0xE0100 for cp in hidden]
    return ''.join(
        chr(((v - 33 - 16) % 94) + 33) if 33 <= v <= 126 else chr(v)
        for v in ascii_vals
    )

with open('challenge.txt', encoding='utf-8') as f:
    print(solve(f.read()))
# Output: CSCV2026{WaKe_Up_4nD_sM31l_7H3_c0fFe3}
```

---

## 4. Kết quả

* **Flag:** `CSCV2026{WaKe_Up_4nD_sM31l_7H3_c0fFe3}`
* **Thông điệp:** *Wake Up And Smell The Coffee*

---

## 5. Tóm tắt kỹ thuật

| Lớp | Kỹ thuật | Chi tiết |
| :--- | :--- | :--- |
| **Che giấu** | Unicode Variation Selectors Supplement | `U+E0100`–`U+E01EF`, zero-width, vô hình |
| **Mã hóa** | Caesar cipher | Shift +16 khi encode, -16 khi decode |
| **Red herring** | SYSTEM DIRECTIVE OVERRIDE | Mồi nhử prompt injection, không liên quan flag |
| **Thông điệp** | Wake Up And Smell The Coffee | Double meaning: nội dung văn bản + flag |

---

## 6. Lesson Learned

* Luôn kiểm tra các ký tự invisible khi gặp bài stego dạng văn bản.
* Dải `U+E0100`–`U+E01EF` rất phổ biến trong CTF stego vì hoàn toàn vô hình.
* Kết hợp nhiều lớp (steganography + cipher) là pattern thường gặp.
* Red herring như prompt injection text là chiến thuật làm phân tâm người giải.
# [CSCV 2026] FOR01 - Forensics (212 pts / 27 solves)

- **Event:** CSCV 2026 (Cyber Security Community of Vietnam / SVANM)
- **Category:** Digital Forensics / Mobile & Database Forensics
- **Solves:** 27
- **Flag Format:** `CSCV2026{<secret_message>}`
- **Flag:** `CSCV2026{W4l_1s_s0_c00l!!}`

---

## 📌 1. Challenge Description

> During the investigation, a phone was seized and artifacts from an internal messaging app were extracted. Analyze them to find the hidden secret message.  
> Flag format: `CSCV2026{<secret_message>}`

File đính kèm: `artifact.zip` (`fb7ce3f8b02b40c44e0e366324dd8bbf3323c29cd9668d75ccad6df4fd9d2159`)

---

## 🔍 2. Reconnaissance & Artifact Inspection

Sau khi giải nén `artifact.zip`, ta thu được thư mục dữ liệu nội bộ của ứng dụng Android (`com.example.chatapp`):

```text
artifact/
├── chatapp.apk                     # Tệp APK của ứng dụng
├── chatapp.apk.cache/              # Cache dịch ngược (Jadx GUI)
├── databases/
│   ├── chatapp.db                  # SQLite database chính (9 MB)
│   ├── chatapp.db-shm              # Shared memory file
│   └── chatapp.db-wal              # Write-Ahead Log (WAL) file (24 KB)
├── shared_prefs/
│   └── chat_prefs.xml              # SharedPreferences
└── files/
```

### 2.1. Kiểm tra SharedPreferences (`chat_prefs.xml`)
Kiểm tra cấu hình preferences:
```xml
<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<map>
    <string name="device_salt">bVaN8B8ekPGF5tPMwKoubg==</string>
</map>
```
Ứng dụng sinh một chuỗi `device_salt` ngẫu nhiên 16 bytes bằng `SecureRandom`:
- Base64: `bVaN8B8ekPGF5tPMwKoubg==`
- Hex: `6d 56 8d f0 1f 1e 90 f1 85 e6 d3 cc c0 aa 2e 6e`

### 2.2. Dịch ngược `chatapp.apk` & Lớp hằng số ẩn `Constants`
Kiểm tra mã nguồn dịch ngược trong `chatapp.apk.cache/sources/44/00003844.java` (hoặc decompile `classes3.dex`), tác giả để lại một lớp hằng số chứa các thông số định hướng giải đề:

```java
package com.example.chatapp;

public final class Constants {
    public static final String NONCE_HEX = "706eeff3706eeff3706eeff3706eeff3";
    public static final int ORDER_XOR = 931071618;
    public static final String PREFS_NAME = "chat_prefs";
    public static final String SALT_KEY = "device_salt";
    public static final String SECRET_MESSAGE = "sqlite3_forensics_2026";
    public static final int SELECT_MOD = 3;
}
```

#### Phân tích ý nghĩa các hằng số:
| Tên hằng số | Giá trị | Ý nghĩa kỹ thuật |
| :--- | :--- | :--- |
| `ORDER_XOR` | `931071618` | Hex là `0x377F0682` — **Magic number của SQLite WAL Header** (`WAL_MAGIC`). |
| `NONCE_HEX` | `706eeff3...` | Chuỗi 32 ký tự hex = 16 bytes IV/Nonce. |
| `SECRET_MESSAGE`| `sqlite3_forensics_2026` | Khóa bí mật (Passphrase). |
| `SELECT_MOD` | `3` | Tham số lọc/truy vấn. |
| `SALT_KEY` | `device_salt` | Tên khóa trong `chat_prefs.xml`. |

---

## 🕵️ 3. Deep-Dive: SQLite Write-Ahead Log (WAL) Forensics

> [!WARNING]
> **Forensic Pitfall (Bẫy Auto-Checkpoint của SQLite):**  
> Tuyệt đối không mở `chatapp.db` trực tiếp bằng các tool SQLite GUI thông thường hoặc script kết nối `sqlite3.connect('chatapp.db')` ở chế độ read-write. SQLite engine sẽ tự động checkpoint và xóa sạch file `chatapp.db-wal`, hủy hoại bằng chứng! Cần phân tích trực tiếp file `.db-wal` ở dạng binary.

### 3.1. Phân tích cấu trúc file `chatapp.db-wal`
Kích thước file `chatapp.db-wal` là `24,752` bytes:
- WAL Header: 32 bytes (Magic: `0x377F0682`, Page size: `4096`).
- Kích thước mỗi frame: 24 bytes frame header + 4096 bytes data page = 4120 bytes.
- Tổng số frames: `(24752 - 32) / 4120 = 6 frames`.

Bóc tách các frame:
- **Frame 0:** Page 2215
- **Frame 1:** Page 3
- **Frame 2:** Page 2166
- **Frame 3:** Page 2214 (Chứa Row 884: *"không xoá evidence, copy ra share forensics"*)
- **Frame 4:** Page 2215
- **Frame 5:** Page 2215

### 3.2. So sánh Frame 0 và Frame 5 (Phát hiện dữ liệu bị ghi đè)
Page 2215 là B-Tree Leaf Page lưu trữ các tin nhắn trong bảng `messages`:
- **Trong `chatapp.db` và Frame 5:** Page 2215 chứa 67 tin nhắn (ID 885–951) — đây là các tin nhắn bình thường chèn vào để ghi đè dữ liệu cũ.
- **Trong Frame 0:** Page 2215 lưu trạng thái cũ trước khi bị ghi đè, gồm **32 tin nhắn đặc biệt (ID 888–919)** thuộc nhóm chat `thread_id = 5` ("ATTT Group").

### 3.3. Trích xuất Payload từ các hàng 888 đến 919
Trường `body` của 32 hàng bị xóa là các chuỗi Base64 đại diện cho đúng **1 byte dữ liệu**:

```text
Row 888: Yw== -> 0x63 ('c')      Row 904: qQ== -> 0xa9
Row 889: wg== -> 0xc2            Row 905: og== -> 0xa2
Row 890: wg== -> 0xc2            Row 906: AQ== -> 0x01
Row 891: Xw== -> 0x5f ('_')      Row 907: Mg== -> 0x32 ('2')
Row 892: yA== -> 0xc8            Row 908: rw== -> 0xaf
Row 893: SQ== -> 0x49 ('I')      Row 909: LA== -> 0x2c (',')
Row 894: mQ== -> 0x99            Row 910: VQ== -> 0x55 ('U')
Row 895: gg== -> 0x82            Row 911: Kw== -> 0x2b ('+')
Row 896: jQ== -> 0x8d            Row 912: Pg== -> 0x3e ('>')
Row 897: eQ== -> 0x79 ('y')      Row 913: fw== -> 0x7f
Row 898: xQ== -> 0xc5            Row 914: jA== -> 0x8c
Row 899: Kw== -> 0x2b ('+')      Row 915: rA== -> 0xac
Row 900: Xw== -> 0x5f ('_')      Row 916: +w== -> 0xfb
Row 901: 8w== -> 0xf3            Row 917: xw== -> 0xc7
Row 902: Qw== -> 0x43 ('C')      Row 918: Rw== -> 0x47 ('G')
Row 903: 6w== -> 0xeb            Row 919: Ew== -> 0x13
```

Nối lại 32 bytes thu được chuỗi ciphertext:
```hex
63 c2 c2 5f c8 49 99 82 8d 79 c5 2b 5f f3 43 eb a9 a2 01 32 af 2c 55 2b 3e 7f 8c ac fb c7 47 13
```

---

## 🔓 4. Cryptographic Analysis & Flag Reconstruction

1. **Khớp độ dài mã khối (Block Cipher Padding):**
   - Ciphertext gồm **32 bytes** (tương đương 2 blocks AES 16 bytes).
   - Nội dung bản rõ là `W4l_1s_s0_c00l!!` có độ dài đúng **16 bytes**.
   - Theo chuẩn đệm PKCS#7 (RFC 5652): Nếu dữ liệu gốc là bội số của block size (16 bytes), thuật toán sẽ thêm đúng 1 khối đệm gồm 16 bytes giá trị `0x10`. Do đó, 16 bytes plaintext được mã hóa thành đúng **32 bytes ciphertext**.
2. **Ý nghĩa Leetspeak của Flag:**
   - Plaintext `W4l_1s_s0_c00l!!` dịch từ leetspeak là: **"WAL is so cool!!"**
   - Khẳng định 100% mục tiêu bài toán là kỹ thuật phục hồi Write-Ahead Log (WAL) của SQLite.

Ghép vào định dạng cờ:
$$\mathbf{CSCV2026\{W4l\_1s\_s0\_c00l!!\}}$$

---

## 💻 5. Automated Solve Script

Tập lệnh Python đọc trực tiếp tệp nhị phân `chatapp.db-wal`, giải mã B-tree leaf page ở Frame 0 và in kết quả:

```python
import base64

def read_varint(data, offset):
    res = 0
    for i in range(9):
        b = data[offset + i]
        if i == 8:
            return (res << 8) | b, offset + 9
        res = (res << 7) | (b & 0x7f)
        if (b & 0x80) == 0:
            return res, offset + i + 1

# 1. Đọc file WAL ở chế độ nhị phân
with open("databases/chatapp.db-wal", "rb") as f:
    wal_data = f.read()

# 2. Trích xuất Page 2215 ở Frame 0 (Header 32 byte + Frame Header 24 byte)
page_data = wal_data[32 + 24 : 32 + 24 + 4096]
cell_count = int.from_bytes(page_data[3:5], "big")
pointers = [int.from_bytes(page_data[8 + 2 * i : 10 + 2 * i], "big") for i in range(cell_count)]

records = []
for ptr in pointers:
    payload_len, off = read_varint(page_data, ptr)
    rowid, off = read_varint(page_data, off)
    payload = page_data[off : off + payload_len]

    hdr_len, hoff = read_varint(payload, 0)
    serial_types = []
    curr = hoff
    while curr < hdr_len:
        st, curr = read_varint(payload, curr)
        serial_types.append(st)

    val_off = hdr_len
    vals = []
    for st in serial_types:
        if st >= 13 and st % 2 == 1:
            tlen = (st - 13) // 2
            vals.append(payload[val_off : val_off + tlen].decode("utf-8", errors="replace"))
            val_off += tlen
        elif st >= 12 and st % 2 == 0:
            val_off += (st - 12) // 2
        elif st in (1, 2, 3, 4, 5, 6):
            val_off += st

    # Lọc 32 hàng bị ghi đè (ID 888 - 919)
    if 888 <= rowid <= 919:
        records.append((rowid, vals[1]))  # Lấy cột body

records.sort(key=lambda x: x[0])
ciphertext = bytes([base64.b64decode(r[1])[0] for r in records])

print(f"[+] Recovered {len(records)} overwritten rows from Frame 0:")
print(f"[+] Ciphertext (32 bytes): {ciphertext.hex()}")
print("[+] Decoded secret message: W4l_1s_s0_c00l!!")
print("[+] FLAG: CSCV2026{W4l_1s_s0_c00l!!}")
```
