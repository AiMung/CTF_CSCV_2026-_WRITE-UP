# CTF_CSCV_2026-_WRITE-UP
Tổng hợp bài giải (write-ups) các thử thách trong giải CTF CSCV 2026
CSCV 2026 – MISC02 Write-up
Category: Miscellaneous · Flag: CSCV2026{WaKe_Up_4nD_sM31l_7H3_c0fFe3}
1. Đề bài
Challenge gửi đến một đoạn văn bản trông bề ngoài như hướng dẫn pha cà phê, kèm theo một "SYSTEM DIRECTIVE OVERRIDE" lạ mắt ở đầu – nhưng đây thực ra là mồi nhử (red herring) để che giấu dữ liệu ẩn thực sự.
Nội dung hiển thị:
☕ BREWING INSTRUCTIONS ☕
...
Enjoy your coffee! ☕
Flag format: CSCV2026{[A-Za-z0-9_]+}
2. Nhận diện kỹ thuật ẩn
2.1 Phát hiện ký tự invisible
Bước đầu tiên: kiểm tra tất cả code point trong văn bản.
for i, ch in enumerate(text):
    cp = ord(ch)
    if cp > 0x7F:
        print(f"pos {i}: U+{cp:06X}")
Kết quả: rải rác trong văn bản (chủ yếu sau các emoji) có rất nhiều ký tự thuộc dải U+E0100 – U+E01EF.
2.2 Unicode Variation Selectors Supplement
Unicode dành dải U+E0100 – U+E01EF (256 code point) làm variation selectors. Về mặt hiển thị, chúng hoàn toàn vô hình (zero-width, không render ra màn hình). Đây là kỹ thuật steganography cực kỳ hiệu quả để nhúng dữ liệu vào văn bản mà mắt thường không thể phát hiện.
3. Giải mã từng bước
Bước 1: Trích xuất variation selectors
hidden = [ord(ch) for ch in text
          if 0xE0100 <= ord(ch) <= 0xE01EF]
Bước 2: Trừ base offset ra giá trị ASCII
Mỗi variation selector mang offset so với 0xE0100:
ascii_vals = [cp - 0xE0100 for cp in hidden]
# ''.join(chr(v) for v in ascii_vals)
# => chuỗi bị mã hóa Caesar, chưa đọc được
Bước 3: Giải mã Caesar shift -16
Chuỗi thu được ở bước 2 vẫn chưa đọc được. Áp dụng Caesar cipher với shift -16 trên tập 94 ký tự printable ASCII:
def caesar_decode(vals, shift=16):
    result = []
    for v in vals:
        if 33 <= v <= 126:
            decoded = ((v - 33 - shift) % 94) + 33
            result.append(chr(decoded))
        else:
            result.append(chr(v))
    return ''.join(result)
Script hoàn chỉnh
def solve(text):
    hidden = [ord(ch) for ch in text
              if 0xE0100 <= ord(ch) <= 0xE01EF]
    ascii_vals = [cp - 0xE0100 for cp in hidden]
    return ''.join(
        chr(((v - 33 - 16) % 94) + 33) if 33 <= v <= 126 else chr(v)
        for v in ascii_vals
    )

with open('challenge.txt', encoding='utf-8') as f:
    print(solve(f.read()))
# => CSCV2026{WaKe_Up_4nD_sM31l_7H3_c0fFe3}
4. Kết quả
CSCV2026{WaKe_Up_4nD_sM31l_7H3_c0fFe3}
Thông điệp: Wake Up And Smell The Coffee
5. Tóm tắt kỹ thuật
Lớp
Kỹ thuật
Chi tiết
Che giấu
Unicode Variation Selectors Supplement
U+E0100–U+E01EF, zero-width, vô hình
Mã hóa
Caesar cipher
Shift +16 khi encode, -16 khi decode
Red herring
SYSTEM DIRECTIVE OVERRIDE
Mồi nhử prompt injection, không liên quan flag
Thông điệp
Wake Up And Smell The Coffee
Double meaning: văn bản + flag
6. Lesson Learned
• Luôn kiểm tra các ký tự invisible khi gặp bài stego dạng văn bản
• Dải U+E0100–U+E01EF rất phổ biến trong CTF stego vì hoàn toàn vô hình
• Kết hợp nhiều lớp (steganography + cipher) là pattern thường gặp
• Red herring như prompt injection text là chiến thuật làm phân tâm người giải
CSCV 2026 - Team ITDLU
