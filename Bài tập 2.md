# BÀI TẬP VỀ NHÀ – MÔN: AN TOÀN VÀ BẢO MẬT THÔNG TIN
Chủ đề: Chữ ký số trong file PDF
Giảng viên: Đỗ Duy Cốp
Sinh viên: Nguyễn Thị Thu Hiền – K225480106015
Thời điểm giao: 2025-10-24 11:45
Đối tượng áp dụng: Toàn bộ sv lớp học phần 58KTPM
Hạn nộp: Sv upload tất cả lên github trước 2025-10-31 23:59:59

I. MÔ TẢ CHUNG
Sinh viên thực hiện báo cáo và thực hành: phân tích và hiện thực việc nhúng, xác 
thực chữ ký số trong file PDF.
Phải nêu rõ chuẩn tham chiếu (PDF 1.7 / PDF 2.0, PAdES/ETSI) và sử dụng công cụ 
thực thi (ví dụ iText7, OpenSSL, PyPDF, pdf-lib).

(1) Cấu trúc PDF liên quan chữ ký (Nghiên cứu) - Mô tả ngắn gọn: Catalog, Pages tree, Page object, Resources, Content streams, XObject, AcroForm, Signature field (widget), Signature dictionary (/Sig), /ByteRange, /Contents, incremental updates, và DSS (theo PAdES). - Liệt kê object refs quan trọng và giải thích vai trò của từng object trong lưu/truy xuất chữ ký. - Đầu ra: 1 trang tóm tắt + sơ đồ object (ví dụ: Catalog → Pages → Page → /Contents ; Catalog → /AcroForm → SigField → SigDict).
>>>>>>
Catalog (Root):	Là đối tượng gốc của PDF, liên kết đến toàn bộ cấu trúc (trang, form, v.v).
Pages Tree:	Danh sách phân cấp chứa các Page Object (từng trang trong PDF).
Page Object:	Mô tả nội dung của một trang (text, hình, font, resources,...).
Resources:	Chứa tham chiếu đến các tài nguyên (font, ảnh, XObject, form fields).
Content Streams:	Dòng lệnh vẽ (text, hình, vector) được render lên trang.
XObject:	Đối tượng đồ họa có thể tái sử dụng (ảnh, form con, template).
AcroForm:	Đối tượng mô tả các form fields, bao gồm cả Signature Field.
Signature Field (Widget)	Field: hiển thị vùng chữ ký (hình ảnh, tên người ký, lý do,...).
Signature Dictionary (/Sig):	Chứa dữ liệu chữ ký số thật sự: cert, hash, thời gian,...
/ByteRange:	Mảng 4 số chỉ định các vùng byte được hash (ngoại trừ vùng /Contents).
/Contents:	Chứa dữ liệu chữ ký số PKCS#7 (đã mã hóa base16/hex).
Incremental: Updates	PDF lưu chữ ký bằng cách thêm phần mới chứ không ghi đè, giúp giữ nguyên lịch sử.
DSS (Document Security Store)	(Theo chuẩn PAdES) – chứa chứng chỉ, OCSP, CRL phục vụ xác thực lâu dài (LTV).
>>>>>>
<img width="900" height="580" alt="image" src="https://github.com/user-attachments/assets/58e4961e-098d-44ae-8462-37b003cc9c10" />

2) rủi ro bảo mật
- Rò rỉ hoặc đánh cắp Private Key
- Tấn công sửa đổi nội dung (Tampering)
- Giả mạo hiển thị chữ ký (UI attack)
- Thuật toán băm hoặc mã hóa yếu
- Tấn công Replay / Resigning
- Tấn công vào Timestamp hoặc TSA
- Sai sót trong xác minh chuỗi chứng chỉ (Chain validation)
- Rủi ro phần mềm ký không chuẩn
- Không bảo vệ long-term (LTV)

>>>>

A.	Chuẩn bị môi trường
1. Sử dụng Anaconda để tạo môi trường, cài các thư viện và sinh khóa
<img width="844" height="1023" alt="image" src="https://github.com/user-attachments/assets/01cf8e9d-65db-4a50-b83a-aa67dbdd56ab" />

2. Tạo private key + certificate

<img width="1072" height="329" alt="image" src="https://github.com/user-attachments/assets/52aa1724-f701-4017-b37d-884e6adfcc6f" />

3. Các bước tạo và lưu chữ ký trong PDF (đã có private RSA)
- Viết script/code thực hiện tuần tự:
  1. Chuẩn bị file PDF gốc.
  2. Tạo Signature field (AcroForm), reserve vùng /Contents (8192 bytes).
  3. Xác định /ByteRange (loại trừ vùng /Contents khỏi hash).
  4. Tính hash (SHA-256/512) trên vùng ByteRange.
  5. Tạo PKCS#7/CMS detached hoặc CAdES:
     - Include messageDigest, signingTime, contentType.
     - Include certificate chain.
     - (Tùy chọn) thêm RFC3161 timestamp token.
  6. Chèn blob DER PKCS#7 vào /Contents (hex/binary) đúng offset.
  7. Ghi incremental update.
  8. (LTV) Cập nhật DSS với Certs, OCSPs, CRLs, VRI.
- Phải nêu rõ: hash alg, RSA padding, key size, vị trí lưu trong PKCS#7.
- Đầu ra: mã nguồn, file PDF gốc, file PDF đã ký.
<img width="1041" height="592" alt="image" src="https://github.com/user-attachments/assets/c564235d-04db-482c-a8da-966fe93b8d1a" />

4. Các bước xác thực chữ ký trên PDF đã ký
- Các bước kiểm tra:
1. Đọc Signature dictionary: /Contents, /ByteRange.
2. Tách PKCS#7, kiểm tra định dạng.
3. Tính hash và so sánh messageDigest.
4. Verify signature bằng public key trong cert.
5. Kiểm tra chain → root trusted CA.
6. Kiểm tra OCSP/CRL.
7. Kiểm tra timestamp token.
8. Kiểm tra incremental update (phát hiện sửa đổi).
- Nộp kèm script verify + log kiểm thử.
<img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/4bb1542e-bf5a-471c-94b1-d786e040fea4" />

<img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/1d6de662-8b8e-41dd-9f93-0cabd8f68c28" />

