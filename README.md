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

